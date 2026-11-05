"""
Gradnik analitične nadzorne plošče
Odzivni zgodovinski trendi, analiza groženj in metrike tveganja.
"""

import csv
import logging
import os
import math
from collections import Counter, deque
from datetime import datetime, timedelta
from pathlib import Path

import pyqtgraph as pg
from PyQt5.QtCore import QObject, QThread, QTimer, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QComboBox,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from db_manager import PostgreSQLManager
from threat_analytics import ThreatAnalytics
from ui_components import SummaryCard, card_style as _card_style


class AnalyticsRefreshWorker(QObject):
    finished = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self._load_local_postgres_env()
        self.db_enabled = os.environ.get("POSTGRES_ENABLED", "0") == "1"
        self.db_manager = None
        self.analytics = ThreatAnalytics(None)
        if not self.db_enabled:
            self.logger.info("PostgreSQL analytics disabled; using session fallback data")

    @staticmethod
    def _load_local_postgres_env():
        env_path = Path(__file__).resolve().parent.parent / ".env.local"
        if not env_path.exists():
            return
        try:
            with open(env_path, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, value = line.split("=", 1)
                    key = key.strip()
                    if key.startswith("POSTGRES_"):
                        os.environ.setdefault(key, value.strip())
        except Exception:
            return

    def _ensure_db(self):
        if not self.db_enabled:
            return
        if self.db_manager and getattr(self.db_manager, "connected", False):
            return
        try:
            self.db_manager = PostgreSQLManager()
        except Exception as exc:
            self.logger.warning("PostgreSQL analytics unavailable: %s", exc)
            self.db_manager = None
        self.analytics = ThreatAnalytics(self.db_manager if getattr(self.db_manager, "connected", False) else None)

    @pyqtSlot(int)
    def refresh(self, hours: int):
        self._ensure_db()
        result = {
            "db_enabled": self.db_enabled,
            "connected": bool(self.db_manager and getattr(self.db_manager, "connected", False)),
            "trends": [],
            "distribution": {"by_port": [], "by_source": []},
            "patterns": [],
            "stats": {"total_threats": 0, "unique_sources": 0, "unique_ports": 0, "risk_score": 0.0},
        }
        try:
            result["trends"] = self.analytics.get_threat_trends(hours=hours)
        except Exception:
            pass
        try:
            result["distribution"] = self.analytics.get_threat_distribution(hours=hours)
        except Exception:
            pass
        try:
            result["patterns"] = self.analytics.get_anomaly_patterns(hours=hours)
        except Exception:
            pass
        try:
            result["stats"] = self.analytics.get_stats(hours=hours)
        except Exception:
            pass
        self.finished.emit(result)


class AnalyticsDashboardWidget(QWidget):
    request_refresh = pyqtSignal(int)

    SEVERITY_LABELS = {
        "CRITICAL": "kritično",
        "HIGH": "visoko",
        "MEDIUM": "srednje",
        "LOW": "nizko",
        "INFO": "informativno",
    }

    PATTERN_TYPE_LABELS = {
        "source": "izvor",
        "source_ip": "izvor",
        "destination": "cilj",
        "destination_port": "ciljna vrata",
        "port": "vrata",
        "session": "seja",
        "seja": "seja",
        "pattern": "vzorec",
    }

    def __init__(self, api_client=None, enable_auto_refresh: bool = True):
        super().__init__()
        self.api_client = api_client
        self.logger = logging.getLogger(__name__)
        self.enable_auto_refresh = enable_auto_refresh
        self._closing = False
        self._active = False
        self._refresh_in_progress = False
        self._pending_hours = None
        self._last_refresh_text = "čakam"
        self._last_result = {
            "db_enabled": False,
            "connected": False,
            "trends": [],
            "distribution": {"by_port": [], "by_source": []},
            "patterns": [],
            "stats": {"total_threats": 0, "unique_sources": 0, "unique_ports": 0, "risk_score": 0.0},
        }
        self._session_alerts = deque(maxlen=500)

        self.init_ui()
        self._setup_worker()
        self._setup_timer()
        QTimer.singleShot(0, self.refresh_analytics)

    def add_alert(self, alert: dict):
        payload = dict(alert or {})
        payload["_captured_at"] = datetime.now()
        self._session_alerts.appendleft(payload)
        if not self._refresh_in_progress:
            QTimer.singleShot(250 if self._active else 1000, self.refresh_analytics)

    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(8)

        header = QFrame()
        header.setStyleSheet(_card_style())
        header_layout = QVBoxLayout()
        header_layout.setContentsMargins(10, 8, 10, 8)
        title = QLabel("Analitika")
        title.setFont(QFont("Segoe UI", 13, QFont.Bold))
        title.setStyleSheet("color: #172033;")
        subtitle = QLabel("Trendi, izvorne IP in vrata iz arhiviranih incidentov ali trenutne seje.")
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #64748b;")
        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)
        header.setLayout(header_layout)
        main_layout.addWidget(header)

        summary_layout = QHBoxLayout()
        card_options = {
            "subtitle": "Čakam analitiko",
            "value_size": 14,
            "margins": (10, 8, 10, 8),
            "title_color": "#475569",
        }
        self.total_card = SummaryCard("Incidenti", "#38bdf8", **card_options)
        self.sources_card = SummaryCard("Izvori", "#22c55e", **card_options)
        self.risk_card = SummaryCard("Tveganje", "#f97316", **card_options)
        self.state_card = SummaryCard("Stanje", "#facc15", **card_options)
        summary_layout.addWidget(self.total_card)
        summary_layout.addWidget(self.sources_card)
        summary_layout.addWidget(self.risk_card)
        summary_layout.addWidget(self.state_card)
        main_layout.addLayout(summary_layout)

        control_layout = QHBoxLayout()
        control_layout.addWidget(QLabel("Obdobje:"))
        self.range_combo = QComboBox()
        self.range_combo.addItems(["1 ura", "6 ur", "24 ur", "7 dni"])
        self.range_combo.setCurrentIndex(2)
        self.range_combo.currentTextChanged.connect(lambda _text: self.refresh_analytics())
        control_layout.addWidget(self.range_combo)

        export_btn = QPushButton("Izvozi CSV")
        export_btn.clicked.connect(self.export_report)
        control_layout.addWidget(export_btn)

        self.status_label = QLabel("Čakam prvo osvežitev.")
        self.status_label.setStyleSheet("color: #475569;")
        self.status_label.hide()
        control_layout.addWidget(self.status_label)
        control_layout.addStretch()
        main_layout.addLayout(control_layout)

        risk_layout = QHBoxLayout()
        risk_layout.addWidget(QLabel("Ocena tveganja:"))
        self.risk_bar = QProgressBar()
        self.risk_bar.setRange(0, 100)
        self.risk_bar.setMaximumWidth(220)
        risk_layout.addWidget(self.risk_bar)
        self.risk_value_label = QLabel("0.0%")
        self.risk_value_label.setFont(QFont("Arial", 12, QFont.Bold))
        risk_layout.addWidget(self.risk_value_label)
        risk_layout.addStretch()
        main_layout.addLayout(risk_layout)

        tabs = QTabWidget()
        tabs.addTab(self._create_trends_tab(), "Trend")
        tabs.addTab(self._create_distribution_tab(), "Porazdelitev")
        tabs.addTab(self._create_insights_tab(), "Ugotovitve")
        tabs.addTab(self._create_indicators_tab(), "Indikatorji")
        main_layout.addWidget(tabs)

        stats_layout = QHBoxLayout()
        self.total_label = QLabel("Incidenti: 0")
        self.sources_label = QLabel("Izvori: 0")
        self.ports_label = QLabel("Vrata: 0")
        self.db_label = QLabel("Baza: čakam")
        for widget in (self.total_label, self.sources_label, self.ports_label, self.db_label):
            stats_layout.addWidget(widget)
            stats_layout.addSpacing(16)
        stats_layout.addStretch()
        main_layout.addLayout(stats_layout)

        self.setLayout(main_layout)

    def _create_trends_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        hint = QLabel("Točke so časovni intervali; levo so starejši, desno novejši dogodki.")
        hint.setStyleSheet("color: #64748b;")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        self.trend_plot = pg.PlotWidget(axisItems={"bottom": pg.DateAxisItem(orientation="bottom")})
        self.trend_plot.setBackground("#ffffff")
        self.trend_plot.setLabel("left", "Incidenti")
        self.trend_plot.setLabel("bottom", "Čas")
        self.trend_plot.setTitle("Incidenti skozi čas")
        self.trend_plot.showGrid(x=True, y=True, alpha=0.12)
        layout.addWidget(self.trend_plot)
        widget.setLayout(layout)
        return widget

    def _create_distribution_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()

        ports_group = QGroupBox("Najpogostejša ciljna vrata")
        ports_layout = QVBoxLayout()
        self.ports_table = QTableWidget()
        self.ports_table.setColumnCount(3)
        self.ports_table.setHorizontalHeaderLabels(["Vrata", "Število", "Povp. ocena"])
        self.ports_table.setMaximumHeight(200)
        ports_layout.addWidget(self.ports_table)
        ports_group.setLayout(ports_layout)

        sources_group = QGroupBox("Najpogostejši izvori")
        sources_layout = QVBoxLayout()
        self.sources_table = QTableWidget()
        self.sources_table.setColumnCount(3)
        self.sources_table.setHorizontalHeaderLabels(["Izvor IP", "Število", "Povp. ocena"])
        self.sources_table.setMaximumHeight(200)
        sources_layout.addWidget(self.sources_table)
        sources_group.setLayout(sources_layout)

        layout.addWidget(ports_group)
        layout.addWidget(sources_group)
        widget.setLayout(layout)
        return widget

    def _create_insights_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        patterns_group = QGroupBox("Zaznani vzorci")
        patterns_layout = QVBoxLayout()
        self.patterns_text = QLabel("Čakam osvežitev analitike...")
        self.patterns_text.setWordWrap(True)
        patterns_layout.addWidget(self.patterns_text)
        patterns_group.setLayout(patterns_layout)

        escalation_group = QGroupBox("Tveganje eskalacije")
        escalation_layout = QVBoxLayout()
        self.escalation_text = QLabel("Eskalacija še ni ocenjena.")
        self.escalation_text.setWordWrap(True)
        escalation_layout.addWidget(self.escalation_text)
        escalation_group.setLayout(escalation_layout)

        notes_group = QGroupBox("Opomba")
        notes_layout = QVBoxLayout()
        self.notes_text = QTextEdit()
        self.notes_text.setReadOnly(True)
        self.notes_text.setText("Analitika povzema, ali se incidenti širijo po več izvorih ali se ponavljajo v istih vzorcih.")
        notes_layout.addWidget(self.notes_text)
        notes_group.setLayout(notes_layout)

        layout.addWidget(patterns_group)
        layout.addWidget(escalation_group)
        layout.addWidget(notes_group)
        widget.setLayout(layout)
        return widget

    def _create_indicators_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        self.indicators_table = QTableWidget()
        self.indicators_table.setColumnCount(5)
        self.indicators_table.setHorizontalHeaderLabels(["Tip", "Indikator", "Število", "Povp. ocena", "Stopnja"])
        layout.addWidget(self.indicators_table)
        widget.setLayout(layout)
        return widget

    def _setup_worker(self):
        self._worker_thread = QThread(self)
        try:
            from thread_registry import register
            register(self._worker_thread)
        except Exception:
            pass
        self._worker = AnalyticsRefreshWorker()
        self._worker.moveToThread(self._worker_thread)
        self.request_refresh.connect(self._worker.refresh)
        self._worker.finished.connect(self._on_refresh_finished)
        self._worker_thread.start()

    def _setup_timer(self):
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh_analytics)
        if self.enable_auto_refresh:
            self.refresh_timer.start(10000)

    def set_active(self, active: bool):
        self._active = active
        if self._closing:
            return
        if active:
            self.state_card.set_value("Aktivno", "Samodejno osveževanje", "#4ade80")
            if self.enable_auto_refresh and not self.refresh_timer.isActive():
                self.refresh_timer.start(10000)
            QTimer.singleShot(0, self.refresh_analytics)
        else:
            self.state_card.set_value("V ozadju", "Osveževanje teče", "#94a3b8")

    def get_hours_from_range(self) -> int:
        text = self.range_combo.currentText()
        if "1 hour" in text or "1 ura" in text:
            return 1
        if "6 hours" in text or "6 ur" in text:
            return 6
        if "7 days" in text or "7 dni" in text:
            return 168
        return 24

    def refresh_analytics(self):
        if self._closing:
            return
        hours = self.get_hours_from_range()
        if self._refresh_in_progress:
            self._pending_hours = hours
            return
        self._refresh_in_progress = True
        self.state_card.set_value("Osvežujem", self.range_combo.currentText(), "#facc15")
        self.status_label.setText("Osvežujem analitiko...")
        self.request_refresh.emit(hours)

    def _apply_table(self, table: QTableWidget, rows, columns):
        table.setUpdatesEnabled(False)
        try:
            table.setRowCount(len(rows))
            for row_idx, row in enumerate(rows):
                for col_idx, value in enumerate(columns(row)):
                    table.setItem(row_idx, col_idx, QTableWidgetItem(str(value)))
        finally:
            table.setUpdatesEnabled(True)

    @staticmethod
    def _coerce_plot_timestamp(value, fallback_index: int) -> float:
        if isinstance(value, datetime):
            return value.timestamp()
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value).timestamp()
            except Exception:
                return float(fallback_index)
        return float(fallback_index)

    @staticmethod
    def _format_bucket_label(value) -> str:
        if isinstance(value, datetime):
            return value.strftime("%b %d %H:%M")
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value).strftime("%b %d %H:%M")
            except Exception:
                return value[:12]
        return str(value)

    @classmethod
    def _severity_label(cls, value) -> str:
        text = str(value or "").upper()
        return cls.SEVERITY_LABELS.get(text, text.lower())

    @classmethod
    def _pattern_type_label(cls, value) -> str:
        text = str(value or "vzorec")
        return cls.PATTERN_TYPE_LABELS.get(text.lower(), text)

    def _on_refresh_finished(self, result: dict):
        stats_before_fallback = result.get("stats", {}) if isinstance(result, dict) else {}
        if (not result.get("connected")) or (
            not result.get("trends") and int(stats_before_fallback.get("total_threats", 0) or 0) == 0
        ):
            fallback = self._build_session_fallback(self.get_hours_from_range())
            if fallback["stats"].get("total_threats", 0) > 0:
                result = fallback
        self._last_result = result
        self._last_refresh_text = datetime.now().strftime("%H:%M:%S")
        trends = result.get("trends", [])
        distribution = result.get("distribution", {})
        patterns = result.get("patterns", [])
        stats = result.get("stats", {})

        self.trend_plot.clear()
        if trends:
            plot_points = []
            for idx, item in enumerate(trends):
                x_value = self._coerce_plot_timestamp(item.get("timestamp"), idx)
                plot_points.append((x_value, item.get("threat_count", 0)))
            plot_points.sort(key=lambda row: row[0])
            x_axis = [point[0] for point in plot_points]
            interval_counts = [int(point[1] or 0) for point in plot_points]
            counts = interval_counts
            self.trend_plot.plot(
                x_axis,
                counts,
                pen=pg.mkPen("#2563eb", width=2),
                symbol="o",
                symbolSize=6,
                symbolBrush="#2563eb",
                symbolPen=pg.mkPen("#ffffff", width=1),
            )
            if x_axis:
                now_timestamp = datetime.now().timestamp()
                window_start = now_timestamp - self.get_hours_from_range() * 3600
                self.trend_plot.setXRange(window_start, now_timestamp, padding=0)
            self.trend_plot.setTitle("Incidenti skozi čas")
            if counts:
                peak = max(counts)
                avg = peak
                self.status_label.clear()
        else:
            self.trend_plot.setTitle("Ni podatkov za izbrano obdobje")

        self._apply_table(
            self.ports_table,
            distribution.get("by_port", []),
            lambda row: [row.get("port", "N/A"), row.get("threat_count", 0), f"{row.get('avg_score', 0):.3f}"],
        )
        self._apply_table(
            self.sources_table,
            distribution.get("by_source", []),
            lambda row: [row.get("ip", row.get("src_ip", "N/A")), row.get("threat_count", 0), f"{row.get('avg_score', 0):.3f}"],
        )

        if patterns:
            lines = [
                f"{self._pattern_type_label(item.get('type', 'vzorec'))}: {item.get('label', item.get('source_ip', 'N/A'))} ({item.get('threat_count', 0)} dogodkov, ocena {item.get('avg_score', 0):.2f})"
                for item in patterns
            ]
            self.patterns_text.setText("\n".join(lines))
            self.escalation_text.setText("V izbranem obdobju so vidni ponavljajoči se vzorci.")
            self.notes_text.setText("Najprej preveri skupine z najvišjo oceno in največ ponovitvami.")
        else:
            self.patterns_text.setText("Ni izrazitih vzorcev.")
            self.escalation_text.setText("Ni znakov eskalacije.")
            self.notes_text.setText("V izbranem obdobju ni močnih skupin incidentov.")

        indicator_rows = []
        for item in patterns[:10]:
            indicator_rows.append(
                [
                    self._pattern_type_label(item.get("type", "vzorec")),
                    item.get("label", item.get("source_ip", "N/A")),
                    item.get("threat_count", 0),
                    f"{item.get('avg_score', 0):.3f}",
                    self._severity_label(item.get("severity", "MEDIUM")),
                ]
            )
        self._apply_table(self.indicators_table, indicator_rows, lambda row: row)

        total_threats = stats.get("total_threats", 0)
        unique_sources = stats.get("unique_sources", 0)
        unique_ports = stats.get("unique_ports", 0)
        risk_score = float(stats.get("risk_score", 0.0) or 0.0)

        self.total_label.setText(f"Incidenti: {total_threats}")
        self.sources_label.setText(f"Izvori: {unique_sources}")
        self.ports_label.setText(f"Vrata: {unique_ports}")
        self.total_card.set_value(str(total_threats), "")
        self.sources_card.set_value(str(unique_sources), "")
        self.risk_card.set_value(f"{risk_score * 100:.1f}%", "", "#ef4444" if risk_score > 0.7 else "#f97316" if risk_score > 0.4 else "#4ade80")

        self.risk_bar.setValue(int(risk_score * 100))
        self.risk_value_label.setText(f"{risk_score * 100:.1f}%")
        if risk_score > 0.7:
            self.risk_bar.setStyleSheet("QProgressBar::chunk {background-color: #dc2626;}")
        elif risk_score > 0.4:
            self.risk_bar.setStyleSheet("QProgressBar::chunk {background-color: #d97706;}")
        else:
            self.risk_bar.setStyleSheet("QProgressBar::chunk {background-color: #16a34a;}")

        connected = result.get("connected")
        db_enabled = result.get("db_enabled", True)
        if connected:
            db_text = "Baza: povezana"
            status_suffix = "Baza je povezana."
        elif not db_enabled:
            db_text = "Baza: izklopljena"
            status_suffix = "Prikazujem podatke seje."
        else:
            db_text = "Baza: brez povezave"
            status_suffix = "Prikazujem podatke trenutne seje."
        self.db_label.setText(db_text)
        if not trends:
            self.status_label.clear()
        self.state_card.set_value("Pripravljeno", "", "#4ade80")

        self._refresh_in_progress = False
        if self._pending_hours is not None and not self._closing:
            self._pending_hours = None
            QTimer.singleShot(0, self.refresh_analytics)

    def _build_session_fallback(self, hours: int) -> dict:
        now = datetime.now()
        time_window = max(1, hours)
        relevant = []
        for item in self._session_alerts:
            captured_at = item.get("_captured_at") or now
            if isinstance(captured_at, datetime) and (now - captured_at).total_seconds() <= time_window * 3600:
                relevant.append(item)

        by_source = Counter()
        by_port = Counter()
        source_scores = {}
        port_scores = {}
        severity_weights = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.55, "LOW": 0.25, "INFO": 0.1}
        trends = []
        pattern_rows = []

        for item in relevant:
            src_ip = str(item.get("src_ip") or item.get("source_ip") or "N/A")
            dst_port = int(item.get("dst_port", 0) or 0)
            severity = str(item.get("severity") or item.get("threat_level") or "MEDIUM").upper()
            score = float(item.get("threat_score", severity_weights.get(severity, 0.4)) or severity_weights.get(severity, 0.4))
            by_source[src_ip] += 1
            by_port[dst_port] += 1
            source_scores.setdefault(src_ip, []).append(score)
            port_scores.setdefault(dst_port, []).append(score)

        bucket_count = 12
        bucket_seconds = max(300, int(math.ceil((time_window * 3600) / bucket_count)))
        window_start = now - timedelta(hours=time_window)
        bucket_rows = {idx: [] for idx in range(bucket_count)}

        for item in relevant:
            captured_at = item.get("_captured_at") or now
            if not isinstance(captured_at, datetime):
                continue
            elapsed = (captured_at - window_start).total_seconds()
            if elapsed < 0:
                continue
            bucket_index = min(bucket_count - 1, int(elapsed // bucket_seconds))
            bucket_rows[bucket_index].append(item)

        if relevant:
            for idx in range(bucket_count):
                chunk = bucket_rows[idx]
                bucket_ts = window_start + timedelta(seconds=idx * bucket_seconds)
                trends.append({
                    "timestamp": bucket_ts,
                    "threat_count": len(chunk),
                    "avg_score": sum(float(item.get("threat_score", 0.0) or 0.0) for item in chunk) / len(chunk) if chunk else 0.0,
                    "critical_count": sum(1 for item in chunk if str(item.get("severity") or item.get("threat_level") or "").upper() == "CRITICAL"),
                    "high_count": sum(1 for item in chunk if str(item.get("severity") or item.get("threat_level") or "").upper() == "HIGH"),
                })

        for src_ip, count in by_source.most_common(10):
            avg_score = sum(source_scores.get(src_ip, [0.0])) / max(1, len(source_scores.get(src_ip, [])))
            severity = "CRITICAL" if avg_score > 0.85 else "HIGH" if avg_score > 0.65 else "MEDIUM"
            pattern_rows.append(
                {
                    "type": "seja",
                    "source_ip": src_ip,
                    "threat_count": count,
                    "avg_score": avg_score,
                    "severity": severity,
                }
            )

        avg_risk = 0.0
        if relevant:
            avg_risk = sum(float(item.get("threat_score", severity_weights.get(str(item.get("severity") or item.get("threat_level") or "MEDIUM").upper(), 0.4)) or 0.0) for item in relevant) / len(relevant)

        return {
            "db_enabled": False,
            "connected": False,
            "trends": trends,
            "distribution": {
                "by_port": [
                    {"port": port, "threat_count": count, "avg_score": sum(port_scores.get(port, [0.0])) / max(1, len(port_scores.get(port, [])))}
                    for port, count in by_port.most_common(10)
                ],
                "by_source": [
                    {"src_ip": src_ip, "threat_count": count, "avg_score": sum(source_scores.get(src_ip, [0.0])) / max(1, len(source_scores.get(src_ip, [])))}
                    for src_ip, count in by_source.most_common(10)
                ],
            },
            "patterns": pattern_rows,
            "stats": {
                "total_threats": len(relevant),
                "unique_sources": len(by_source),
                "unique_ports": len(by_port),
                "risk_score": avg_risk,
            },
        }

    def export_report(self):
        filename = f"analitika_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filepath = Path.home() / "Downloads" / filename
        filepath.parent.mkdir(parents=True, exist_ok=True)
        stats = self._last_result.get("stats", {})
        distribution = self._last_result.get("distribution", {}) or {}
        patterns = self._last_result.get("patterns", []) or []
        try:
            with open(filepath, "w", newline="", encoding="utf-8") as handle:
                writer = csv.writer(handle)
                writer.writerow(["Poročilo analitike", datetime.now().isoformat()])
                writer.writerow([])
                writer.writerow(["Incidenti", stats.get("total_threats", 0)])
                writer.writerow(["Izvori", stats.get("unique_sources", 0)])
                writer.writerow(["Vrata", stats.get("unique_ports", 0)])
                writer.writerow(["Tveganje", f"{float(stats.get('risk_score', 0.0)):.3f}"])
                writer.writerow([])
                writer.writerow(["Najpogostejša vrata"])
                writer.writerow(["Vrata", "Število", "Povp. ocena"])
                for row in distribution.get("by_port", [])[:20]:
                    writer.writerow([row.get("port", "N/A"), row.get("threat_count", 0), f"{row.get('avg_score', 0):.3f}"])
                writer.writerow([])
                writer.writerow(["Najpogostejši izvori"])
                writer.writerow(["Izvor IP", "Število", "Povp. ocena"])
                for row in distribution.get("by_source", [])[:20]:
                    writer.writerow([row.get("ip", row.get("src_ip", "N/A")), row.get("threat_count", 0), f"{row.get('avg_score', 0):.3f}"])
                writer.writerow([])
                writer.writerow(["Vzorci"])
                writer.writerow(["Tip", "Indikator", "Število", "Povp. ocena", "Stopnja"])
                for row in patterns[:20]:
                    writer.writerow([
                        self._pattern_type_label(row.get("type", "vzorec")),
                        row.get("label", row.get("source_ip", "N/A")),
                        row.get("threat_count", 0),
                        f"{row.get('avg_score', 0):.3f}",
                        self._severity_label(row.get("severity", "MEDIUM")),
                    ])
            self.logger.info("Exported report to %s", filepath)
            self.state_card.set_value("Izvoženo", filepath.name, "#4ade80")
        except Exception as exc:
            self.logger.error("Export failed: %s", exc)
            self.state_card.set_value("Izvoz ni uspel", str(exc), "#ef4444")

    def closeEvent(self, event):
        self._closing = True
        try:
            if self.refresh_timer.isActive():
                self.refresh_timer.stop()
        except Exception:
            pass
        try:
            if self._worker_thread.isRunning():
                self._worker_thread.quit()
                self._worker_thread.wait(2000)
        except Exception:
            pass
        event.accept()
