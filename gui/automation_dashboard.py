"""
Gradnik nadzorne plošče avtomatizacije - prikaz odzivov in naprednih funkcij.
"""

import logging
import traceback
from datetime import datetime

from PyQt5.QtCore import QObject, QThread, QTimer, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QAction,
    QHeaderView,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QCheckBox,
    QLabel,
    QMenu,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

try:
    from .response_history import ResponseHistoryWidget
except ImportError:
    from response_history import ResponseHistoryWidget
from ui_components import SummaryCard, card_style as _card_style


class AutomationWorker(QObject):
    finished = pyqtSignal(dict)

    def __init__(self, response_engine=None):
        super().__init__()
        self.response_engine = response_engine

    @pyqtSlot()
    def refresh(self):
        result = {
            "response_stats": {},
            "blocked_ips": [],
            "blocked_ip_details": [],
            "statistics": {},
            "playbook_history": [],
            "playbook_stats": {},
        }
        try:
            if self.response_engine:
                try:
                    result["response_stats"] = self.response_engine.get_stats()
                except Exception:
                    pass
                try:
                    result["blocked_ips"] = list(self.response_engine.get_blocked_ips())
                except Exception:
                    pass
                try:
                    if hasattr(self.response_engine, "get_blocked_ip_details"):
                        result["blocked_ip_details"] = list(self.response_engine.get_blocked_ip_details())
                except Exception:
                    pass
                try:
                    playbook_engine = getattr(self.response_engine, "playbook_engine", None)
                    if playbook_engine:
                        result["playbook_history"] = playbook_engine.get_execution_history(limit=20)
                        result["playbook_stats"] = playbook_engine.get_statistics()
                        result["registered_playbooks"] = [
                            {
                                "playbook_id": playbook.playbook_id,
                                "name": playbook.name,
                                "actions": len(playbook.actions),
                            }
                            for playbook in getattr(playbook_engine, "playbooks", {}).values()
                        ]
                except Exception:
                    pass

        except Exception as exc:
            result["error"] = str(exc)
        self.finished.emit(result)


class AutomationActionWorker(QObject):
    finished = pyqtSignal(str, dict)

    def __init__(self, response_engine=None, threat_callback=None):
        super().__init__()
        self.response_engine = response_engine
        self.threat_callback = threat_callback

    @pyqtSlot(dict)
    def run_action(self, payload: dict):
        action = payload.get("action", "")
        result = {
            "ok": False,
            "message": "",
            "refresh": True,
        }
        try:
            if action == "unblock_ip":
                ip = str(payload.get("ip", "")).strip()
                if not ip:
                    result["message"] = "IP naslov ni izbran"
                elif not self.response_engine or not hasattr(self.response_engine, "unblock_ip"):
                    result["message"] = "Odzivni modul še ne podpira odstranitve blokade"
                else:
                    result["ok"] = bool(self.response_engine.unblock_ip(ip))
                    result["message"] = f"IP {ip} je odblokiran" if result["ok"] else f"IP {ip} ni bil blokiran"
            elif action == "inject_threat":
                threat = payload.get("threat") or {}
                playbook_id = payload.get("playbook_id")
                if self.response_engine:
                    self.response_engine.execute_response(threat)

                threat["_automation_response_applied"] = True
                if playbook_id:
                    playbook_engine = getattr(self.response_engine, "playbook_engine", None) if self.response_engine else None
                    if playbook_engine:
                        playbook_engine.execute_playbook(playbook_id, threat)
                result["ok"] = True
                level = str(threat.get("threat_level", "UNKNOWN")).upper()
                level_label = {
                    "CRITICAL": "kritičen",
                    "HIGH": "visok",
                    "MEDIUM": "srednji",
                    "LOW": "nizek",
                    "INFO": "informativni",
                }.get(level, level.lower())
                result["message"] = f"Demo dogodek dodan: {level_label}"
                result["threat"] = dict(threat)
            else:
                result["message"] = f"Nepodprta akcija: {action}"
        except Exception as exc:
            result["message"] = str(exc)
            result["traceback"] = traceback.format_exc()
        self.finished.emit(action, result)


class AutomationWidget(QWidget):
    request_refresh = pyqtSignal()
    request_action = pyqtSignal(dict)

    ACTION_LABELS = {
        "inject_threat": "demo dogodek",
        "unblock_ip": "odblokiranje IP naslova",
    }

    PLAYBOOK_LABELS = {
        "pb_lateral": "Premik po omrežju",
        "pb_portscan": "Pregled vrat",
        "pb_c2": "C2 komunikacija",
        "pb_ddos": "DDoS odziv",
        "pb_exfil": "Odtekanje podatkov",
    }

    SEVERITY_LABELS = {
        "CRITICAL": "kritično",
        "HIGH": "visoko",
        "MEDIUM": "srednje",
        "LOW": "nizko",
        "INFO": "informativno",
        "UNKNOWN": "neznano",
    }

    STATUS_LABELS = {
        "idle": "miruje",
        "pending": "čaka",
        "running": "teče",
        "completed": "zaključeno",
        "success": "uspešno",
        "failed": "neuspešno",
        "rolled_back": "povrnjeno",
        "registered": "registrirano",
    }

    def __init__(
        self,
        response_engine=None,
        enable_timer: bool = True,
        threat_callback=None,
        automation_mode_callback=None,
    ):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.response_engine = response_engine
        self.threat_callback = threat_callback
        self.automation_mode_callback = automation_mode_callback
        self._closing = False
        self._active = False
        self._refresh_in_progress = False
        self._refresh_pending = False
        self._action_in_progress = False
        self._last_refresh_text = "čakam"

        self.init_ui()
        self._setup_worker()
        self._setup_timer(enable_timer)
        if self.response_engine:
            try:
                self.response_history.register_engine(self.response_engine)
            except Exception:
                pass
        QTimer.singleShot(0, self.refresh_data)

    def _setup_worker(self):
        self._worker_thread = QThread(self)
        try:
            from thread_registry import register
            register(self._worker_thread)
        except Exception:
            pass
        self._worker = AutomationWorker(self.response_engine)
        self._worker.moveToThread(self._worker_thread)
        self.request_refresh.connect(self._worker.refresh)
        self._worker.finished.connect(self._on_worker_finished)
        self._worker_thread.start()

        self._action_thread = QThread(self)
        try:
            from thread_registry import register
            register(self._action_thread)
        except Exception:
            pass
        self._action_worker = AutomationActionWorker(self.response_engine, self.threat_callback)
        self._action_worker.moveToThread(self._action_thread)
        self.request_action.connect(self._action_worker.run_action)
        self._action_worker.finished.connect(self._on_action_finished)
        self._action_thread.start()

    def _setup_timer(self, enable_timer: bool):
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh_data)
        if enable_timer:
            self.refresh_timer.start(5000)

    def _configure_table(self, table: QTableWidget):
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.setShowGrid(False)
        header = table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(QHeaderView.ResizeToContents)

    @classmethod
    def _action_label(cls, value) -> str:
        text = str(getattr(value, "value", value) or "")
        return cls.ACTION_LABELS.get(text.lower(), text)

    @classmethod
    def _playbook_label(cls, value) -> str:
        text = str(getattr(value, "value", value) or "")
        return cls.PLAYBOOK_LABELS.get(text.lower(), text)

    @classmethod
    def _severity_label(cls, value) -> str:
        text = str(getattr(value, "value", value) or "").upper()
        return cls.SEVERITY_LABELS.get(text, text.lower())

    @classmethod
    def _status_label(cls, value) -> str:
        text = str(getattr(value, "value", value) or "")
        base, separator, detail = text.partition(":")
        label = cls.STATUS_LABELS.get(base.strip().lower(), base.strip() or text)
        return f"{label}: {detail.strip()}" if separator else label

    def set_active(self, active: bool):
        self._active = active
        if self._closing:
            return
        if active:
            self.state_card.set_value("Aktivno", "Samodejno osveževanje med prikazom", "#16a34a")
            if not self.refresh_timer.isActive():
                self.refresh_timer.start(5000)
            QTimer.singleShot(0, self.refresh_data)
        else:
            self.state_card.set_value("Ozadje", "Samodejno osveževanje se nadaljuje", "#64748b")

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        header = QFrame()
        header.setStyleSheet(_card_style())
        header_layout = QVBoxLayout()
        header_layout.setContentsMargins(16, 14, 16, 14)
        title = QLabel("Avtomatizacija")
        title.setFont(QFont("Segoe UI", 15, QFont.Bold))
        title.setStyleSheet("color: #172033;")
        subtitle = QLabel("Pregled odzivov, blokiranih naslovov in izvedenih postopkov.")
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #94a3b8;")
        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)
        header.setLayout(header_layout)
        layout.addWidget(header)

        summary_layout = QHBoxLayout()
        self.responses_card = SummaryCard("Odzivi", "#2563eb")
        self.blocked_card = SummaryCard("Blokirani IP", "#dc2626")
        self.state_card = SummaryCard("Stanje", "#64748b")
        summary_layout.addWidget(self.responses_card)
        summary_layout.addWidget(self.blocked_card)
        summary_layout.addWidget(self.state_card)
        layout.addLayout(summary_layout)

        top_controls = QHBoxLayout()
        self.automation_switch = QCheckBox("Samodejna obdelava alarmov")
        self.automation_switch.setChecked(False)
        self.automation_switch.toggled.connect(self._on_automation_mode_changed)
        self.automation_switch.setToolTip(
            "Izklopljeno: alarmi se obdelajo samo po ročnem pošiljanju iz zavihka Alarmov."
        )
        top_controls.addWidget(self.automation_switch)
        self.status_label = QLabel("Čakam prvo osvežitev avtomatizacije.")
        self.status_label.setStyleSheet("color: #475569;")
        top_controls.addWidget(self.status_label)
        top_controls.addStretch()
        layout.addLayout(top_controls)

        tabs = QTabWidget()
        tabs.addTab(self._create_response_tab(), "Zgodovina odzivov")
        tabs.addTab(self._create_statistics_tab(), "Statistika")
        tabs.addTab(self._create_playbook_history_tab(), "Zgodovina postopkov")
        layout.addWidget(tabs)

        detail_frame = QFrame()
        detail_frame.setStyleSheet(_card_style())
        detail_layout = QVBoxLayout()
        detail_layout.setContentsMargins(16, 14, 16, 14)
        detail_title = QLabel("Operativne opombe")
        detail_title.setFont(QFont("Segoe UI", 11, QFont.Bold))
        detail_title.setStyleSheet("color: #172033;")
        self.notes_text = QTextEdit()
        self.notes_text.setReadOnly(True)
        self.notes_text.setText("Osvežitve povzamejo odzive, blokirane naslove in izvedene postopke.")
        detail_layout.addWidget(detail_title)
        detail_layout.addWidget(self.notes_text)
        detail_frame.setLayout(detail_layout)
        layout.addWidget(detail_frame)

        self.setLayout(layout)

    def _on_automation_mode_changed(self, enabled):
        if self.automation_mode_callback:
            self.automation_mode_callback(bool(enabled))
        mode = "Samodejni način vključen" if enabled else "Ročni način vključen"
        self.status_label.setText(mode)
        self.state_card.set_value(
            "Samodejno" if enabled else "Ročno",
            "Obdelava vseh alarmov" if enabled else "Obdelava na zahtevo operaterja",
            "#d97706" if enabled else "#2563eb",
        )

    def _create_response_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        self.response_history = ResponseHistoryWidget()
        layout.addWidget(QLabel("Samodejni odzivi:"))
        layout.addWidget(self.response_history)

        stats_group = QGroupBox("Statistika odzivov")
        stats_layout = QHBoxLayout()
        self.total_responses_label = QLabel("Skupaj odzivov: 0")
        self.successful_responses_label = QLabel("Uspešnih: 0")
        self.failed_responses_label = QLabel("Neuspešnih: 0")
        stats_layout.addWidget(self.total_responses_label)
        stats_layout.addWidget(self.successful_responses_label)
        stats_layout.addWidget(self.failed_responses_label)
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        widget.setLayout(layout)
        return widget

    def _create_statistics_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()

        stats_group = QGroupBox("Skupna statistika")
        stats_layout = QVBoxLayout()
        self.total_threats_label = QLabel("Obdelani dogodki: 0")
        self.avg_response_time_label = QLabel("Povp. čas odziva: --")
        self.success_rate_label = QLabel("Uspešnost odzivov: 0%")
        for widget_label in (
            self.total_threats_label,
            self.avg_response_time_label,
            self.success_rate_label,
        ):
            stats_layout.addWidget(widget_label)
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)

        layout.addWidget(QLabel("Trenutno blokirani IP naslovi:"))
        self.blocked_ips_table = QTableWidget()
        self.blocked_ips_table.setColumnCount(3)
        self.blocked_ips_table.setHorizontalHeaderLabels(["IP naslov", "Blokiran ob", "Poteče"])
        self._configure_table(self.blocked_ips_table)
        layout.addWidget(self.blocked_ips_table)

        ip_button_layout = QHBoxLayout()
        self.unblock_ip_btn = QPushButton("Odblokiraj izbrani IP")
        self.unblock_ip_btn.clicked.connect(self._on_unblock_ip)
        ip_button_layout.addWidget(self.unblock_ip_btn)
        ip_button_layout.addStretch()
        layout.addLayout(ip_button_layout)

        widget.setLayout(layout)
        return widget

    def _create_playbook_history_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        self.playbook_table = QTableWidget()
        self.playbook_table.setColumnCount(6)
        self.playbook_table.setHorizontalHeaderLabels(["ID izvedbe", "Postopek", "Status", "Uspešno", "Neuspešno", "Trajanje (s)"])
        self._configure_table(self.playbook_table)
        self.playbook_stats_label = QLabel("Postopki: čakam")
        layout.addWidget(QLabel("Zadnje izvedbe postopkov:"))
        layout.addWidget(self.playbook_stats_label)
        layout.addWidget(self.playbook_table)
        widget.setLayout(layout)
        return widget

    def refresh_data(self):
        if self._closing:
            return
        if self._refresh_in_progress:
            self._refresh_pending = True
            return
        self._refresh_in_progress = True
        self.state_card.set_value("Osvežujem", "Berem stanje avtomatizacije", "#64748b")
        self.status_label.setText("Osveževanje avtomatizacije je v teku...")
        self.request_refresh.emit()

    def _apply_table_rows(self, table, rows):
        table.setUpdatesEnabled(False)
        try:
            table.setRowCount(len(rows))
            for row_idx, row in enumerate(rows):
                for col_idx, value in enumerate(row):
                    table.setItem(row_idx, col_idx, QTableWidgetItem(str(value)))
        finally:
            table.setUpdatesEnabled(True)

    def _on_worker_finished(self, data: dict):
        try:
            self._last_refresh_text = datetime.now().strftime("%H:%M:%S")
            response_stats = data.get("response_stats", {})
            actions_executed = response_stats.get("actions_executed", 0)
            actions_failed = response_stats.get("actions_failed", 0)
            successful = actions_executed - actions_failed
            self.total_responses_label.setText(f"Skupaj odzivov: {actions_executed}")
            self.successful_responses_label.setText(f"Uspešnih: {successful}")
            self.failed_responses_label.setText(f"Neuspešnih: {actions_failed}")
            self.success_rate_label.setText(f"Uspešnost odzivov: {response_stats.get('success_rate', 0.0) * 100:.1f}%")
            self.total_threats_label.setText(f"Obdelani dogodki: {response_stats.get('total_responses', 0)}")
            avg_response_time_ms = float(response_stats.get("avg_response_time_ms", 0.0) or 0.0)
            self.avg_response_time_label.setText(
                f"Povp. čas odziva: {avg_response_time_ms:.1f} ms" if avg_response_time_ms > 0 else "Povp. čas odziva: --"
            )
            self.responses_card.set_value(str(actions_executed), "")

            blocked_ips = data.get("blocked_ips", []) or []
            blocked_details = data.get("blocked_ip_details", []) or []
            blocked_rows = []
            if blocked_details:
                for item in blocked_details:
                    blocked_at = item.get("blocked_at")
                    expires_at = item.get("expires_at")
                    blocked_rows.append(
                        [
                            item.get("ip", ""),
                            str(blocked_at)[:19] if blocked_at else "--",
                            str(expires_at)[:19] if expires_at else "--",
                        ]
                    )
            else:
                blocked_rows = [[ip, "--", "--"] for ip in blocked_ips]
            self._apply_table_rows(self.blocked_ips_table, blocked_rows)
            self.blocked_card.set_value(str(len(blocked_ips)), "", "#dc2626" if blocked_ips else "#94a3b8")

            playbook_rows = []
            for item in data.get("playbook_history", []) or []:
                playbook_rows.append(
                    [
                        item.get("execution_id", ""),
                        self._playbook_label(item.get("playbook_id", "")),
                        self._status_label(item.get("status", "")),
                        item.get("completed_actions", ""),
                        item.get("failed_actions", ""),
                        item.get("duration", ""),
                    ]
                )
            if not playbook_rows:
                for item in data.get("registered_playbooks", []) or []:
                    playbook_rows.append(
                        [
                            "pripravljeno",
                            self._playbook_label(item.get("playbook_id", "")),
                            f"registrirano ({item.get('name', '')})",
                            item.get("actions", 0),
                            0,
                            "--",
                        ]
                    )
            self._apply_table_rows(self.playbook_table, playbook_rows)
            playbook_stats = data.get("playbook_stats", {}) or {}
            if playbook_stats:
                self.playbook_stats_label.setText(
                    "Postopki: "
                    f"{playbook_stats.get('total_playbooks', 0)} registriranih, "
                    f"{playbook_stats.get('total_executions', 0)} izvedb, "
                    f"{playbook_stats.get('successful_executions', 0)} zaključenih"
                )
            else:
                self.playbook_stats_label.setText(f"Postopki: {len(playbook_rows)} registriranih/vidnih")

            self.status_label.clear()
            self.state_card.set_value("Pripravljeno", "", "#16a34a")
            if blocked_ips:
                self.notes_text.setText("Avtomatizacija je stabilna. Preglej blokirane IP naslove in zgodovino postopkov.")
            else:
                self.notes_text.setText("Avtomatizacija miruje. Alarm lahko pošlješ v obravnavo iz zavihka Alarmov.")
        except Exception as exc:
            self.logger.error("Error applying worker results: %s", exc)
            self.state_card.set_value("Napaka", str(exc), "#dc2626")
        finally:
            self._refresh_in_progress = False
            if self._refresh_pending and not self._closing:
                self._refresh_pending = False
                QTimer.singleShot(0, self.refresh_data)

    def _set_action_busy(self, busy: bool, message: str):
        self._action_in_progress = busy
        self.unblock_ip_btn.setEnabled(not busy)
        if busy:
            self.state_card.set_value("Uveljavljam", message, "#d97706")
            self.status_label.setText(message)
        elif not self._refresh_in_progress:
            self.status_label.clear()

    def _queue_action(self, payload: dict, busy_message: str):
        if self._closing or self._action_in_progress:
            return
        self._set_action_busy(True, busy_message)
        self.request_action.emit(dict(payload))

    def _on_action_finished(self, action: str, result: dict):
        self._set_action_busy(False, result.get("message", "Akcija je zaključena"))
        ok = bool(result.get("ok"))
        message = result.get("message", "")
        if ok and action == "inject_threat" and self.threat_callback and result.get("threat"):
            try:
                self.threat_callback(result["threat"])
            except Exception:
                self.logger.exception("Failed to deliver demo threat callback")
        if ok:
            self.state_card.set_value("Pripravljeno", message or "Akcija je uveljavljena", "#16a34a")
        else:
            self.state_card.set_value("Težava", message or "Akcija ni uspela", "#dc2626")
            tb = result.get("traceback")
            if tb:
                self.logger.debug("Automation action traceback for %s:\n%s", action, tb)
        self.status_label.setText(message or f"{self._action_label(action)} zaključeno")
        if result.get("refresh", True) and not self._closing:
            QTimer.singleShot(0, self.refresh_data)

    def _inject_threat(self, threat, playbook_id=None):
        self._queue_action(
            {"action": "inject_threat", "threat": dict(threat), "playbook_id": playbook_id},
            f"Sprožam demo dogodek ({self._severity_label(threat.get('threat_level', 'demo'))})...",
        )

    def _build_demo_threat(self, src_ip, dst_ip, dst_port, protocol, threat_level, threat_score, indicators, recommendation):
        return {
            "threat_id": int(datetime.now().timestamp() * 1000),
            "timestamp": datetime.now().isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "threat_level": threat_level,
            "threat_score": threat_score,
            "ml_score": max(threat_score - 0.02, 0.0),
            "anomaly_score": max(threat_score - 0.05, 0.0),
            "behavioral_score": max(threat_score - 0.1, 0.0),
            "indicators": indicators,
            "recommendation": recommendation,
        }

    def _trigger_demo_exfiltration(self):
        self._inject_threat(self._build_demo_threat("10.10.10.99", "192.168.1.1", 8080, "TCP", "CRITICAL", 0.97, ["exfiltration"], "Blokiraj in izoliraj gostitelja. Preveri možnost odtekanja podatkov."), playbook_id="pb_exfil")

    def _trigger_demo_portscan(self):
        self._inject_threat(self._build_demo_threat("10.10.10.77", "192.168.1.2", 22, "TCP", "HIGH", 0.85, ["port_scanning"], "Blokiraj izvorni IP in obvesti skrbnika."), playbook_id="pb_portscan")

    def _trigger_demo_c2(self):
        self._inject_threat(self._build_demo_threat("10.10.10.55", "8.8.8.8", 443, "TCP", "CRITICAL", 0.93, ["c2_beacon"], "Izoliraj gostitelja in blokiraj C2 strežnik."), playbook_id="pb_c2")

    def _trigger_demo_ddos(self):
        self._inject_threat(self._build_demo_threat("10.10.10.200", "192.168.1.10", 80, "TCP", "CRITICAL", 0.99, ["ddos_attack"], "Blokiraj napadalne izvore in omeji hitrost prometa."), playbook_id="pb_ddos")

    def _trigger_demo_lateral(self):
        self._inject_threat(self._build_demo_threat("10.10.10.150", "192.168.1.20", 445, "TCP", "CRITICAL", 0.96, ["lateral_movement"], "Izoliraj kompromitiranega gostitelja in izvedi podrobnejši pregled."), playbook_id="pb_lateral")

    def _trigger_demo_medium(self):
        self._inject_threat(self._build_demo_threat("10.10.10.33", "192.168.1.5", 53, "UDP", "MEDIUM", 0.55, ["dns_tunnel"], "Omeji DNS promet in nadaljuj spremljanje."))

    def _trigger_demo_low(self):
        self._inject_threat(self._build_demo_threat("10.10.10.10", "192.168.1.100", 443, "TCP", "LOW", 0.10, ["benign"], "Samo zabeleži. Dodatna akcija ni potrebna."))

    def _on_unblock_ip(self):
        selected = self.blocked_ips_table.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Izberi IP", "Izberi IP naslov za odblokiranje.")
            return
        ip = self.blocked_ips_table.item(self.blocked_ips_table.currentRow(), 0).text()
        self._queue_action({"action": "unblock_ip", "ip": ip}, f"Odstranjujem blokado za {ip}...")

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
        try:
            if self._action_thread.isRunning():
                self._action_thread.quit()
                self._action_thread.wait(2000)
        except Exception:
            pass
        event.accept()
