"""
Gradnik tokov - prikaz in pregled omrežnih tokov.
"""

import csv
import logging
from collections import deque
from datetime import datetime
from pathlib import Path

from PyQt5.QtCore import QSignalBlocker, QObject, QThread, QTimer, Qt, pyqtSignal
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from ui_components import SummaryCard, card_style as _card_style


class _FlowsFetchWorker(QObject):
    finished = pyqtSignal(list)
    failed = pyqtSignal(str)

    def __init__(self, api_client, limit: int):
        super().__init__()
        self.api_client = api_client
        self.limit = limit

    def run(self):
        try:
            flows = self.api_client.get_flows(limit=self.limit)
        except Exception as exc:
            self.failed.emit(str(exc))
            return
        self.finished.emit(list(flows))


class FlowDetailsDialog(QDialog):
    def __init__(self, flow: dict, parent=None):
        super().__init__(parent)
        self.flow = dict(flow)
        self.setWindowTitle("Podrobnosti toka")
        self.resize(720, 440)

        layout = QVBoxLayout(self)

        summary_lines = [
            f"Izvor: {flow.get('src_ip', 'N/A')}:{flow.get('src_port', 'N/A')}",
            f"Cilj: {flow.get('dst_ip', 'N/A')}:{flow.get('dst_port', 'N/A')}",
            f"Protokol: {flow.get('protocol', 'N/A')}",
            f"Paketi: {flow.get('packets', 'N/A')}",
            f"Bajti: {flow.get('bytes', 'N/A')}",
            f"Trajanje (s): {flow.get('duration', 'N/A')}",
            f"Ocena anomalije: {flow.get('anomaly_score', 'N/A')}",
            f"Čas: {flow.get('timestamp', flow.get('last_seen', 'N/A'))}",
        ]
        summary = QLabel("\n".join(summary_lines))
        summary.setTextInteractionFlags(Qt.TextSelectableByMouse)
        summary.setStyleSheet(
            """
            QLabel {
                background-color: #f8fafc;
                color: #172033;
                border: 1px solid #d8dee8;
                padding: 10px;
            }
            """
        )
        layout.addWidget(summary)

        layout.addWidget(QLabel("Surovi podatki"))
        raw = QTextEdit()
        raw.setReadOnly(True)
        raw.setPlainText(self._format_raw(flow))
        layout.addWidget(raw)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        buttons.button(QDialogButtonBox.Close).setText("Zapri")
        buttons.button(QDialogButtonBox.Close).clicked.connect(self.close)
        layout.addWidget(buttons)

    @staticmethod
    def _format_raw(flow: dict) -> str:
        return "\n".join(f"{key}: {flow.get(key)}" for key in sorted(flow.keys()))


class FlowsWidget(QWidget):
    """Prikaži in analiziraj omrežne tokove."""

    FLOW_COLUMNS = [
        "Izvorni IP",
        "Izvorna vrata",
        "Ciljni IP",
        "Ciljna vrata",
        "Protokol",
        "Paketi",
        "Bajti",
        "Trajanje (s)",
        "Ocena anomalije",
    ]

    def __init__(self, api_client):
        super().__init__()
        self.api_client = api_client
        self.logger = logging.getLogger(__name__)
        self._active = True
        self._cached_flows = []
        self._visible_flows = []
        self._refresh_thread = None
        self._refresh_worker = None
        self._refresh_in_progress = False
        self._pending_flows = deque()
        self._flow_flush_scheduled = False
        self._render_scheduled = False
        self._pending_live_render = False
        self._max_cached_flows = 500
        self._max_pending_flows = 1000
        self._selected_flow_keys = set()
        self.init_ui()
        self.refresh_flows()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        header = QFrame()
        header.setStyleSheet(_card_style())
        header_layout = QVBoxLayout()
        header_layout.setContentsMargins(16, 14, 16, 14)
        title = QLabel("Omrežni tokovi")
        title.setFont(QFont("Segoe UI", 15, QFont.Bold))
        title.setStyleSheet("color: #172033;")
        subtitle = QLabel("Filtriranje, razvrščanje in pregled aktivnih povezav v omrežju.")
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #94a3b8;")
        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)
        header.setLayout(header_layout)
        layout.addWidget(header)

        summary_layout = QGridLayout()
        self.total_card = SummaryCard("Vidni tokovi", "#2563eb")
        self.anomalous_card = SummaryCard("Anomalni", "#dc2626")
        self.selection_card = SummaryCard("Izbrani", "#64748b")
        self.protocol_card = SummaryCard("Protokol", "#16a34a")
        summary_layout.addWidget(self.total_card, 0, 0)
        summary_layout.addWidget(self.anomalous_card, 0, 1)
        summary_layout.addWidget(self.selection_card, 0, 2)
        summary_layout.addWidget(self.protocol_card, 0, 3)
        layout.addLayout(summary_layout)

        control_layout = QHBoxLayout()
        control_layout.addWidget(QLabel("Prikaz:"))
        self.limit_spinner = QSpinBox()
        self.limit_spinner.setValue(50)
        self.limit_spinner.setMinimum(10)
        self.limit_spinner.setMaximum(500)
        self.limit_spinner.valueChanged.connect(self.apply_filters)
        control_layout.addWidget(self.limit_spinner)

        control_layout.addWidget(QLabel("Razvrsti po:"))
        self.sort_combo = QComboBox()
        for label, value in [
            ("Zadnja aktivnost", "last_activity"),
            ("Preneseni bajti", "bytes"),
            ("Paketi", "packets"),
            ("Trajanje", "duration"),
            ("Ocena anomalije", "anomaly_score"),
        ]:
            self.sort_combo.addItem(label, value)
        self.sort_combo.currentTextChanged.connect(self.apply_filters)
        control_layout.addWidget(self.sort_combo)

        control_layout.addWidget(QLabel("Protokol:"))
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItem("Vsi", "ALL")
        self.protocol_combo.addItem("TCP", "TCP")
        self.protocol_combo.addItem("UDP", "UDP")
        self.protocol_combo.currentTextChanged.connect(self.apply_filters)
        control_layout.addWidget(self.protocol_combo)

        control_layout.addWidget(QLabel("Iskanje:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("IP, vrata, protokol...")
        self.search_input.textChanged.connect(self.apply_filters)
        control_layout.addWidget(self.search_input)

        self.refresh_btn = QPushButton("Osveži")
        self.refresh_btn.clicked.connect(self.refresh_flows)
        control_layout.addWidget(self.refresh_btn)

        self.view_details_btn = QPushButton("Podrobnosti")
        self.view_details_btn.setEnabled(False)
        self.view_details_btn.clicked.connect(self.show_selected_flow_details)
        control_layout.addWidget(self.view_details_btn)

        export_btn = QPushButton("Izvozi CSV")
        export_btn.clicked.connect(self.export_flows)
        control_layout.addWidget(export_btn)
        control_layout.addStretch()
        layout.addLayout(control_layout)

        content_layout = QHBoxLayout()
        left_layout = QVBoxLayout()

        self.flows_table = QTableWidget()
        self.flows_table.setColumnCount(len(self.FLOW_COLUMNS))
        self.flows_table.setHorizontalHeaderLabels(self.FLOW_COLUMNS)
        header = self.flows_table.horizontalHeader()
        if header:
            for col in range(len(self.FLOW_COLUMNS)):
                header.setSectionResizeMode(col, QHeaderView.Interactive)
            header.setStretchLastSection(True)
        self.flows_table.setAlternatingRowColors(True)
        self.flows_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.flows_table.setSelectionMode(QTableWidget.MultiSelection)
        self.flows_table.itemDoubleClicked.connect(self.show_flow_details_for_item)
        self.flows_table.itemSelectionChanged.connect(self._update_selection_state)
        left_layout.addWidget(self.flows_table)

        actions_layout = QHBoxLayout()
        self.copy_source_btn = QPushButton("Kopiraj izvorni IP")
        self.copy_source_btn.clicked.connect(self.copy_selected_source_ip)
        actions_layout.addWidget(self.copy_source_btn)
        actions_layout.addWidget(self.view_details_btn)
        actions_layout.addStretch()
        left_layout.addLayout(actions_layout)

        stats_layout = QHBoxLayout()
        stats_layout.addWidget(QLabel("Vidni tokovi:"))
        self.total_flows_label = QLabel("0")
        self.total_flows_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.total_flows_label.setStyleSheet("color: #16a34a;")
        stats_layout.addWidget(self.total_flows_label)
        stats_layout.addWidget(QLabel("Izbrani:"))
        self.selected_flows_label = QLabel("0")
        self.selected_flows_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.selected_flows_label.setStyleSheet("color: #2563eb;")
        stats_layout.addWidget(self.selected_flows_label)
        stats_layout.addWidget(QLabel("Anomalni:"))
        self.anomalous_flows_label = QLabel("0")
        self.anomalous_flows_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.anomalous_flows_label.setStyleSheet("color: #dc2626;")
        stats_layout.addWidget(self.anomalous_flows_label)
        stats_layout.addStretch()
        left_layout.addLayout(stats_layout)

        self.empty_state_label = QLabel("Ni tokov za prikaz")
        self.empty_state_label.setStyleSheet("color: #64748b; padding: 4px 0;")
        self.empty_state_label.hide()
        left_layout.addWidget(self.empty_state_label)
        content_layout.addLayout(left_layout, 2)

        detail_frame = QFrame()
        detail_frame.setStyleSheet(_card_style())
        detail_layout = QVBoxLayout()
        detail_layout.setContentsMargins(16, 14, 16, 14)
        detail_title = QLabel("Izbrani tok")
        detail_title.setFont(QFont("Segoe UI", 11, QFont.Bold))
        detail_title.setStyleSheet("color: #172033;")
        self.selection_summary_label = QLabel("")
        self.selection_summary_label.setWordWrap(True)
        self.selection_summary_label.setStyleSheet("color: #475569;")
        self.selection_details = QTextEdit()
        self.selection_details.setReadOnly(True)
        self.selection_details.setText("Noben tok ni izbran.")
        detail_layout.addWidget(detail_title)
        detail_layout.addWidget(self.selection_summary_label)
        detail_layout.addWidget(self.selection_details, 1)
        detail_frame.setLayout(detail_layout)
        content_layout.addWidget(detail_frame, 1)

        layout.addLayout(content_layout)
        self.setLayout(layout)
        self._update_selection_state()
        self._update_summary([])

    def refresh_flows(self):
        if self._refresh_in_progress:
            self.logger.info("Flows refresh skipped (already running)")
            return
        self._refresh_in_progress = True
        if hasattr(self, "refresh_btn"):
            self.refresh_btn.setEnabled(False)

        limit = self.limit_spinner.value()
        self._refresh_thread = QThread()
        try:
            from thread_registry import register
            register(self._refresh_thread)
        except Exception:
            pass
        self._refresh_worker = _FlowsFetchWorker(self.api_client, limit)
        self._refresh_worker.moveToThread(self._refresh_thread)
        self._refresh_thread.started.connect(self._refresh_worker.run)
        self._refresh_worker.finished.connect(self._on_flows_ready)
        self._refresh_worker.failed.connect(self._on_flows_failed)
        self._refresh_worker.finished.connect(self._refresh_thread.quit)
        self._refresh_worker.failed.connect(self._refresh_thread.quit)
        self._refresh_worker.finished.connect(self._refresh_worker.deleteLater)
        self._refresh_worker.failed.connect(self._refresh_worker.deleteLater)
        self._refresh_thread.finished.connect(self._cleanup_refresh_thread)
        self._refresh_thread.finished.connect(self._refresh_thread.deleteLater)
        self._refresh_thread.start()

    def _on_flows_ready(self, flows: list):
        self.logger.info("Flows refresh OK (count=%s)", len(flows))
        self._cached_flows = list(flows)
        if len(self._cached_flows) > self._max_cached_flows:
            self._cached_flows = self._cached_flows[:self._max_cached_flows]
        self.apply_filters()

    def _on_flows_failed(self, _message: str):
        self.logger.warning("Flows refresh failed")
        self._cached_flows = []
        self.apply_filters()

    def _cleanup_refresh_thread(self):
        self._refresh_thread = None
        self._refresh_worker = None
        self._refresh_in_progress = False
        if hasattr(self, "refresh_btn"):
            self.refresh_btn.setEnabled(True)

    def apply_filters(self):
        protocol = self.protocol_combo.currentData() or self.protocol_combo.currentText().strip().upper()
        query = self.search_input.text().strip().lower()
        flows = list(self._cached_flows)

        if protocol != "ALL":
            flows = [flow for flow in flows if str(flow.get("protocol", "")).upper() == protocol]

        if query:
            filtered = []
            for flow in flows:
                haystack = " ".join(
                    [
                        str(flow.get("src_ip", "")),
                        str(flow.get("src_port", "")),
                        str(flow.get("dst_ip", "")),
                        str(flow.get("dst_port", "")),
                        str(flow.get("protocol", "")),
                    ]
                ).lower()
                if query in haystack:
                    filtered.append(flow)
            flows = filtered

        sort_by = self.sort_combo.currentData() or self.sort_combo.currentText()
        if sort_by == "bytes":
            flows.sort(key=lambda item: float(item.get("bytes", 0) or 0), reverse=True)
        elif sort_by == "packets":
            flows.sort(key=lambda item: float(item.get("packets", 0) or 0), reverse=True)
        elif sort_by == "duration":
            flows.sort(key=lambda item: float(item.get("duration", 0) or 0), reverse=True)
        elif sort_by == "anomaly_score":
            flows.sort(key=lambda item: float(item.get("anomaly_score", 0) or 0), reverse=True)

        limit = self.limit_spinner.value()
        self._render_flows(flows[:limit])

    def _schedule_render(self):
        if self._render_scheduled:
            return
        self._render_scheduled = True
        QTimer.singleShot(0, self._run_scheduled_render)

    def _run_scheduled_render(self):
        self._render_scheduled = False
        self._pending_live_render = False
        self.apply_filters()

    def set_active(self, active: bool):
        self._active = bool(active)
        if self._active and (self._pending_live_render or self._pending_flows):
            if self._pending_flows and not self._flow_flush_scheduled:
                self._flow_flush_scheduled = True
                QTimer.singleShot(0, self._flush_flows)
            else:
                self._schedule_render()

    def _render_flows(self, flows):
        selected_keys = set(self._selected_flow_keys)
        self._visible_flows = [dict(flow) for flow in flows]
        self.flows_table.setSortingEnabled(False)
        self.flows_table.setUpdatesEnabled(False)
        with QSignalBlocker(self.flows_table):
            self.flows_table.clearSelection()
            self.flows_table.setRowCount(len(flows))
            for row, flow in enumerate(flows):
                items = [
                    flow.get("src_ip", "N/A"),
                    str(flow.get("src_port", "N/A")),
                    flow.get("dst_ip", "N/A"),
                    str(flow.get("dst_port", "N/A")),
                    flow.get("protocol", "TCP"),
                    str(flow.get("packets", 0)),
                    str(flow.get("bytes", 0)),
                    str(flow.get("duration", 0)),
                    f"{float(flow.get('anomaly_score', 0) or 0):.3f}",
                ]
                for col, text in enumerate(items):
                    item = QTableWidgetItem(text)
                    if col == 0:
                        item.setData(Qt.UserRole, dict(flow))
                    if col == 8:
                        try:
                            score = float(text)
                            if score > 0.7:
                                item.setForeground(QColor("#dc2626"))
                                item.setFont(QFont("Segoe UI", 10, QFont.Bold))
                            elif score > 0.4:
                                item.setForeground(QColor("#d97706"))
                        except Exception:
                            pass
                    self.flows_table.setItem(row, col, item)
                if self._flow_key(flow) in selected_keys:
                    self.flows_table.selectRow(row)
        anomalous_count = sum(
            1 for flow in flows if float(flow.get("anomaly_score", 0) or 0) > 0.7
        )
        self._selected_flow_keys = {
            self._flow_key(flow) for flow in flows if self._flow_key(flow) in selected_keys
        }
        self.total_flows_label.setText(str(len(flows)))
        self.anomalous_flows_label.setText(str(anomalous_count))
        self.flows_table.setUpdatesEnabled(True)
        self.flows_table.setSortingEnabled(True)
        self.empty_state_label.setText("Noben tok ne ustreza trenutnim filtrom" if self._cached_flows and not flows else "Tokovi še niso na voljo")
        self.empty_state_label.setVisible(len(flows) == 0)
        self._update_summary(flows)
        self._update_selection_state()

    def _update_summary(self, flows):
        total = len(flows)
        anomalous = sum(1 for flow in flows if float(flow.get("anomaly_score", 0) or 0) > 0.7)
        protocol = self.protocol_combo.currentText()
        self.total_card.set_value(str(total), "")
        self.anomalous_card.set_value(str(anomalous), "", "#dc2626" if anomalous else "#94a3b8")
        self.protocol_card.set_value(self.protocol_combo.currentText(), "")

    def export_flows(self):
        if not self._visible_flows:
            QMessageBox.information(self, "Ni podatkov", "Ni vidnih tokov za izvoz.")
            return
        filename = f"tokovi_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filepath = Path.home() / "Downloads" / filename
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(self.FLOW_COLUMNS)
            for flow in self._visible_flows:
                writer.writerow(
                    [
                        flow.get("src_ip", "N/A"),
                        str(flow.get("src_port", "N/A")),
                        flow.get("dst_ip", "N/A"),
                        str(flow.get("dst_port", "N/A")),
                        flow.get("protocol", "TCP"),
                        str(flow.get("packets", 0)),
                        str(flow.get("bytes", 0)),
                        str(flow.get("duration", 0)),
                        f"{float(flow.get('anomaly_score', 0) or 0):.3f}",
                    ]
                )
        QMessageBox.information(self, "Izvoz uspešen", f"Izvoženih tokov: {len(self._visible_flows)}\n{filepath}")

    def _update_selection_state(self):
        selection_model = self.flows_table.selectionModel()
        selected_rows = selection_model.selectedRows() if selection_model else []
        selected_count = len(selected_rows)
        self.selected_flows_label.setText(str(selected_count))
        self.selection_card.set_value(str(selected_count), "")
        self.view_details_btn.setEnabled(selected_count > 0)
        self.copy_source_btn.setEnabled(selected_count > 0)

        if selected_count == 0:
            self.selection_summary_label.clear()
            self.selection_details.setText("Noben tok ni izbran.")
            self._selected_flow_keys = set()
            return

        flow = self._flow_for_row(selected_rows[0].row())
        if flow is None:
            self.selection_summary_label.clear()
            self.selection_details.setText("Noben tok ni izbran.")
            return

        self._selected_flow_keys = {
            self._flow_key(self._flow_for_row(index.row()))
            for index in selected_rows
            if self._flow_for_row(index.row()) is not None
        }
        score = float(flow.get("anomaly_score", 0) or 0)
        state = "Anomalen" if score > 0.7 else "Sumljiv" if score > 0.4 else "Običajen"
        self.selection_summary_label.setText(
            f"{flow.get('src_ip', 'N/A')}:{flow.get('src_port', 'N/A')} -> {flow.get('dst_ip', 'N/A')}:{flow.get('dst_port', 'N/A')} | {state}"
        )
        self.selection_details.setText(
            "\n".join(
                [
                    f"Izvor: {flow.get('src_ip', 'N/A')}:{flow.get('src_port', 'N/A')}",
                    f"Cilj: {flow.get('dst_ip', 'N/A')}:{flow.get('dst_port', 'N/A')}",
                    f"Protokol: {flow.get('protocol', 'N/A')}",
                    f"Paketi: {flow.get('packets', 0)}",
                    f"Bajti: {flow.get('bytes', 0)}",
                    f"Trajanje: {flow.get('duration', 0)}",
                    f"Ocena anomalije: {score:.3f}",
                    f"Čas: {flow.get('timestamp', flow.get('last_seen', 'N/A'))}",
                ]
            )
        )

    def copy_selected_source_ip(self):
        selection_model = self.flows_table.selectionModel()
        selected_rows = selection_model.selectedRows() if selection_model else []
        if not selected_rows:
            QMessageBox.information(self, "Ni izbire", "Najprej izberi tok.")
            return
        flow = self._flow_for_row(selected_rows[0].row())
        if not flow:
            QMessageBox.warning(self, "Ni na voljo", "Izvorni IP za to vrstico ni na voljo.")
            return
        text = str(flow.get("src_ip", ""))
        if not text:
            QMessageBox.warning(self, "Ni na voljo", "Izvorni IP za to vrstico ni na voljo.")
            return
        app = QApplication.instance()
        if app is not None:
            app.clipboard().setText(text)
        QMessageBox.information(self, "Kopirano", f"Kopiran izvorni IP: {text}")

    def _flow_for_row(self, row: int):
        if row < 0:
            return None
        item = self.flows_table.item(row, 0)
        if item is not None:
            flow = item.data(Qt.UserRole)
            if isinstance(flow, dict):
                return dict(flow)
        if row < len(self._visible_flows):
            return dict(self._visible_flows[row])
        return None

    @staticmethod
    def _flow_key(flow):
        if not isinstance(flow, dict):
            return None
        flow_id = flow.get("flow_id") or flow.get("id")
        if flow_id:
            return str(flow_id)
        return (
            str(flow.get("src_ip", "")),
            str(flow.get("src_port", "")),
            str(flow.get("dst_ip", "")),
            str(flow.get("dst_port", "")),
            str(flow.get("protocol", "")).upper(),
        )

    def show_flow_details_for_item(self, item):
        if item is None:
            return
        self._show_flow_details(item.row())

    def show_selected_flow_details(self):
        selection_model = self.flows_table.selectionModel()
        selected_rows = selection_model.selectedRows() if selection_model else []
        if not selected_rows:
            self.selection_summary_label.clear()
            self.selection_details.setText("Noben tok ni izbran.")
            return
        self._show_flow_details(selected_rows[0].row())

    def _show_flow_details(self, row: int):
        flow = self._flow_for_row(row)
        if flow is None:
            self.selection_summary_label.clear()
            self.selection_details.setText("Noben tok ni izbran.")
            return
        dialog = FlowDetailsDialog(flow, self)
        dialog.exec_()

    def add_flow(self, flow: dict):
        try:
            self._pending_flows.append(dict(flow))
        except Exception:
            return
        if len(self._pending_flows) > self._max_pending_flows:
            try:
                self._pending_flows.popleft()
            except Exception:
                pass
        if not self._flow_flush_scheduled:
            self._flow_flush_scheduled = True
            QTimer.singleShot(100, self._flush_flows)

    def _flush_flows(self):
        self._flow_flush_scheduled = False
        updated = False
        for _ in range(min(50, len(self._pending_flows))):
            try:
                flow = self._pending_flows.popleft()
            except IndexError:
                break
            self._cached_flows.insert(0, flow)
            updated = True
        if len(self._cached_flows) > self._max_cached_flows:
            self._cached_flows = self._cached_flows[:self._max_cached_flows]
        if updated:
            self._pending_live_render = True
            self._schedule_render()
        if self._pending_flows:
            self._flow_flush_scheduled = True
            QTimer.singleShot(200 if self._active else 500, self._flush_flows)

    def cache_flow(self, flow: dict):
        self._cached_flows.insert(0, dict(flow))
        if len(self._cached_flows) > self._max_cached_flows:
            self._cached_flows = self._cached_flows[:self._max_cached_flows]

    def get_cached_flows(self, limit: int = 50):
        return list(self._cached_flows[:limit])
