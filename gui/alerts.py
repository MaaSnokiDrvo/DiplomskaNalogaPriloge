"""
Gradnik alarmov - zgodovina in upravljanje alarmov.
"""

from collections import deque
from datetime import datetime
import csv
from pathlib import Path

from PyQt5.QtCore import QDate, QObject, QSignalBlocker, QThread, QTimer, Qt, pyqtSignal
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QComboBox,
    QDateEdit,
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
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from ui_components import SummaryCard, card_style as _card_style
from incident_journal import IncidentJournal


class _AlertsFetchWorker(QObject):
    finished = pyqtSignal(list)
    failed = pyqtSignal(str)

    def __init__(self, api_client, limit: int):
        super().__init__()
        self.api_client = api_client
        self.limit = limit

    def run(self):
        try:
            alerts = self.api_client.get_alerts(limit=self.limit)
        except Exception as exc:
            self.failed.emit(str(exc))
            return
        self.finished.emit(list(alerts))


class AlertDetailsDialog(QDialog):
    def __init__(self, alert: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Podrobnosti alarma")
        self.resize(700, 420)

        layout = QVBoxLayout(self)

        summary_lines = [
            f"ID: {alert.get('id', 'N/A')}",
            f"Čas: {alert.get('timestamp', 'N/A')}",
            f"Tip: {alert.get('type', 'Neznano')}",
            f"Resnost: {AlertsWidget._severity_label(str(alert.get('severity', 'LOW')).upper())}",
            f"Status: {AlertsWidget._status_label(AlertsWidget._status_value(alert))}",
            f"Izvor: {alert.get('src_ip', 'N/A')}",
            f"Cilj: {alert.get('dst_ip', 'N/A')}",
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

        layout.addWidget(QLabel("Opis"))
        details = QTextEdit()
        details.setReadOnly(True)
        details.setPlainText(str(alert.get("description", "Ni podrobnosti")))
        layout.addWidget(details)

        layout.addWidget(QLabel("Surovi podatki"))
        raw = QTextEdit()
        raw.setReadOnly(True)
        raw.setPlainText(self._format_raw(alert))
        layout.addWidget(raw)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        buttons.button(QDialogButtonBox.Close).setText("Zapri")
        buttons.button(QDialogButtonBox.Close).clicked.connect(self.close)
        layout.addWidget(buttons)

    @staticmethod
    def _format_raw(alert: dict) -> str:
        return "\n".join(f"{key}: {alert.get(key)}" for key in sorted(alert.keys()))


class AlertsWidget(QWidget):
    """Prikaži in upravljaj alarme."""

    ALERT_COLUMNS = [
        "Čas",
        "Tip",
        "Resnost",
        "Status",
        "Izvor",
        "Cilj",
        "Podrobnosti",
    ]

    SEVERITY_LABELS = {
        "CRITICAL": "Kritično",
        "HIGH": "Visoko",
        "MEDIUM": "Srednje",
        "LOW": "Nizko",
        "INFO": "Informativno",
    }

    STATUS_LABELS = {
        "OPEN": "Odprto",
        "ACKNOWLEDGED": "Potrjeno",
        "RESOLVED": "Rešeno",
    }

    def __init__(self, api_client, incident_journal=None, automation_callback=None):
        super().__init__()
        self.api_client = api_client
        self.incident_journal = incident_journal or IncidentJournal()
        self.automation_callback = automation_callback
        self._active = True
        self._refresh_thread = None
        self._refresh_worker = None
        self._refresh_in_progress = False
        self._pending_alerts = deque()
        self._alert_flush_scheduled = False
        self._render_scheduled = False
        self._pending_live_render = False
        self._all_alerts = []
        self._visible_alerts = []
        self._max_alerts = 1000
        self._max_pending_alerts = 1000
        self.init_ui()
        self.refresh_alerts()

    @staticmethod
    def _severity_label(value: str) -> str:
        raw = str(value or "LOW").upper()
        return AlertsWidget.SEVERITY_LABELS.get(raw, raw.title())

    @staticmethod
    def _status_label(value: str) -> str:
        raw = str(value or "OPEN").upper()
        return AlertsWidget.STATUS_LABELS.get(raw, raw.title())

    @staticmethod
    def _status_value(alert: dict) -> str:
        value = alert.get("status", alert.get("state", "OPEN"))
        if isinstance(value, bool):
            return "RESOLVED" if value else "OPEN"
        return str(value or "OPEN").upper()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        header = QFrame()
        header.setStyleSheet(_card_style())
        header_layout = QVBoxLayout()
        header_layout.setContentsMargins(16, 14, 16, 14)
        title = QLabel("Alarmi")
        title.setFont(QFont("Segoe UI", 15, QFont.Bold))
        title.setStyleSheet("color: #172033;")
        subtitle = QLabel("Pregled trenutnih alarmov, potrjevanje, zaključevanje in pregled izbranega incidenta.")
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #94a3b8;")
        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)
        header.setLayout(header_layout)
        layout.addWidget(header)

        summary_layout = QGridLayout()
        self.total_card = SummaryCard("Vidni alarmi", "#2563eb")
        self.critical_card = SummaryCard("Kritični", "#dc2626")
        self.open_card = SummaryCard("Odprti", "#d97706")
        self.selection_card = SummaryCard("Izbrani", "#64748b")
        summary_layout.addWidget(self.total_card, 0, 0)
        summary_layout.addWidget(self.critical_card, 0, 1)
        summary_layout.addWidget(self.open_card, 0, 2)
        summary_layout.addWidget(self.selection_card, 0, 3)
        layout.addLayout(summary_layout)

        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Obdobje:"))
        self.date_from = QDateEdit()
        self.date_from.setCalendarPopup(True)
        self.date_from.setDate(QDate.currentDate().addDays(-90))
        self.date_from.dateChanged.connect(self.apply_filters)
        filter_layout.addWidget(self.date_from)

        filter_layout.addWidget(QLabel("do"))
        self.date_to = QDateEdit()
        self.date_to.setCalendarPopup(True)
        self.date_to.setDate(QDate.currentDate())
        self.date_to.dateChanged.connect(self.apply_filters)
        filter_layout.addWidget(self.date_to)

        filter_layout.addWidget(QLabel("Resnost:"))
        self.severity_combo = QComboBox()
        for label, value in [
            ("Vse", "ALL"),
            ("Kritično", "CRITICAL"),
            ("Visoko", "HIGH"),
            ("Srednje", "MEDIUM"),
            ("Nizko", "LOW"),
        ]:
            self.severity_combo.addItem(label, value)
        self.severity_combo.currentTextChanged.connect(self.apply_filters)
        filter_layout.addWidget(self.severity_combo)

        filter_layout.addWidget(QLabel("Status:"))
        self.status_combo = QComboBox()
        for label, value in [
            ("Vse", "ALL"),
            ("Odprto", "OPEN"),
            ("Potrjeno", "ACKNOWLEDGED"),
            ("Rešeno", "RESOLVED"),
        ]:
            self.status_combo.addItem(label, value)
        self.status_combo.currentTextChanged.connect(self.apply_filters)
        filter_layout.addWidget(self.status_combo)

        filter_layout.addWidget(QLabel("Iskanje:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("IP, tip, podrobnosti...")
        self.search_input.textChanged.connect(self.apply_filters)
        filter_layout.addWidget(self.search_input)

        self.refresh_btn = QPushButton("Osveži")
        self.refresh_btn.clicked.connect(self.refresh_alerts)
        filter_layout.addWidget(self.refresh_btn)
        layout.addLayout(filter_layout)

        content_layout = QHBoxLayout()

        left_layout = QVBoxLayout()
        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(len(self.ALERT_COLUMNS))
        self.alerts_table.setHorizontalHeaderLabels(self.ALERT_COLUMNS)
        self.alerts_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        self.alerts_table.setAlternatingRowColors(True)
        self.alerts_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.alerts_table.setSelectionMode(QTableWidget.MultiSelection)
        self.alerts_table.itemDoubleClicked.connect(self.show_alert_details_for_item)
        self.alerts_table.itemSelectionChanged.connect(self._update_selection_state)
        left_layout.addWidget(self.alerts_table)

        actions_layout = QHBoxLayout()
        self.ack_btn = QPushButton("Potrdi izbrane")
        self.ack_btn.clicked.connect(self.acknowledge_selected)
        actions_layout.addWidget(self.ack_btn)

        self.resolve_btn = QPushButton("Označi kot rešeno")
        self.resolve_btn.clicked.connect(self.resolve_selected)
        actions_layout.addWidget(self.resolve_btn)

        self.automation_btn = QPushButton("Pošlji v avtomatizacijo")
        self.automation_btn.clicked.connect(self.send_to_automation)
        self.automation_btn.setEnabled(self.automation_callback is not None)
        actions_layout.addWidget(self.automation_btn)

        self.journal_btn = QPushButton("Zapisnik")
        self.journal_btn.clicked.connect(self.show_journal)
        actions_layout.addWidget(self.journal_btn)

        self.details_btn = QPushButton("Podrobnosti")
        self.details_btn.clicked.connect(self.show_selected_details)
        actions_layout.addWidget(self.details_btn)

        export_btn = QPushButton("Izvozi CSV")
        export_btn.clicked.connect(self.export_alerts)
        actions_layout.addWidget(export_btn)
        actions_layout.addStretch()
        left_layout.addLayout(actions_layout)

        self.empty_state_label = QLabel("Ni alarmov za prikaz")
        self.empty_state_label.setStyleSheet("color: #64748b; padding: 4px 0;")
        self.empty_state_label.hide()
        left_layout.addWidget(self.empty_state_label)
        content_layout.addLayout(left_layout, 2)

        detail_frame = QFrame()
        detail_frame.setStyleSheet(_card_style())
        detail_layout = QVBoxLayout()
        detail_layout.setContentsMargins(16, 14, 16, 14)
        detail_title = QLabel("Izbrani alarm")
        detail_title.setFont(QFont("Segoe UI", 11, QFont.Bold))
        detail_title.setStyleSheet("color: #172033;")
        self.selection_summary_label = QLabel("")
        self.selection_summary_label.setWordWrap(True)
        self.selection_summary_label.setStyleSheet("color: #475569;")
        self.selection_details = QTextEdit()
        self.selection_details.setReadOnly(True)
        self.selection_details.setText("Noben alarm ni izbran.")
        detail_layout.addWidget(detail_title)
        detail_layout.addWidget(self.selection_summary_label)
        detail_layout.addWidget(self.selection_details, 1)
        detail_frame.setLayout(detail_layout)
        content_layout.addWidget(detail_frame, 1)
        layout.addLayout(content_layout)

        self.setLayout(layout)
        self._update_summary([])
        self._update_selection_state()

    def add_alert(self, alert: dict):
        try:
            self._pending_alerts.append(alert)
        except Exception:
            return
        while len(self._pending_alerts) > self._max_pending_alerts:
            try:
                self._pending_alerts.popleft()
            except Exception:
                break
        if not self._alert_flush_scheduled:
            self._alert_flush_scheduled = True
            QTimer.singleShot(100, self._flush_alerts)

    def _flush_alerts(self):
        self._alert_flush_scheduled = False
        updated = False
        for _ in range(min(50, len(self._pending_alerts))):
            try:
                alert = self._pending_alerts.popleft()
            except IndexError:
                break
            self._all_alerts.insert(0, alert)
            updated = True
        if len(self._all_alerts) > self._max_alerts:
            self._all_alerts = self._all_alerts[:self._max_alerts]

        if updated:
            self._pending_live_render = True
            self._schedule_render()
        if self._pending_alerts:
            self._alert_flush_scheduled = True
            QTimer.singleShot(200 if self._active else 500, self._flush_alerts)

    def refresh_alerts(self):
        if self._refresh_in_progress:
            return
        self._refresh_in_progress = True
        self.refresh_btn.setEnabled(False)
        self._refresh_thread = QThread()
        try:
            from thread_registry import register
            register(self._refresh_thread)
        except Exception:
            pass
        self._refresh_worker = _AlertsFetchWorker(self.api_client, 500)
        self._refresh_worker.moveToThread(self._refresh_thread)
        self._refresh_thread.started.connect(self._refresh_worker.run)
        self._refresh_worker.finished.connect(self._on_alerts_ready)
        self._refresh_worker.failed.connect(self._on_alerts_failed)
        self._refresh_worker.finished.connect(self._refresh_thread.quit)
        self._refresh_worker.failed.connect(self._refresh_thread.quit)
        self._refresh_worker.finished.connect(self._refresh_worker.deleteLater)
        self._refresh_worker.failed.connect(self._refresh_worker.deleteLater)
        self._refresh_thread.finished.connect(self._cleanup_refresh_thread)
        self._refresh_thread.finished.connect(self._refresh_thread.deleteLater)
        self._refresh_thread.start()

    def _on_alerts_ready(self, alerts: list):
        self._all_alerts = list(alerts)
        if len(self._all_alerts) > self._max_alerts:
            self._all_alerts = self._all_alerts[:self._max_alerts]
        self.apply_filters()

    def _on_alerts_failed(self, _message: str):
        self._all_alerts = []
        self.apply_filters()

    def _cleanup_refresh_thread(self):
        self._refresh_thread = None
        self._refresh_worker = None
        self._refresh_in_progress = False
        self.refresh_btn.setEnabled(True)

    def apply_filters(self):
        severity_filter = self.severity_combo.currentData() or self.severity_combo.currentText().strip().upper()
        status_filter = self.status_combo.currentData() or self.status_combo.currentText().strip().upper()
        query = self.search_input.text().strip().lower()
        from_date = self.date_from.date().toPyDate()
        to_date = self.date_to.date().toPyDate()

        filtered = []
        for alert in self._all_alerts:
            severity = str(alert.get("severity", "LOW")).upper()
            status = self._status_value(alert)
            if severity_filter != "ALL" and severity != severity_filter:
                continue
            if status_filter != "ALL" and status != status_filter:
                continue

            alert_dt = self._parse_alert_datetime(alert.get("timestamp"))
            if alert_dt is not None:
                alert_date = alert_dt.date()
                if alert_date < from_date or alert_date > to_date:
                    continue

            if query:
                haystack = " ".join(
                    [
                        str(alert.get("id", "")),
                        str(alert.get("type", "")),
                        str(alert.get("severity", "")),
                        str(alert.get("status", "")),
                        str(alert.get("src_ip", "")),
                        str(alert.get("dst_ip", "")),
                        str(alert.get("description", "")),
                    ]
                ).lower()
                if query not in haystack:
                    continue
            filtered.append(alert)

        self._render_alerts(filtered)

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
        if self._active and (self._pending_live_render or self._pending_alerts):
            if self._pending_alerts and not self._alert_flush_scheduled:
                self._alert_flush_scheduled = True
                QTimer.singleShot(0, self._flush_alerts)
            else:
                self._schedule_render()

    def _render_alerts(self, alerts):
        selected_ids = {
            str(item.data(Qt.UserRole))
            for item in self.alerts_table.selectionModel().selectedRows()
            if item is not None
            and self.alerts_table.item(item.row(), 0) is not None
            and self.alerts_table.item(item.row(), 0).data(Qt.UserRole)
        }
        self._visible_alerts = [dict(alert) for alert in alerts]
        self.alerts_table.setUpdatesEnabled(False)
        with QSignalBlocker(self.alerts_table):
            self.alerts_table.clearSelection()
            self.alerts_table.setRowCount(len(alerts))
            for row, alert in enumerate(alerts):
                self._populate_alert_row(row, alert)

            if selected_ids:
                for row, alert in enumerate(alerts):
                    if str(alert.get("id", "")) in selected_ids:
                        self.alerts_table.selectRow(row)
        self.alerts_table.setUpdatesEnabled(True)
        self.empty_state_label.setText(
            "Noben alarm ne ustreza trenutnim filtrom" if self._all_alerts and not alerts else "Alarmi še niso na voljo"
        )
        self.empty_state_label.setVisible(len(alerts) == 0)
        self._update_summary(alerts)
        self._update_selection_state()

    def acknowledge_selected(self):
        self._apply_alert_action("acknowledge", "ACKNOWLEDGED", "potrditev")

    def resolve_selected(self):
        self._apply_alert_action("resolve", "RESOLVED", "zaključek")

    def show_journal(self):
        entries = self.incident_journal.list_entries(100)
        if not entries:
            text = "Zapisnik je prazen."
        else:
            lines = []
            for entry in entries:
                incident = entry.get("incident", {})
                lines.append(
                    f"{entry.get('recorded_at', 'N/A')} | "
                    f"{entry.get('event', 'N/A')} | "
                    f"{incident.get('id', 'N/A')}\n"
                    f"{entry.get('details', '')}"
                )
            text = "\n\n".join(lines)
        dialog = QDialog(self)
        dialog.setWindowTitle("Incidentni zapisnik")
        dialog.resize(760, 500)
        layout = QVBoxLayout(dialog)
        output = QTextEdit()
        output.setReadOnly(True)
        output.setPlainText(text)
        layout.addWidget(output)
        close_button = QDialogButtonBox(QDialogButtonBox.Close)
        close_button.rejected.connect(dialog.reject)
        close_button.accepted.connect(dialog.accept)
        close_button.button(QDialogButtonBox.Close).setText("Zapri")
        layout.addWidget(close_button)
        dialog.exec_()

    def send_to_automation(self):
        selected_rows = self.alerts_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "Ni izbire", "Izberi alarm za avtomatizacijo.")
            return
        if self.automation_callback is None:
            QMessageBox.warning(self, "Avtomatizacija ni na voljo", "Odzivni modul še ni pripravljen.")
            return
        alert = self._alert_for_row(selected_rows[0].row())
        if not alert:
            QMessageBox.warning(self, "Napaka", "Podatki izbranega alarma niso na voljo.")
            return
        try:
            result = self.automation_callback(dict(alert))
        except Exception as exc:
            QMessageBox.critical(self, "Napaka avtomatizacije", str(exc))
            return
        if not isinstance(result, dict) or not result.get("ok"):
            message = result.get("message", "Odziv ni bil uspešen.") if isinstance(result, dict) else "Odziv ni bil uspešen."
            QMessageBox.warning(self, "Avtomatizacija", message)
            return

        target_status = str(result.get("status", "ACKNOWLEDGED")).upper()
        alert_id = str(alert.get("id", ""))
        status_saved = (
            self.api_client.resolve_alert(alert_id)
            if target_status == "RESOLVED"
            else self.api_client.acknowledge_alert(alert_id)
        )
        if not status_saved:
            QMessageBox.warning(self, "Avtomatizacija", "Odziv je bil izveden, status alarma pa ni bil shranjen.")
            return
        for item in self._all_alerts:
            if str(item.get("id", "")) == alert_id:
                item["status"] = target_status
                self.incident_journal.record(item, "AUTOMATION", str(result.get("message", "")))
                break
        self.apply_filters()
        QMessageBox.information(
            self,
            "Avtomatizacija zaključena",
            f"{result.get('message', 'Odziv je bil izveden.')}\nStatus alarma: {self._status_label(target_status)}",
        )

    def _apply_alert_action(self, action: str, target_status: str, action_label: str):
        selected_rows = self.alerts_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "Ni izbire", f"Izberi alarme za {action_label}.")
            return

        succeeded = 0
        failed = 0
        for model_row in selected_rows:
            row = model_row.row()
            time_item = self.alerts_table.item(row, 0)
            status_item = self.alerts_table.item(row, 3)
            if time_item is None or status_item is None:
                failed += 1
                continue

            alert_id = str(time_item.data(Qt.UserRole) or "")
            if not alert_id:
                failed += 1
                continue

            ok = self.api_client.acknowledge_alert(alert_id) if action == "acknowledge" else self.api_client.resolve_alert(alert_id)
            if not ok:
                failed += 1
                continue

            for alert in self._all_alerts:
                if str(alert.get("id", "")) == alert_id:
                    alert["status"] = target_status
                    self.incident_journal.record(
                        alert,
                        target_status,
                        f"Alarm je bil ročno označen kot {self._status_label(target_status).lower()}.",
                    )
                    break
            status_item.setText(self._status_label(target_status))
            status_item.setForeground(self._status_color(target_status))
            succeeded += 1

        if succeeded:
            self.apply_filters()

        if succeeded and not failed:
            QMessageBox.information(self, "Uspeh", f"Uspešno posodobljenih alarmov: {succeeded}")
        elif succeeded:
            QMessageBox.warning(self, "Delni uspeh", f"Posodobljenih alarmov: {succeeded}, neuspešnih: {failed}")
        else:
            QMessageBox.warning(self, "Napaka", "Izbranih alarmov ni bilo mogoče posodobiti.")

    def show_selected_details(self):
        selected_rows = self.alerts_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "Ni izbire", "Najprej izberi alarm.")
            return
        self._show_alert_details_for_row(selected_rows[0].row())

    def show_alert_details_for_item(self, item):
        if item is None:
            return
        self._show_alert_details_for_row(item.row())

    def _show_alert_details_for_row(self, row: int):
        alert = self._alert_for_row(row)
        if not isinstance(alert, dict):
            return
        dialog = AlertDetailsDialog(alert, self)
        dialog.exec_()

    def export_alerts(self):
        filename = f"alarmi_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filepath = Path.home() / "Downloads" / filename
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(self.ALERT_COLUMNS)
            for alert in self._visible_alerts:
                writer.writerow(
                    [
                        self._format_timestamp(alert.get("timestamp", "N/A")),
                        alert.get("type", "Neznano"),
                        self._severity_label(str(alert.get("severity", "LOW")).upper()),
                        self._status_label(self._status_value(alert)),
                        alert.get("src_ip", "N/A"),
                        alert.get("dst_ip", "N/A"),
                        alert.get("description", "Ni podrobnosti"),
                    ]
                )
        QMessageBox.information(self, "Izvoz uspešen", f"Izvoženih alarmov: {len(self._visible_alerts)}\n{filepath}")

    def _populate_alert_row(self, row: int, alert: dict):
        time_item = QTableWidgetItem(self._format_timestamp(alert.get("timestamp", "N/A")))
        time_item.setData(Qt.UserRole, str(alert.get("id", "")))
        time_item.setData(Qt.UserRole + 1, dict(alert))
        self.alerts_table.setItem(row, 0, time_item)

        self.alerts_table.setItem(row, 1, QTableWidgetItem(alert.get("type", "Neznano")))

        severity = str(alert.get("severity", "LOW")).upper()
        severity_item = QTableWidgetItem(self._severity_label(severity))
        severity_item.setForeground(self._severity_color(severity))
        severity_item.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.alerts_table.setItem(row, 2, severity_item)

        status = self._status_value(alert)
        status_item = QTableWidgetItem(self._status_label(status))
        status_item.setForeground(self._status_color(status))
        status_item.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.alerts_table.setItem(row, 3, status_item)

        self.alerts_table.setItem(row, 4, QTableWidgetItem(alert.get("src_ip", "N/A")))
        self.alerts_table.setItem(row, 5, QTableWidgetItem(alert.get("dst_ip", "N/A")))
        self.alerts_table.setItem(row, 6, QTableWidgetItem(alert.get("description", "Ni podrobnosti")))

    def _update_summary(self, alerts):
        total = len(alerts)
        critical = sum(1 for alert in alerts if str(alert.get("severity", "LOW")).upper() == "CRITICAL")
        open_count = sum(1 for alert in alerts if self._status_value(alert) == "OPEN")
        self.total_card.set_value(str(total), "")
        self.critical_card.set_value(str(critical), "", "#dc2626" if critical else "#94a3b8")
        self.open_card.set_value(str(open_count), "", "#d97706" if open_count else "#16a34a")

    def _update_selection_state(self):
        selection_model = self.alerts_table.selectionModel()
        selected_rows = selection_model.selectedRows() if selection_model else []
        selected_count = len(selected_rows)
        self.selection_card.set_value(str(selected_count), "")
        self.ack_btn.setEnabled(selected_count > 0)
        self.resolve_btn.setEnabled(selected_count > 0)
        self.automation_btn.setEnabled(selected_count > 0 and self.automation_callback is not None)
        self.details_btn.setEnabled(selected_count > 0)

        if selected_count == 0:
            self.selection_summary_label.setText("")
            self.selection_details.setText("Noben alarm ni izbran.")
            return

        alert = self._alert_for_row(selected_rows[0].row())
        if not alert:
            self.selection_summary_label.setText("Podrobnosti izbranega alarma niso na voljo.")
            self.selection_details.setText("Noben alarm ni izbran.")
            return

        severity = str(alert.get("severity", "LOW")).upper()
        status = self._status_value(alert)
        self.selection_summary_label.setText(
            f"{alert.get('type', 'Alarm')} | {self._severity_label(severity)} | {self._status_label(status)} | {alert.get('src_ip', 'N/A')} -> {alert.get('dst_ip', 'N/A')}"
        )
        self.selection_details.setText(
            "\n".join(
                [
                    f"ID: {alert.get('id', 'N/A')}",
                    f"Čas: {alert.get('timestamp', 'N/A')}",
                    f"Tip: {alert.get('type', 'Neznano')}",
                    f"Resnost: {self._severity_label(severity)}",
                    f"Status: {self._status_label(status)}",
                    f"Izvor: {alert.get('src_ip', 'N/A')}",
                    f"Cilj: {alert.get('dst_ip', 'N/A')}",
                    "",
                    "Opis:",
                    str(alert.get("description", "Ni podrobnosti")),
                ]
            )
        )

    def _alert_for_row(self, row: int):
        if row < 0:
            return None
        item = self.alerts_table.item(row, 0)
        if item is not None:
            alert = item.data(Qt.UserRole + 1)
            if isinstance(alert, dict):
                return dict(alert)
        if row < len(self._visible_alerts):
            return dict(self._visible_alerts[row])
        return None

    @staticmethod
    def _parse_alert_datetime(value):
        if isinstance(value, datetime):
            return value
        if value is None:
            return None
        raw = str(value)
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(raw)
        except Exception:
            return None

    @staticmethod
    def _severity_color(severity: str) -> QColor:
        return {
            "CRITICAL": QColor("#dc2626"),
            "HIGH": QColor("#b45309"),
            "MEDIUM": QColor("#d97706"),
            "LOW": QColor("#16a34a"),
        }.get(severity, QColor("#aaaaaa"))

    @staticmethod
    def _status_color(status: str) -> QColor:
        return {
            "OPEN": QColor("#dc2626"),
            "ACKNOWLEDGED": QColor("#d97706"),
            "RESOLVED": QColor("#16a34a"),
        }.get(status, QColor("#aaaaaa"))

    @staticmethod
    def _format_timestamp(value) -> str:
        if isinstance(value, datetime):
            return value.isoformat(sep=" ", timespec="seconds")
        return str(value)
