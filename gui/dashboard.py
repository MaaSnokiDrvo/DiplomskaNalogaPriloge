"""
Gradnik glavne nadzorne plošče - glavni pregled meritev sistema IDS.
"""

from collections import deque
from datetime import datetime

import pyqtgraph as pg
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QFrame, QGridLayout, QHBoxLayout, QLabel, QVBoxLayout, QWidget
from ui_components import card_style as _card_style


TEXT_COLOR = "#111827"


class MetricCard(QFrame):
    """Prikaži posamezno ključno metriko."""

    def __init__(self, title: str, value: str = "0", subtitle: str = "", accent: str = "#38bdf8"):
        super().__init__()
        self._accent = accent
        self.setStyleSheet(_card_style())

        layout = QVBoxLayout()
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(4)

        self.title_label = QLabel(title)
        self.title_label.setFont(QFont("Segoe UI", 9, QFont.Bold))
        self.title_label.setStyleSheet(f"color: {TEXT_COLOR};")

        self.value_label = QLabel(value)
        self.value_label.setFont(QFont("Segoe UI", 22, QFont.Bold))
        self.value_label.setStyleSheet(f"color: {TEXT_COLOR};")

        self.subtitle_label = QLabel(subtitle)
        self.subtitle_label.setFont(QFont("Segoe UI", 9))
        self.subtitle_label.setStyleSheet(f"color: {TEXT_COLOR};")

        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)
        layout.addWidget(self.subtitle_label)
        layout.addStretch()
        self.setLayout(layout)

    def set_value(self, value: str, subtitle: str = None, color: str = None):
        self.value_label.setText(value)
        self.value_label.setStyleSheet(f"color: {color or TEXT_COLOR};")
        if subtitle is not None:
            self.subtitle_label.setText(subtitle)


class StatusCard(QFrame):
    """Zgoščen kazalnik stanja izvajanja."""

    def __init__(self, title: str, value: str, accent: str):
        super().__init__()
        self._accent = accent
        self.setStyleSheet(_card_style())

        layout = QVBoxLayout()
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(2)

        title_label = QLabel(title)
        title_label.setFont(QFont("Segoe UI", 8, QFont.Bold))
        title_label.setStyleSheet(f"color: {TEXT_COLOR}; text-transform: uppercase;")

        self.value_label = QLabel(value)
        self.value_label.setFont(QFont("Segoe UI", 11, QFont.Bold))
        self.value_label.setStyleSheet(f"color: {TEXT_COLOR};")

        layout.addWidget(title_label)
        layout.addWidget(self.value_label)
        self.setLayout(layout)

    def set_value(self, value: str, accent: str = None):
        self.value_label.setText(value)
        self.value_label.setStyleSheet(f"color: {accent or TEXT_COLOR};")


class DashboardWidget(QWidget):
    """Glavna nadzorna plošča z metrikami v realnem času in stanjem delovanja."""

    def __init__(self, api_client):
        super().__init__()
        self.api_client = api_client
        self.packet_history = deque(maxlen=60)
        self.alert_history = deque(maxlen=60)
        self.anomaly_history = deque(maxlen=60)
        self.refresh_history = deque(maxlen=60)
        self._connected = False
        self._simulator_enabled = None
        self._last_runtime_refresh = None
        self._queue_depths = {"flows": 0, "alerts": 0, "metrics": 0}
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(14)

        hero_row = QHBoxLayout()
        title_layout = QVBoxLayout()
        title_layout.setSpacing(2)

        title = QLabel("Operativni pregled")
        title.setFont(QFont("Segoe UI", 18, QFont.Bold))
        title.setStyleSheet(f"color: {TEXT_COLOR};")

        subtitle = QLabel("Živo stanje trenutne zaledne seje, prometa in alarmov")
        subtitle.setFont(QFont("Segoe UI", 10))
        subtitle.setStyleSheet(f"color: {TEXT_COLOR};")

        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        hero_row.addLayout(title_layout)
        hero_row.addStretch()

        self.last_refresh_label = QLabel("")
        self.last_refresh_label.setFont(QFont("Segoe UI", 9, QFont.Bold))
        self.last_refresh_label.setStyleSheet(f"color: {TEXT_COLOR};")
        hero_row.addWidget(self.last_refresh_label)

        main_layout.addLayout(hero_row)

        status_row = QHBoxLayout()
        status_row.setSpacing(10)
        self.backend_card = StatusCard("Zaledje", "Brez povezave", "#b91c1c")
        self.simulator_card = StatusCard("Simulator", "Neznano", "#94a3b8")
        self.queue_card = StatusCard("Vrste", "tokovi 0 | alarmi 0", "#2563eb")
        self.mode_card = StatusCard("Stanje", "Čakam podatke", "#64748b")
        status_row.addWidget(self.backend_card)
        status_row.addWidget(self.simulator_card)
        status_row.addWidget(self.queue_card)
        status_row.addWidget(self.mode_card)
        main_layout.addLayout(status_row)

        metrics_layout = QGridLayout()
        metrics_layout.setHorizontalSpacing(12)
        metrics_layout.setVerticalSpacing(12)
        self.metric_packets = MetricCard("Paketi", "0", "Ni prometa", "#16a34a")
        self.metric_flows = MetricCard("Tokovi", "0", "", "#2563eb")
        self.metric_alerts = MetricCard("Alarmi", "0", "", "#d97706")
        self.metric_anomalies = MetricCard("Anomalije", "0", "", "#64748b")
        metrics_layout.addWidget(self.metric_packets, 0, 0)
        metrics_layout.addWidget(self.metric_flows, 0, 1)
        metrics_layout.addWidget(self.metric_alerts, 0, 2)
        metrics_layout.addWidget(self.metric_anomalies, 0, 3)
        main_layout.addLayout(metrics_layout)

        charts_layout = QHBoxLayout()
        charts_layout.setSpacing(12)

        self.packet_rate_plot = self._build_plot(
            "Aktivnost paketov",
            "Število paketov",
            "Zaporedna meritev",
        )
        self.packet_rate_curve = self.packet_rate_plot.plot(pen=pg.mkPen("#111827", width=2))

        self.alert_timeline_plot = self._build_plot(
            "Alarmi in anomalije",
            "Število dogodkov",
            "Zaporedna meritev",
        )
        self.alert_curve = self.alert_timeline_plot.plot(pen=pg.mkPen("#111827", width=2), name="Alarmi")
        self.anomaly_curve = self.alert_timeline_plot.plot(
            pen=pg.mkPen("#6b7280", width=2, style=Qt.DashLine),
            name="Anomalije",
        )
        self.alert_timeline_plot.addLegend(offset=(10, 10))

        charts_layout.addWidget(self.packet_rate_plot)
        charts_layout.addWidget(self.alert_timeline_plot)
        main_layout.addLayout(charts_layout, 1)

        self.setLayout(main_layout)

    def _build_plot(self, title: str, left_label: str, bottom_label: str):
        plot = pg.PlotWidget()
        plot.setTitle(title, color=TEXT_COLOR)
        plot.setLabel("left", left_label, color=TEXT_COLOR)
        plot.setLabel("bottom", bottom_label, color=TEXT_COLOR)
        plot.setBackground("#ffffff")
        plot.setStyleSheet("background-color: #ffffff;")
        plot.getPlotItem().getViewBox().setBackgroundColor("#ffffff")
        for axis_name in ("left", "bottom"):
            axis = plot.getAxis(axis_name)
            axis.setTextPen(TEXT_COLOR)
            axis.setPen(pg.mkPen(TEXT_COLOR, width=1))
        plot.showGrid(x=True, y=True, alpha=0.25)
        return plot

    def update_runtime_state(self, connected: bool, simulator_enabled=None, queue_depths=None, last_refresh=None):
        self._connected = bool(connected)
        self._simulator_enabled = simulator_enabled
        if isinstance(queue_depths, dict):
            self._queue_depths = {
                "flows": int(queue_depths.get("flows", 0)),
                "alerts": int(queue_depths.get("alerts", 0)),
                "metrics": int(queue_depths.get("metrics", 0)),
            }
        if last_refresh:
            self._last_runtime_refresh = last_refresh
            self.last_refresh_label.clear()

        if self._connected:
            self.backend_card.set_value("Povezan", "#16a34a")
        else:
            self.backend_card.set_value("Brez povezave", "#f87171")

        if simulator_enabled is True:
            self.simulator_card.set_value("Vključen", "#fbbf24")
        elif simulator_enabled is False:
            self.simulator_card.set_value("Izključen", "#2563eb")
        else:
            self.simulator_card.set_value("Neznano", "#94a3b8")

        self.queue_card.set_value(
            f"tokovi {self._queue_depths['flows']} | alarmi {self._queue_depths['alerts']}",
            "#2563eb",
        )

        if not self._connected:
            self.mode_card.set_value("Preveri zaledje", "#f87171")
        elif self._queue_depths["alerts"] > 10:
            self.mode_card.set_value("Povišan pritisk", "#d97706")
        elif simulator_enabled:
            self.mode_card.set_value("Simulator aktiven", "#fbbf24")
        else:
            self.mode_card.set_value("Normalno", "#16a34a")

    def update_metrics(self, status: dict):
        packets = int(status.get("packets", 0) or 0)
        flows = int(status.get("flows", 0) or 0)
        alerts = int(status.get("alerts", 0) or 0)
        anomalies = int(status.get("anomalies", 0) or 0)

        self.packet_history.append(packets)
        self.alert_history.append(alerts)
        self.anomaly_history.append(anomalies)
        self.refresh_history.append(datetime.now())

        self.metric_packets.set_value(f"{packets:,}", "")
        self.metric_flows.set_value(f"{flows:,}", "")

        alert_subtitle = ""
        alert_color = "#16a34a"
        if alerts > 10:
            alert_color = "#dc2626"
        elif alerts > 0:
            alert_color = "#d97706"
        self.metric_alerts.set_value(str(alerts), alert_subtitle, alert_color)

        anomaly_subtitle = ""
        anomaly_color = "#16a34a"
        if anomalies > 5:
            anomaly_color = "#64748b"
        self.metric_anomalies.set_value(str(anomalies), anomaly_subtitle, anomaly_color)

        self._update_plots()

    def _update_plots(self):
        x_axis = list(range(len(self.packet_history)))
        self.packet_rate_curve.setData(x_axis, list(self.packet_history))
        self.alert_curve.setData(x_axis, list(self.alert_history))
        self.anomaly_curve.setData(x_axis, list(self.anomaly_history))
