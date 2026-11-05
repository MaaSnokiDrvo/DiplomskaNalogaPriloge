"""
Gradnik nastavitev - konfiguracija sistema IDS.
"""

import os

from PyQt5.QtCore import QObject, QThread, pyqtSignal
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)
from ui_components import card_style as _panel_style


class _ConfigLoadWorker(QObject):
    finished = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, api_client):
        super().__init__()
        self.api_client = api_client

    def run(self):
        try:
            try:
                connected = self.api_client.is_connected()
            except Exception:
                connected = False

            if not connected:
                self.finished.emit(None)
                return

            cfg = self.api_client.get_config()
            self.finished.emit(cfg)
        except Exception as exc:
            self.failed.emit(str(exc))


class _ConfigSaveWorker(QObject):
    finished = pyqtSignal(bool, str)

    def __init__(self, api_client, config):
        super().__init__()
        self.api_client = api_client
        self.config = dict(config)

    def run(self):
        try:
            connected = self.api_client.is_connected()
        except Exception:
            connected = False

        if not connected:
            self.finished.emit(False, "backend ni dosegljiv; lokalne nastavitve so shranjene")
            return

        try:
            ok = self.api_client.update_config(self.config)
        except Exception as exc:
            self.finished.emit(False, f"uveljavitev ni uspela: {exc}")
            return

        if ok:
            self.finished.emit(True, "nastavitve shranjene; vmesnik velja po ponovnem zagonu")
        else:
            self.finished.emit(False, "backend je zavrnil nastavitve")


class ConfigWidget(QWidget):
    """Nastavi sistemske nastavitve IDS."""

    def __init__(self, api_client):
        super().__init__()
        self.api_client = api_client
        self._silent_load = True
        self._config_thread = None
        self._config_worker = None
        self._save_thread = None
        self._save_worker = None
        self.init_ui()
        self._start_config_load()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        header = QFrame()
        header.setStyleSheet(_panel_style())
        header_layout = QVBoxLayout()
        header_layout.setContentsMargins(16, 14, 16, 14)
        title = QLabel("Nastavitve")
        title.setFont(QFont("Segoe UI", 15, QFont.Bold))
        title.setStyleSheet("color: #172033;")
        subtitle = QLabel("Simulator se lahko uveljavi v živo; ostalo velja ob naslednjem zagonu.")
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #64748b;")
        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)
        header.setLayout(header_layout)
        layout.addWidget(header)

        tabs = QTabWidget()
        tabs.addTab(self.create_general_tab(), "Splošno")
        # Nastavitve zaznavanja ohranimo, vendar jih ne prikazujemo, ker niso povezane z aktivnim tokom.
        self._hidden_detection_tab = self.create_detection_tab()
        self._hidden_detection_tab.setParent(self)
        tabs.addTab(self.create_network_tab(), "Omrežje")
        layout.addWidget(tabs)

        buttons_layout = QHBoxLayout()
        self.save_btn = QPushButton("Shrani za zagon")
        self.save_btn.clicked.connect(self.save_config)
        buttons_layout.addWidget(self.save_btn)

        self.apply_runtime_btn = QPushButton("Uveljavi simulator")
        self.apply_runtime_btn.clicked.connect(self.apply_runtime_config)
        buttons_layout.addWidget(self.apply_runtime_btn)

        self.reset_btn = QPushButton("Ponovno naloži")
        self.reset_btn.clicked.connect(self.load_config)
        buttons_layout.addWidget(self.reset_btn)

        buttons_layout.addStretch()
        layout.addLayout(buttons_layout)

        self.setLayout(layout)

    def _build_card(self, title: str, subtitle: str) -> QFrame:
        frame = QFrame()
        frame.setStyleSheet(_panel_style())
        frame_layout = QVBoxLayout()
        frame_layout.setContentsMargins(14, 12, 14, 12)
        title_label = QLabel(title)
        title_label.setFont(QFont("Segoe UI", 11, QFont.Bold))
        title_label.setStyleSheet("color: #172033;")
        subtitle_label = QLabel(subtitle)
        subtitle_label.setWordWrap(True)
        subtitle_label.setStyleSheet("color: #64748b;")
        frame_layout.addWidget(title_label)
        frame_layout.addWidget(subtitle_label)
        frame.setLayout(frame_layout)
        return frame

    def create_general_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(12)

        name_group = QGroupBox("Identiteta")
        name_layout = QHBoxLayout()
        name_layout.addWidget(QLabel("Ime:"))
        self.name_input = QLineEdit()
        self.name_input.setText("NetSentinel-01")
        name_layout.addWidget(self.name_input)
        name_group.setLayout(name_layout)
        layout.addWidget(name_group)

        interface_group = QGroupBox("Omrežni vmesnik")
        interface_layout = QHBoxLayout()
        interface_layout.addWidget(QLabel("Vmesnik:"))
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(["Samodejno", "eth0", "eth1", "wlan0"])
        interface_layout.addWidget(self.interface_combo)
        interface_group.setLayout(interface_layout)
        layout.addWidget(interface_group)

        simulation_group = QGroupBox("Simulator napadov")
        simulation_layout = QVBoxLayout()

        runtime_badge = QLabel("Vir v živo: zaledni API")
        runtime_badge.setStyleSheet("color: #2563eb; font-weight: bold;")
        simulation_layout.addWidget(runtime_badge)

        self.simulate_checkbox = QCheckBox("Vključi simulator")
        simulation_layout.addWidget(self.simulate_checkbox)

        interval_layout = QHBoxLayout()
        interval_layout.addWidget(QLabel("Interval (ms):"))
        self.simulate_interval_spinbox = QSpinBox()
        self.simulate_interval_spinbox.setMinimum(250)
        self.simulate_interval_spinbox.setMaximum(60000)
        self.simulate_interval_spinbox.setSingleStep(250)
        self.simulate_interval_spinbox.setValue(1500)
        interval_layout.addWidget(self.simulate_interval_spinbox)
        simulation_layout.addLayout(interval_layout)

        self.runtime_status_label = QLabel("Simulator: čakam sinhronizacijo")
        simulation_layout.addWidget(self.runtime_status_label)

        simulation_group.setLayout(simulation_layout)
        layout.addWidget(simulation_group)

        self.simulate_checkbox.toggled.connect(self._mark_runtime_pending)
        self.simulate_interval_spinbox.valueChanged.connect(self._mark_runtime_pending)

        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def create_detection_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout()

        threshold_group = QGroupBox("Anomalije")
        threshold_layout = QVBoxLayout()
        threshold_layout.addWidget(QLabel("Prag ocene (0.0 - 1.0):"))
        self.threshold_spinbox = QDoubleSpinBox()
        self.threshold_spinbox.setMinimum(0.0)
        self.threshold_spinbox.setMaximum(1.0)
        self.threshold_spinbox.setSingleStep(0.05)
        self.threshold_spinbox.setValue(0.5)
        threshold_layout.addWidget(self.threshold_spinbox)
        threshold_group.setLayout(threshold_layout)
        layout.addWidget(threshold_group)

        methods_group = QGroupBox("Metode")
        methods_layout = QVBoxLayout()

        self.ml_checkbox = QCheckBox("Dodatna analitika")
        methods_layout.addWidget(self.ml_checkbox)

        self.statistical_checkbox = QCheckBox("Statistična analiza")
        self.statistical_checkbox.setChecked(True)
        methods_layout.addWidget(self.statistical_checkbox)

        device_layout = QHBoxLayout()
        device_layout.addWidget(QLabel("Naprava obdelave:"))
        self.device_combo = QComboBox()
        self.device_combo.addItems(["Samodejno", "CPU", "GPU", "CPU + GPU"])
        device_layout.addWidget(self.device_combo)
        methods_layout.addLayout(device_layout)

        methods_group.setLayout(methods_layout)
        layout.addWidget(methods_group)

        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def create_network_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout()

        api_group = QGroupBox("REST API")
        api_layout = QVBoxLayout()
        api_layout.addWidget(QLabel("Vrata:"))
        self.api_port_spinbox = QSpinBox()
        self.api_port_spinbox.setMinimum(1024)
        self.api_port_spinbox.setMaximum(65535)
        self.api_port_spinbox.setValue(8080)
        api_layout.addWidget(self.api_port_spinbox)
        api_group.setLayout(api_layout)
        layout.addWidget(api_group)

        pg_group = QGroupBox("PostgreSQL")
        pg_layout = QVBoxLayout()
        self.pg_checkbox = QCheckBox("Vključi arhiviranje")
        pg_layout.addWidget(self.pg_checkbox)
        pg_layout.addWidget(QLabel("Povezava:"))
        self.pg_connstr = QLineEdit()
        self.pg_connstr.setText("postgresql://netsentinel_user:admin@localhost:5432/netsentinel_db")
        pg_layout.addWidget(self.pg_connstr)
        pg_group.setLayout(pg_layout)
        layout.addWidget(pg_group)

        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def load_config(self):
        self._start_config_load()

    def _start_config_load(self):
        if self._config_thread is not None:
            return
        self._config_thread = QThread()
        try:
            from thread_registry import register
            register(self._config_thread)
        except Exception:
            pass
        self._config_worker = _ConfigLoadWorker(self.api_client)
        self._config_worker.moveToThread(self._config_thread)
        self._config_thread.started.connect(self._config_worker.run)
        self._config_worker.finished.connect(self._on_config_loaded)
        self._config_worker.failed.connect(self._on_config_failed)
        self._config_worker.finished.connect(self._config_thread.quit)
        self._config_worker.finished.connect(self._config_worker.deleteLater)
        self._config_thread.finished.connect(self._config_thread.deleteLater)
        self._config_thread.start()

    def _on_config_loaded(self, config: dict):
        try:
            self._load_simulation_setting(config)
            self._load_device_setting()
            self._load_startup_defaults()
            if config:
                self._set_runtime_status("Simulator: sinhroniziran z backendom", "#166534")
                self.name_input.setText(config.get("name", "NetSentinel-01"))
                self.threshold_spinbox.setValue(config.get("threshold", 0.5))
                self.api_port_spinbox.setValue(int(config.get("api_port", self.api_port_spinbox.value()) or self.api_port_spinbox.value()))
                interface_value = str(config.get("interface", self._interface_value()))
                if interface_value == "Auto-detect":
                    interface_value = "Samodejno"
                self.interface_combo.setCurrentText(interface_value)
                if not self._silent_load:
                    QMessageBox.information(self, "Uspeh", "Nastavitve so naložene")
            else:
                self._set_runtime_status("Simulator: backend ni dosegljiv", "#92400e")
                if not self._silent_load:
                    QMessageBox.warning(self, "Napaka", "Nastavitev ni bilo mogoče naložiti")
        finally:
            self._silent_load = False
            self._config_thread = None
            self._config_worker = None

    def _on_config_failed(self, message: str):
        self._set_runtime_status(f"Simulator: nalaganje ni uspelo ({message})", "#991b1b")
        if not self._silent_load:
            QMessageBox.warning(self, "Napaka", f"Nalaganje ni uspelo: {message}")
        self._silent_load = False
        self._config_thread = None
        self._config_worker = None

    def save_config(self):
        config = self._build_runtime_config()
        self._save_simulation_setting()
        self._save_device_setting()
        self._set_runtime_status("Simulator: shranjujem in uveljavljam...", "#1d4ed8")
        self._set_save_controls_enabled(False)
        self._start_save_worker(config)

    def apply_runtime_config(self):
        config = self._build_runtime_config()
        self._save_simulation_setting()
        self._save_device_setting()
        self._set_runtime_status("Simulator: uveljavljam...", "#1d4ed8")
        self._set_save_controls_enabled(False)
        self._start_save_worker(config)

    def _build_runtime_config(self) -> dict:
        return {
            "name": self.name_input.text(),
            "interface": self._interface_value(),
            "threshold": self.threshold_spinbox.value(),
            "api_port": self.api_port_spinbox.value(),
            "postgres_enabled": self.pg_checkbox.isChecked(),
            "postgres_connection_string": self.pg_connstr.text(),
            "ml_enabled": self.ml_checkbox.isChecked(),
            "statistical_enabled": self.statistical_checkbox.isChecked(),
            "simulate_attacks": self.simulate_checkbox.isChecked(),
            "simulate_interval_ms": self.simulate_interval_spinbox.value(),
        }

    def _start_save_worker(self, config: dict):
        if self._save_thread is not None:
            self._set_runtime_status("Simulator: počakaj na trenutno uveljavitev", "#92400e")
            self._set_save_controls_enabled(True)
            return
        self._save_thread = QThread()
        try:
            from thread_registry import register
            register(self._save_thread)
        except Exception:
            pass
        self._save_worker = _ConfigSaveWorker(self.api_client, config)
        self._save_worker.moveToThread(self._save_thread)
        self._save_thread.started.connect(self._save_worker.run)
        self._save_worker.finished.connect(self._on_save_finished)
        self._save_worker.finished.connect(self._save_thread.quit)
        self._save_worker.finished.connect(self._save_worker.deleteLater)
        self._save_thread.finished.connect(self._save_thread.deleteLater)
        self._save_thread.start()

    def _on_save_finished(self, ok: bool, message: str):
        self._set_save_controls_enabled(True)
        if ok:
            self._set_runtime_status(f"Simulator: {message}", "#166534")
            QMessageBox.information(self, "Uspeh", message)
        else:
            self._set_runtime_status(f"Simulator: {message}", "#92400e")
            QMessageBox.warning(self, "Opozorilo", message)
        self._save_thread = None
        self._save_worker = None

    def _mark_runtime_pending(self, *_args):
        self._set_runtime_status("Simulator: spremembe čakajo na uveljavitev", "#92400e")

    def _set_runtime_status(self, text: str, color: str):
        self.runtime_status_label.setText(text)
        self.runtime_status_label.setStyleSheet(f"color: {color}; font-weight: bold;")

    def _set_save_controls_enabled(self, enabled: bool):
        for widget in (self.save_btn, self.reset_btn, self.apply_runtime_btn):
            widget.setEnabled(enabled)

    def _load_simulation_setting(self, config: dict = None):
        if config:
            if "simulate_attacks" in config:
                self.simulate_checkbox.setChecked(bool(config.get("simulate_attacks")))
            if "simulate_interval_ms" in config:
                try:
                    self.simulate_interval_spinbox.setValue(max(250, int(config.get("simulate_interval_ms", 1500))))
                except Exception:
                    self.simulate_interval_spinbox.setValue(1500)
            return
        env_path = self._get_env_path()
        settings = self._read_env_file(env_path)
        value = settings.get("NETSENTINEL_SIMULATE_ATTACKS", "1")
        self.simulate_checkbox.setChecked(str(value).strip() == "1")
        interval = settings.get("NETSENTINEL_SIMULATE_INTERVAL_MS", "1500")
        try:
            self.simulate_interval_spinbox.setValue(max(250, int(str(interval).strip())))
        except Exception:
            self.simulate_interval_spinbox.setValue(1500)

    def _save_simulation_setting(self):
        env_path = self._get_env_path()
        settings = self._read_env_file(env_path)
        settings["NETSENTINEL_SIMULATE_ATTACKS"] = "1" if self.simulate_checkbox.isChecked() else "0"
        settings["NETSENTINEL_SIMULATE_INTERVAL_MS"] = str(self.simulate_interval_spinbox.value())
        settings["REST_API_PORT"] = str(self.api_port_spinbox.value())
        settings["POSTGRES_ENABLED"] = "1" if self.pg_checkbox.isChecked() else "0"
        settings["POSTGRES_CONNECTION_STRING"] = self.pg_connstr.text().strip()
        settings["NETSENTINEL_THRESHOLD"] = str(self.threshold_spinbox.value())
        settings["NETSENTINEL_INTERFACE"] = self._interface_value()
        settings["NETSENTINEL_NAME"] = self.name_input.text().strip()
        settings["NETSENTINEL_ML_ENABLED"] = "1" if self.ml_checkbox.isChecked() else "0"
        settings["NETSENTINEL_STATISTICAL_ENABLED"] = "1" if self.statistical_checkbox.isChecked() else "0"
        self._write_env_file(env_path, settings)

    def _load_device_setting(self):
        env_path = self._get_env_path()
        settings = self._read_env_file(env_path)
        value = settings.get("IDS_DEVICE", "auto").strip().lower()
        mapping = {"auto": 0, "cpu": 1, "cuda": 2, "gpu": 2, "both": 3}
        self.device_combo.setCurrentIndex(mapping.get(value, 0))

    def _load_startup_defaults(self):
        env_path = self._get_env_path()
        settings = self._read_env_file(env_path)
        self.name_input.setText(settings.get("NETSENTINEL_NAME", self.name_input.text()))
        interface_value = settings.get("NETSENTINEL_INTERFACE", "").strip()
        if interface_value == "Auto-detect":
            interface_value = "Samodejno"
        if interface_value:
            idx = self.interface_combo.findText(interface_value)
            if idx >= 0:
                self.interface_combo.setCurrentIndex(idx)
        self.pg_checkbox.setChecked(settings.get("POSTGRES_ENABLED", "0").strip() == "1")
        self.pg_connstr.setText(settings.get("POSTGRES_CONNECTION_STRING", self.pg_connstr.text()))
        try:
            self.api_port_spinbox.setValue(int(settings.get("REST_API_PORT", self.api_port_spinbox.value())))
        except Exception:
            pass
        try:
            self.threshold_spinbox.setValue(float(settings.get("NETSENTINEL_THRESHOLD", self.threshold_spinbox.value())))
        except Exception:
            pass
        self.ml_checkbox.setChecked(settings.get("NETSENTINEL_ML_ENABLED", "0").strip() == "1")
        self.statistical_checkbox.setChecked(settings.get("NETSENTINEL_STATISTICAL_ENABLED", "1").strip() == "1")

    def _save_device_setting(self):
        env_path = self._get_env_path()
        settings = self._read_env_file(env_path)
        idx = self.device_combo.currentIndex()
        value = "auto"
        if idx == 1:
            value = "cpu"
        elif idx == 2:
            value = "cuda"
        elif idx == 3:
            value = "both"
        settings["IDS_DEVICE"] = value
        self._write_env_file(env_path, settings)

    def _interface_value(self) -> str:
        value = self.interface_combo.currentText().strip()
        return "Auto-detect" if value == "Samodejno" else value

    def _get_env_path(self) -> str:
        return os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env.local")

    def _read_env_file(self, path: str) -> dict:
        settings = {}
        if not os.path.exists(path):
            return settings
        try:
            with open(path, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, value = line.split("=", 1)
                    settings[key.strip()] = value.strip()
        except Exception:
            return settings
        return settings

    def _write_env_file(self, path: str, settings: dict) -> None:
        try:
            with open(path, "w", encoding="utf-8") as handle:
                for key, value in settings.items():
                    handle.write(f"{key}={value}\n")
        except Exception:
            pass

    def closeEvent(self, event):
        for thread_name in ("_config_thread", "_save_thread"):
            thread = getattr(self, thread_name, None)
            try:
                if thread is not None and thread.isRunning():
                    thread.quit()
                    thread.wait(2000)
            except Exception:
                pass
        super().closeEvent(event)
