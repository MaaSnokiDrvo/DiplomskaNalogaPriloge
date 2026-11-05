
import os
os.environ.setdefault("QT_QPA_PLATFORM", "windows")
# --- Čista, ponovno zgrajena glavna datoteka ---
import sys
import builtins
import logging
import time
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QTabWidget, QPushButton
from PyQt5.QtCore import pyqtSignal, pyqtSlot, QTimer, QThread, QObject
from collections import deque
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QLabel

# Uvoz poslovne logike in gradnikov.
from api_client import APIClient
from websocket_client import WebSocketClient
from response_engine import ResponseEngine
from attack_playbooks import PlaybookEngine
from dashboard import DashboardWidget
from alerts import AlertsWidget
from flows import FlowsWidget
from config import ConfigWidget
from analytics_dashboard import AnalyticsDashboardWidget
from automation_dashboard import AutomationWidget
from incident_journal import IncidentJournal

_ORIGINAL_PRINT = builtins.print


def _env_flag(name, default="0"):
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


_GUI_DEBUG_OUTPUT = _env_flag("NETSENTINEL_DEBUG_GUI")


def _filtered_print(*args, **kwargs):
    if not _GUI_DEBUG_OUTPUT and args:
        text = " ".join(str(arg) for arg in args)
        if text.startswith("[DEBUG]"):
            return
    _ORIGINAL_PRINT(*args, **kwargs)


builtins.print = _filtered_print


def _configure_gui_logging():
    level_name = os.environ.get("NETSENTINEL_GUI_LOG_LEVEL")
    if level_name:
        level = getattr(logging, level_name.upper(), logging.ERROR)
    elif _GUI_DEBUG_OUTPUT:
        level = logging.DEBUG
    else:
        level = logging.ERROR

    try:
        logging.basicConfig(
            level=level,
            format="[%(levelname)s] %(name)s: %(message)s",
            force=True,
        )
    except TypeError:
        logging.basicConfig(
            level=level,
            format="[%(levelname)s] %(name)s: %(message)s",
        )


def _terminal_status(kind, message):
    _ORIGINAL_PRINT(f"[{kind}] {message}", flush=True)


class NetSentinelMainWindow(QMainWindow):
    flow_received_signal = pyqtSignal(dict)
    alert_received_signal = pyqtSignal(dict)
    metric_received_signal = pyqtSignal(dict)
    threat_received_signal = pyqtSignal(dict)
    request_live_status = pyqtSignal()
    request_process_threat = pyqtSignal(object)

    def __init__(self):
        super().__init__()
        print("[DEBUG] NetSentinelMainWindow: __init__ start")
        self.logger = logging.getLogger(__name__)
        self._debug_enabled = os.environ.get("NETSENTINEL_DEBUG_GUI", "0") == "1"
        self._headless_mode = os.environ.get("QT_QPA_PLATFORM", "").lower() == "offscreen"
        self._deferred_init_done = False
        self._signals_wired = False
        self._closing = False
        self.update_timer = None
        # Odjemalca API in WebSocket; tukaj ne izvajaj omrežnih klicev.
        print("[DEBUG] Creating APIClient (deferred network checks)...")
        self.api_client = APIClient(base_url="http://localhost:8080")
        print("[DEBUG] Creating WebSocketClient (deferred connect)...")
        self.ws_client = WebSocketClient(base_url="ws://localhost:8080/ws")
        # Privzeto uporabi način brez povezave do preverjanja v ozadju.
        self.offline_mode = True
        self._offline_retry_counter = 0
        self.ui_lite = os.environ.get("NETSENTINEL_UI_LITE", "0") == "1"
        self.presentation_mode = os.environ.get("NETSENTINEL_PRESENTATION_MODE", "0") == "1"
        self.disable_automation = os.environ.get("NETSENTINEL_DISABLE_AUTOMATION", "0") == "1"
        self.disable_automation_timer = os.environ.get("NETSENTINEL_DISABLE_AUTOMATION_TIMER", "0") == "1"
        self._automation_enabled = False
        self.disable_analytics_timer = os.environ.get("NETSENTINEL_DISABLE_ANALYTICS_TIMER", "0") == "1"
        self.disable_websocket = os.environ.get("NETSENTINEL_DISABLE_WEBSOCKET", "0") == "1"
        if self._headless_mode:
            self.disable_websocket = True
            self.disable_automation_timer = True
            self.disable_analytics_timer = True
        self._last_flow_update = 0.0
        self._last_metric_update = 0.0
        self._last_status_refresh_text = "čakam"
        self._simulator_enabled = None
        self._status_thread = None
        self._status_worker = None
        self._status_in_progress = False
        self._live_status_thread = None
        self._live_status_worker = None
        self._live_status_in_progress = False
        self._threat_thread = None
        self._threat_worker = None
        self.analytics_widget = None
        self.automation_widget = None
        self._managed_threads = []
        self._setup_live_status_worker()
        # Stopnje vzorčenja resnosti preprečijo preobremenitev vmesnika.
        # LOW se vzorči močneje, MEDIUM delno, HIGH in CRITICAL v celoti.
        self.threat_sample_rates = {
            # Pri veliki obremenitvi privzeto močno zmanjšaj šum.
            'LOW': float(os.environ.get('NETSENTINEL_THREAT_SAMPLE_LOW', '0.01')),
            'MEDIUM': float(os.environ.get('NETSENTINEL_THREAT_SAMPLE_MEDIUM', '0.10')),
            'HIGH': float(os.environ.get('NETSENTINEL_THREAT_SAMPLE_HIGH', '1.0')),
            'CRITICAL': float(os.environ.get('NETSENTINEL_THREAT_SAMPLE_CRITICAL', '1.0')),
        }
        self._dropped_threats = 0
        self._dropped_flows = 0
        # Medpomnilniki dogodkov WebSocket preprečijo preobremenitev vmesnika.
        self._pending_flows = deque()
        self._pending_alerts = deque()
        self._pending_metrics = deque()
        self._metric_flush_pending = False
        self._flush_timer = QTimer(self)
        # Krajši interval izboljša odzivnost; posamezno praznjenje je časovno omejeno.
        self._flush_timer.setInterval(500)  # Praznjenje vsakih 0,5 sekunde.
        self._flush_timer.timeout.connect(self._flush_pending)
        # Nastavitve praznjenja medpomnilnikov.
        self._flush_batch_size = 5
        self._flush_time_cap_ms = 50.0
        # Če vrsta preseže mejo, se odstranijo najstarejši vnosi.
        self._flush_hard_limit = 5000
        self._flush_resume_size = 1000
        # Zastavice in pragovi za povratni pritisk WebSocket povezave.
        self._ws_paused = False
        self._ws_pause_threshold = 500
        self._ws_resume_threshold = 250
        # Poskrbi za poslovne objekte pred ustvarjanjem gradnikov.
        # Težjo inicializacijo odloži do zagona zanke Qt, da se vmesnik pokaže hitro.
        print("[DEBUG] Creating minimal UI now; heavy init deferred")
        self.init_ui()
        if not self._headless_mode:
            QTimer.singleShot(0, self.finish_init)
        print("[DEBUG] NetSentinelMainWindow: __init__ deferred finish_init scheduled")

    def setup_update_timer(self):
        print("[DEBUG] setup_update_timer: Creating QTimer")
        self.update_timer = QTimer(self)
        print("[DEBUG] setup_update_timer: Connecting timeout signal")
        self.update_timer.timeout.connect(self.update_data)
        print("[DEBUG] setup_update_timer: Starting timer (2000ms)")
        self.update_timer.start(2000)

    def _setup_live_status_worker(self):
        self._live_status_thread = QThread(self)
        try:
            from thread_registry import register
            register(self._live_status_thread)
        except Exception:
            pass
        self._live_status_worker = StatusSnapshotWorker(self.api_client)
        self._live_status_worker.moveToThread(self._live_status_thread)
        self.request_live_status.connect(self._live_status_worker.run)
        self._live_status_worker.finished.connect(self._on_live_status_ready)
        self._live_status_thread.start()

    def _setup_threat_worker(self):
        if self._threat_thread is not None:
            return
        self._threat_thread = QThread(self)
        try:
            from thread_registry import register
            register(self._threat_thread)
        except Exception:
            pass
        self._threat_worker = ThreatProcessingWorker(
            getattr(self, "response_engine", None),
        )
        self._threat_worker.moveToThread(self._threat_thread)
        self.request_process_threat.connect(self._threat_worker.process)
        self._threat_worker.finished.connect(self._on_processed_threat_ready)
        self._threat_thread.start()

    def finish_init(self):
        """Zaženi asinhrono preverjanje stanja API-ja in nadaljuj inicializacijo.
        Tako se vmesnik med preverjanjem zaledja ne blokira.
        """
        print("[DEBUG] finish_init: scheduling API status check in background thread")
        self._api_thread = QThread()
        try:
            from thread_registry import register
            register(self._api_thread)
        except Exception:
            pass
        self._api_worker = APIStatusWorker(self.api_client)
        self._api_worker.moveToThread(self._api_thread)
        self._api_thread.started.connect(self._api_worker.run)
        self._api_worker.finished.connect(self._on_api_status)
        self._api_worker.finished.connect(self._api_thread.quit)
        self._api_worker.finished.connect(self._api_worker.deleteLater)
        self._api_thread.finished.connect(self._api_thread.deleteLater)
        self._api_thread.start()

    def _on_api_status(self, status):
        """Pokliči v glavni niti, ko delavec za stanje API-ja konča."""
        if self._deferred_init_done:
            return
        self._deferred_init_done = True
        try:
            self.offline_mode = status is None
        except Exception:
            self.offline_mode = True
        self._update_status_labels(not self.offline_mode, None)
        if self.offline_mode:
            _terminal_status("INFO", "Zaledni API trenutno ni dosegljiv; GUI deluje brez povezave.")
        else:
            _terminal_status("OK", "Povezava z zalednim API je vzpostavljena.")

        # Nadaljuj odloženo inicializacijo, ko je povezljivost preverjena.
        print("[DEBUG] _on_api_status: starting deferred widget/business init")

        # Inicializiraj objekte poslovne logike.
        try:
            self.response_engine = ResponseEngine()
        except Exception as e:
            print(f"[DEBUG] response_engine init failed: {e}")
            self.response_engine = ResponseEngine()
        self.incident_journal = IncidentJournal()
        try:
            playbook_engine = PlaybookEngine()
            playbook_engine.create_default_playbooks()
            self.response_engine.playbook_engine = playbook_engine
        except Exception as e:
            print(f"[DEBUG] playbook engine init warning: {e}")

        if self._headless_mode:
            self._wire_ws_signals()
            print("[DEBUG] _on_api_status: headless mode, response engine only")
            return

        try:
            self._setup_threat_worker()
        except Exception as e:
            print(f"[DEBUG] Threat worker setup failed: {e}")

        def _replace_placeholder_contents(placeholder, widget):
            layout = placeholder.layout() if placeholder else None
            if layout is None:
                return
            while layout.count():
                item = layout.takeAt(0)
                child = item.widget()
                if child is not None:
                    child.deleteLater()
            layout.addWidget(widget)

        # Po potrebi ustvari zahtevne gradnike in zamenjaj označbe mesta.
        try:
            # Alarmi.
            try:
                real_alerts = AlertsWidget(
                    self.api_client,
                    self.incident_journal,
                    self._run_alert_automation,
                )
                placeholder = self.tabs.widget(self._placeholder_indices['alerts'])
                _replace_placeholder_contents(placeholder, real_alerts)
                self.alerts_widget = real_alerts
            except Exception as e:
                print(f"[DEBUG] AlertsWidget init failed: {e}")

            # Tokovi.
            try:
                real_flows = FlowsWidget(self.api_client)
                placeholder = self.tabs.widget(self._placeholder_indices['flows'])
                _replace_placeholder_contents(placeholder, real_flows)
                self.flows_widget = real_flows
            except Exception as e:
                print(f"[DEBUG] FlowsWidget init failed: {e}")

            # Config
            try:
                real_config = ConfigWidget(self.api_client)
                placeholder = self.tabs.widget(self._placeholder_indices['config'])
                _replace_placeholder_contents(placeholder, real_config)
                self.config_widget = real_config
            except Exception as e:
                print(f"[DEBUG] ConfigWidget init failed: {e}")

            # Analitika, ki je zahtevnejša za bazo.
            try:
                if self._placeholder_indices['analytics'] is not None and not self._headless_mode:
                    real_analytics = AnalyticsDashboardWidget(
                        self.api_client,
                        enable_auto_refresh=(not self.offline_mode and not self.ui_lite and not self.disable_analytics_timer),
                    )
                    placeholder = self.tabs.widget(self._placeholder_indices['analytics'])
                    _replace_placeholder_contents(placeholder, real_analytics)
                    self.analytics_widget = real_analytics
            except Exception as e:
                print(f"[DEBUG] AnalyticsDashboardWidget init failed: {e}")

            # Automation
            try:
                if self._placeholder_indices['automation'] is not None and not self._headless_mode:
                    real_automation = AutomationWidget(
                        response_engine=self.response_engine,
                        enable_timer=not self.ui_lite and not self.disable_automation_timer,
                        threat_callback=self.on_threat_received,
                        automation_mode_callback=self._set_automation_enabled,
                    )
                    placeholder = self.tabs.widget(self._placeholder_indices['automation'])
                    _replace_placeholder_contents(placeholder, real_automation)
                    self.automation_widget = real_automation
            except Exception as e:
                print(f"[DEBUG] AutomationWidget init failed: {e}")

        except Exception as e:
            print(f"[DEBUG] Deferred widget initialization encountered an error: {e}")

        # Poveži signale WebSocket in zaženi povezave, če so omogočene.
        try:
            self._wire_ws_signals()
            # Naroči se na dogodke WebSocket in oddaj signale PyQt.
            if not self.disable_websocket:
                try:
                        # Preslikaj vrste dogodkov WebSocket v naše signale PyQt.
                        self.ws_client.subscribe("flow", self._emit_flow_signal)
                        self.ws_client.subscribe("alert", self._emit_alert_signal)
                        self.ws_client.subscribe("metric", self._emit_metric_signal)
                        self.ws_client.subscribe("threat", self._emit_threat_signal)
                except Exception:
                    pass
                # Poveži nit ozadja WebSocket.
                self.ws_client.connect()

            # Poveži signale PyQt z notranjimi vrstami za omejevanje osveževanja.
            try:
                self.flow_received_signal.connect(self._enqueue_flow)
                self.alert_received_signal.connect(self._enqueue_alert)
                self.metric_received_signal.connect(self._enqueue_metric)
                # Zaženi časovnik praznjenja ob povezavi prvega naročnika.
                if not self._flush_timer.isActive():
                    self._flush_timer.start()
            except Exception:
                pass
        except Exception as e:
            print(f"[DEBUG] WebSocket wiring/connect failed: {e}")

        # Zdaj, ko je težja inicializacija končana, zaženi časovnik posodabljanja.
        if not self._headless_mode:
            try:
                self.setup_update_timer()
            except Exception as e:
                print(f"[DEBUG] setup_update_timer failed: {e}")
            try:
                self.update_data()
            except Exception:
                pass

        try:
            self._on_tab_changed(self.tabs.currentIndex())
        except Exception:
            pass
        if not self._headless_mode:
            QTimer.singleShot(700, self._prime_background_views)

        try:
            tab_names = [self.tabs.tabText(i) for i in range(self.tabs.count())]
            _terminal_status("OK", "Zavihki pripravljeni: " + ", ".join(tab_names) + ".")
        except Exception:
            _terminal_status("OK", "Zavihki pripravljeni.")
        _terminal_status("OK", "GUI pripravljen za uporabo.")
        print("[DEBUG] finish_init: deferred initialization complete")

    def _run_alert_automation(self, alert):
        """Zaženi obstoječi odzivni modul za ročno izbrani alarm."""
        threat = dict(alert)
        threat["threat_id"] = alert.get("id", 0)
        threat["threat_level"] = str(alert.get("severity", "LOW")).upper()
        threat["threat_score"] = float(alert.get("threat_score", alert.get("anomaly_score", 0.0)) or 0.0)
        threat["indicators"] = alert.get("indicators", [])
        response = self.response_engine.execute_response(threat)
        if response is None:
            return {"ok": False, "message": "Za ta alarm ni določenega avtomatiziranega odziva."}
        status = getattr(response.status, "value", str(response.status)).lower()
        if status != "success":
            return {"ok": False, "message": response.result or "Avtomatizirani odziv ni uspel."}
        target_status = "RESOLVED" if threat["threat_level"] == "LOW" else "ACKNOWLEDGED"
        return {
            "ok": True,
            "status": target_status,
            "message": response.result or "Avtomatizirani odziv je bil izveden.",
        }

    def _set_automation_enabled(self, enabled):
        self._automation_enabled = bool(enabled)

    def _prime_background_views(self):
        """Zaženi začetno osveževanje neaktivnih predstavitvenih zavihkov."""
        if self._closing:
            return
        for attr_name, method_name in (
            ("alerts_widget", "refresh_alerts"),
            ("flows_widget", "refresh_flows"),
            ("analytics_widget", "refresh_analytics"),
            ("automation_widget", "refresh_data"),
        ):
            widget = getattr(self, attr_name, None)
            method = getattr(widget, method_name, None)
            if callable(method):
                try:
                    method()
                except Exception:
                    pass

    def _on_app_about_to_quit(self):
        print("[DEBUG] _on_app_about_to_quit: application is quitting, performing cleanup")
        try:
            self.close()
        except Exception as e:
            print(f"[DEBUG] _on_app_about_to_quit: close() failed: {e}")

    def closeEvent(self, a0):
        self._closing = True
        print("[DEBUG] closeEvent: Stopping update_timer if active")
        if hasattr(self, 'update_timer') and self.update_timer and self.update_timer.isActive():
            self.update_timer.stop()
            print("[DEBUG] closeEvent: update_timer stopped")
        else:
            print("[DEBUG] closeEvent: update_timer not active or not present")
        if getattr(self, "_flush_timer", None) and self._flush_timer.isActive():
            self._flush_timer.stop()

        # Odklopi nit ozadja WebSocket.
        try:
            if hasattr(self, 'ws_client') and self.ws_client:
                try:
                    print("[DEBUG] closeEvent: disconnecting websocket client")
                    self.ws_client.clear_callbacks()
                    self.ws_client.disconnect(wait=False)
                except Exception as e:
                    print(f"[DEBUG] closeEvent: websocket disconnect failed: {e}")
        except Exception:
            pass

        # Pomožna funkcija za varno ustavljanje niti QThread.
        def _stop_qthread(t):
            try:
                if t is None:
                    return
                # QThread has isRunning on PyQt
                if hasattr(t, 'isRunning') and t.isRunning():
                    try:
                        t.quit()
                    except Exception:
                        pass
                    try:
                        t.wait(2000)
                    except Exception:
                        pass
            except Exception:
                pass

        # Ustavi znane niti glavnega okna.
        try:
            _stop_qthread(getattr(self, '_api_thread', None))
        except Exception:
            pass
        try:
            _stop_qthread(getattr(self, '_live_status_thread', None))
        except Exception:
            pass
        try:
            _stop_qthread(getattr(self, '_threat_thread', None))
        except Exception:
            pass

        # Če obstajajo, poskusi ustaviti niti podrejenih gradnikov.
        for attr in ('alerts_widget', 'flows_widget', 'analytics_widget', 'automation_widget', 'config_widget'):
            try:
                w = getattr(self, attr, None)
                if not w:
                    continue
                # common names used by widgets
                for tname in ('_refresh_thread', '_db_thread', '_worker_thread', '_action_thread', '_thread'):
                    t = getattr(w, tname, None)
                    _stop_qthread(t)
            except Exception:
                pass

        try:
            from thread_registry import stop_all
            stop_all(timeout=2000)
        except Exception:
            pass

        super().closeEvent(a0)

    def update_data(self):
        if self._closing or self._live_status_in_progress:
            return
        self._live_status_in_progress = True
        self.request_live_status.emit()

    def _apply_shared_styles(self):
        self.setStyleSheet(
            """
            QMainWindow {
                background-color: #f7f8fa;
            }
            QWidget {
                background-color: #f7f8fa;
                color: #172033;
            }
            QTabWidget::pane {
                border: 1px solid #e2e8f0;
                background: #ffffff;
                border-radius: 3px;
            }
            QTabBar::tab {
                background: #f1f5f9;
                color: #263242;
                padding: 7px 12px;
                margin-right: 2px;
                border: 1px solid #e2e8f0;
                border-top-left-radius: 3px;
                border-top-right-radius: 3px;
            }
            QTabBar::tab:selected {
                background: #ffffff;
                color: #172033;
            }
            QLabel {
                color: #172033;
            }
            QPushButton {
                background-color: #ffffff;
                color: #172033;
                border: 1px solid #cbd5e1;
                border-radius: 3px;
                padding: 6px 9px;
            }
            QPushButton:hover {
                background-color: #f1f5f9;
                border-color: #94a3b8;
            }
            QPushButton:disabled {
                background-color: #f1f5f9;
                border: 1px solid #e2e8f0;
                color: #64748b;
            }
            QGroupBox {
                border: 1px solid #e2e8f0;
                border-radius: 3px;
                margin-top: 10px;
                padding-top: 10px;
                color: #172033;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 4px;
            }
            QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox, QDoubleSpinBox, QDateEdit {
                background: #ffffff;
                color: #172033;
                border: 1px solid #cbd5e1;
                border-radius: 3px;
                padding: 6px 8px;
                selection-background-color: #bfdbfe;
                selection-color: #172033;
            }
            QComboBox QAbstractItemView, QMenu {
                background: #ffffff;
                color: #172033;
                border: 1px solid #cbd5e1;
                selection-background-color: #bfdbfe;
                selection-color: #172033;
            }
            QTableWidget, QTreeWidget, QListWidget {
                background: #ffffff;
                alternate-background-color: #f8fafc;
                color: #172033;
                border: 1px solid #e2e8f0;
                gridline-color: #e5e7eb;
                selection-background-color: #bfdbfe;
                selection-color: #172033;
            }
            QHeaderView::section {
                background: #f1f5f9;
                color: #172033;
                border: 1px solid #e2e8f0;
                padding: 6px;
            }
            QProgressBar {
                background: #e5e7eb;
                color: #172033;
                border: 1px solid #cbd5e1;
                border-radius: 3px;
                text-align: center;
            }
            QProgressBar::chunk {
                background: #2563eb;
                border-radius: 3px;
            }
            """
        )

    def _update_global_status_strip(self):
        try:
            if hasattr(self, "_global_backend_chip"):
                if self.offline_mode:
                    self._global_backend_chip.setText("Zaledje brez povezave")
                    self._global_backend_chip.setStyleSheet(
                        "background-color: #fef2f2; border: 1px solid #fecaca; border-radius: 4px; padding: 5px 8px; color: #991b1b;"
                    )
                else:
                    self._global_backend_chip.setText("Zaledje povezano")
                    self._global_backend_chip.setStyleSheet(
                        "background-color: #ecfdf5; border: 1px solid #bbf7d0; border-radius: 4px; padding: 5px 8px; color: #166534;"
                    )

            if hasattr(self, "_global_queue_chip"):
                self._global_queue_chip.setText(
                    f"Vrste T:{len(self._pending_flows)} A:{len(self._pending_alerts)} M:{len(self._pending_metrics)}"
                )

            if hasattr(self, "_global_refresh_chip"):
                self._global_refresh_chip.setText(f"Osveženo {self._last_status_refresh_text}")

            if hasattr(self, "_global_tab_chip"):
                try:
                    tab_text = self.tabs.tabText(self.tabs.currentIndex())
                except Exception:
                    tab_text = "neznan"
                self._global_tab_chip.setText(f"Aktiven zavihek: {tab_text}")

            if hasattr(self, "dashboard_widget") and hasattr(self.dashboard_widget, "update_runtime_state"):
                self.dashboard_widget.update_runtime_state(
                    connected=not self.offline_mode,
                    simulator_enabled=getattr(self, "_simulator_enabled", None),
                    queue_depths={
                        "flows": len(self._pending_flows),
                        "alerts": len(self._pending_alerts),
                        "metrics": len(self._pending_metrics),
                    },
                    last_refresh=self._last_status_refresh_text if self._last_status_refresh_text != "čakam" else None,
                )
        except Exception:
            pass

    def init_ui(self):
        print("[DEBUG] init_ui: start")
        if self._headless_mode:
            self.setWindowTitle("NetSentinel IDS")
            self.tabs = QTabWidget()
            self._placeholder_indices = {
                'alerts': None,
                'flows': None,
                'analytics': None,
                'automation': None,
                'config': None,
            }
            central_widget = QWidget()
            layout = QVBoxLayout()
            layout.addWidget(self.tabs)
            central_widget.setLayout(layout)
            self.setCentralWidget(central_widget)
            self.dashboard_widget = QWidget()
            self.alerts_widget = QWidget()
            self.flows_widget = QWidget()
            self.analytics_widget = None
            self.automation_widget = None
            self.config_widget = QWidget()
            print("[DEBUG] init_ui: headless minimal UI complete")
            return
        self.setWindowTitle("NetSentinel IDS - demonstracija zaznavanja in odzivov")
        self.setGeometry(100, 100, 1240, 780)
        self._apply_shared_styles()
        central_widget = QWidget()
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(6)
        self.tabs = QTabWidget()
        self.tabs.setFont(QFont("Segoe UI", 10))
        shutdown_button = QPushButton("Izhod")
        shutdown_button.setToolTip("Ustavi lokalno zaledje in zapri vsa okna")
        shutdown_button.clicked.connect(self.shutdown_application)
        main_layout.addWidget(shutdown_button)
        # Nadzorno ploščo ustvari takoj, ker je lahka.
        try:
            print("[DEBUG] Creating DashboardWidget...")
            self.dashboard_widget = DashboardWidget(self.api_client)
        except Exception as e:
            print(f"[EXCEPTION] DashboardWidget: {e}")
            self.dashboard_widget = QWidget()

        # Za druge zavihke ustvari začasne vsebine; pravi gradniki se
        # ustvarijo v finish_init, da se zanka dogodkov ne blokira.
        from PyQt5.QtWidgets import QLabel
        def _placeholder(text="Nalaganje..."):
            ph = QWidget()
            ph_layout = QVBoxLayout()
            lbl = QLabel(text)
            ph_layout.addWidget(lbl)
            ph_layout.addStretch()
            ph.setLayout(ph_layout)
            return ph

        self.alerts_widget = _placeholder("Nalaganje alarmov...")
        self.flows_widget = _placeholder("Nalaganje tokov...")
        self.analytics_widget = _placeholder("Nalaganje analitike...")
        self.automation_widget = _placeholder("Nalaganje avtomatizacije...")
        self.config_widget = _placeholder("Nalaganje nastavitev...")
        print("[DEBUG] Adding ONLY Dashboard tab for isolation...")
        self.tabs.addTab(self.dashboard_widget, "Nadzorna plošča")
        print("[DEBUG] Adding Alerts tab (placeholder)...")
        idx_alerts = self.tabs.addTab(self.alerts_widget, "Alarmi")
        print("[DEBUG] Adding Flows tab (placeholder)...")
        idx_flows = self.tabs.addTab(self.flows_widget, "Tokovi")
        print("[DEBUG] Adding Analytics tab (placeholder)...")
        idx_analytics = self.tabs.addTab(self.analytics_widget, "Analitika")
        print("[DEBUG] Adding Automation tab (placeholder)...")
        idx_automation = self.tabs.addTab(self.automation_widget, "Avtomatizacija")
        print("[DEBUG] Adding Config tab (placeholder)...")
        idx_config = self.tabs.addTab(self.config_widget, "Nastavitve")

        # Zabeleži indekse označb mesta, da jih lahko finish_init zamenja.
        self._placeholder_indices = {
            'alerts': idx_alerts,
            'flows': idx_flows,
            'analytics': idx_analytics,
            'automation': idx_automation,
            'config': idx_config,
        }
        if self.presentation_mode:
            hidden_tabs = []
            for key in ("analytics", "automation"):
                idx = self._placeholder_indices.get(key)
                if idx is None:
                    continue
                hidden_tabs.append((idx, key))
            for idx, key in sorted(hidden_tabs, reverse=True):
                self._placeholder_indices[key] = None
                try:
                    self.tabs.removeTab(idx)
                except Exception:
                    pass
            for _, key in hidden_tabs:
                self._placeholder_indices[key] = None
        main_layout.addWidget(self.tabs)
        print("[DEBUG] All tabs added. Setting up status bar...")
        status_bar = self.statusBar()
        if status_bar is not None and hasattr(status_bar, 'showMessage'):
            if self.presentation_mode:
                status_bar.showMessage("Pripravljeno - predstavitveni način")
            else:
                status_bar.showMessage("Pripravljeno - demo način")
        # Oznaka srčnega utripa za spremljanje odzivnosti glavne niti.
        try:
            self._backend_status_label = QLabel("Zaledje: preverjam")
            self._simulator_status_label = QLabel("Simulator: neznan")
            status_bar.addPermanentWidget(self._backend_status_label)
            status_bar.addPermanentWidget(self._simulator_status_label)
        except Exception:
            pass
        print("[DEBUG] Connecting tab changed signal...")
        self.tabs.currentChanged.connect(self._on_tab_changed)
        print("[DEBUG] Setting layout on central widget...")
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)
        print("[DEBUG] init_ui: complete")
        self._update_global_status_strip()

    def shutdown_application(self):
        """Ustavi lokalno zaledje in nato zapri grafični vmesnik."""
        self._closing = True
        try:
            self.api_client.shutdown_backend()
        finally:
            app = QApplication.instance()
            if app is not None:
                app.quit()

    def _emit_flow_signal(self, data):
        if not self._closing and not self._ws_paused:
            self.flow_received_signal.emit(data)

    def _emit_alert_signal(self, data):
        if not self._closing:
            self.alert_received_signal.emit(data)

    def _emit_metric_signal(self, data):
        if not self._closing:
            self.metric_received_signal.emit(data)

    def _emit_threat_signal(self, data):
        if not self._closing:
            self.threat_received_signal.emit(data)

    def _update_status_labels(self, connected: bool, simulator_enabled=None):
        try:
            self._simulator_enabled = simulator_enabled
            if hasattr(self, "_backend_status_label"):
                if connected:
                    self._backend_status_label.setText("Zaledje: povezano")
                    self._backend_status_label.setStyleSheet("color: #166534;")
                else:
                    self._backend_status_label.setText("Zaledje: brez povezave")
                    self._backend_status_label.setStyleSheet("color: #991b1b;")
            if hasattr(self, "_simulator_status_label"):
                if simulator_enabled is True:
                    self._simulator_status_label.setText("Simulator: vključen")
                    self._simulator_status_label.setStyleSheet("color: #92400e;")
                    if hasattr(self, "_global_simulator_chip"):
                        self._global_simulator_chip.setText("Simulator vključen")
                        self._global_simulator_chip.setStyleSheet(
                            "background-color: #fffbeb; border: 1px solid #fde68a; border-radius: 4px; padding: 5px 8px; color: #92400e;"
                        )
                elif simulator_enabled is False:
                    self._simulator_status_label.setText("Simulator: izključen")
                    self._simulator_status_label.setStyleSheet("color: #1d4ed8;")
                    if hasattr(self, "_global_simulator_chip"):
                        self._global_simulator_chip.setText("Simulator izključen")
                        self._global_simulator_chip.setStyleSheet(
                            "background-color: #eff6ff; border: 1px solid #bfdbfe; border-radius: 4px; padding: 5px 8px; color: #1d4ed8;"
                        )
                else:
                    self._simulator_status_label.setText("Simulator: neznan")
                    self._simulator_status_label.setStyleSheet("color: #64748b;")
                    if hasattr(self, "_global_simulator_chip"):
                        self._global_simulator_chip.setText("Simulator neznan")
                        self._global_simulator_chip.setStyleSheet(
                            "background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 4px; padding: 5px 8px; color: #64748b;"
                        )
            self._update_global_status_strip()
        except Exception:
            pass

    def _on_live_status_ready(self, status, config):
        self.offline_mode = status is None
        self._last_status_refresh_text = time.strftime("%H:%M:%S")
        simulator_enabled = None
        if isinstance(config, dict):
            simulator_enabled = config.get("simulate_attacks")
        self._update_status_labels(not self.offline_mode, simulator_enabled)
        if hasattr(self, "dashboard_widget") and hasattr(self.dashboard_widget, "update_metrics"):
            try:
                self.dashboard_widget.update_metrics(status or {})
            except Exception:
                pass
        self._live_status_in_progress = False

    def on_threat_received(self, data: dict):
        self.threat_received_signal.emit(data)

    def _enqueue_flow(self, data: dict):
        try:
            # Omeji velikost vrste, da preprečiš neomejeno rast pomnilnika in dogodkov.
            if len(self._pending_flows) > 2000:
                try:
                    self._pending_flows.popleft()
                    self._dropped_flows += 1
                except Exception:
                    pass
            self._pending_flows.append(data)
            # Zagotovi, da časovnik praznjenja deluje.
            try:
                if not self._flush_timer.isActive():
                    self._flush_timer.start()
            except Exception:
                pass
            self._update_global_status_strip()
            # Če vrsta preseže mejo, začasno ustavi WebSocket zaradi povratnega pritiska.
            try:
                if not self._ws_paused and len(self._pending_flows) > self._ws_pause_threshold:
                    self.logger.warning(
                        "Pending flows %s exceeded threshold, temporarily dropping incoming flow events",
                        len(self._pending_flows),
                    )
                    self._ws_paused = True
            except Exception:
                pass
        except Exception:
            pass

    def _enqueue_alert(self, data: dict):
        try:
            if len(self._pending_alerts) > 2000:
                try:
                    self._pending_alerts.popleft()
                except Exception:
                    pass
            self._pending_alerts.append(data)
            try:
                if not self._flush_timer.isActive():
                    self._flush_timer.start()
            except Exception:
                pass
            self._update_global_status_strip()
        except Exception:
            pass

    def _enqueue_metric(self, data: dict):
        try:
            self._pending_metrics.clear()
            self._pending_metrics.append(data)
            if not self._metric_flush_pending:
                self._metric_flush_pending = True
                QTimer.singleShot(0, self._flush_metrics)
            self._update_global_status_strip()
        except Exception:
            pass

    def _flush_metrics(self):
        self._metric_flush_pending = False
        latest_metric = None
        while self._pending_metrics:
            latest_metric = self._pending_metrics.pop()
        if latest_metric is None:
            return
        if hasattr(self, "dashboard_widget") and hasattr(self.dashboard_widget, "update_metrics"):
            try:
                self.dashboard_widget.update_metrics(latest_metric)
            except Exception:
                pass
        self._update_global_status_strip()

    def _flush_pending(self):
        """Izprazni čakajoče dogodke WebSocket v manjših paketih, da preprečiš blokado vmesnika."""
        try:
            start = time.time()
            # Uporabi nastavljeno velikost paketa in časovno omejitev.
            batch_size = getattr(self, '_flush_batch_size', 5)
            max_elapsed_ms = getattr(self, '_flush_time_cap_ms', 50.0)
            total_processed = 0

            # Pri ogromnem zaostanku odstrani najstarejše vnose, da preprečiš OOM.
            try:
                if len(self._pending_flows) > getattr(self, '_flush_hard_limit', 5000):
                    drop_to = getattr(self, '_flush_resume_size', 1000)
                    to_drop = len(self._pending_flows) - drop_to
                    for _ in range(to_drop):
                        try:
                            self._pending_flows.popleft()
                            self._dropped_flows += 1
                        except Exception:
                            break
                    self.logger.warning("Dropped %s old pending flows to recover from large backlog", to_drop)
            except Exception:
                pass

            # Obdelaj tokove z omejenim časom; če zavihek ni viden, obdelaj manj vnosov.
            active_tab = None
            try:
                active_tab = self.tabs.currentIndex()
            except Exception:
                active_tab = None

            flows_priority = batch_size
            try:
                flows_index = self._placeholder_indices.get('flows')
                # Če zavihek tokov ni viden, zmanjša obdelavo na en vnos.
                if active_tab is not None and flows_index is not None and active_tab != flows_index:
                    flows_priority = max(1, batch_size // 4)
            except Exception:
                flows_priority = batch_size

            flows_to_process = min(flows_priority, len(self._pending_flows))
            for _ in range(flows_to_process):
                try:
                    # Ustavi se, če je preteklo preveč časa.
                    if (time.time() - start) * 1000.0 > max_elapsed_ms:
                        break
                    item = self._pending_flows.popleft()
                    if getattr(self, 'flows_widget', None) and hasattr(self.flows_widget, 'add_flow'):
                        try:
                            self.flows_widget.add_flow(item)
                        except Exception:
                            pass
                    total_processed += 1
                except IndexError:
                    break

            # Obdelaj alarme z omejenim časom; če zavihek ni viden, zmanjša obseg dela.
            alerts_priority = batch_size
            try:
                alerts_index = self._placeholder_indices.get('alerts')
                if active_tab is not None and alerts_index is not None and active_tab != alerts_index:
                    alerts_priority = max(1, batch_size // 4)
            except Exception:
                alerts_priority = batch_size

            alerts_to_process = min(alerts_priority, len(self._pending_alerts))
            for _ in range(alerts_to_process):
                try:
                    if (time.time() - start) * 1000.0 > max_elapsed_ms:
                        break
                    item = self._pending_alerts.popleft()
                    if getattr(self, 'alerts_widget', None) and hasattr(self.alerts_widget, 'add_alert'):
                        try:
                            self.alerts_widget.add_alert(item)
                        except Exception:
                            pass
                    if getattr(self, 'analytics_widget', None) and hasattr(self.analytics_widget, 'add_alert'):
                        try:
                            self.analytics_widget.add_alert(item)
                        except Exception:
                            pass
                    total_processed += 1
                except IndexError:
                    break

            elapsed = (time.time() - start) * 1000.0
            if self._debug_enabled and total_processed > 0:
                self.logger.debug(
                    "_flush_pending processed=%s flows_remaining=%s alerts_remaining=%s elapsed_ms=%.1f dropped_flows=%s",
                    total_processed,
                    len(self._pending_flows),
                    len(self._pending_alerts),
                    elapsed,
                    self._dropped_flows,
                )

            # Ustavi časovnik, če nič ne čaka.
            if not (self._pending_flows or self._pending_alerts or self._pending_metrics):
                try:
                    if self._flush_timer.isActive():
                        self._flush_timer.stop()
                except Exception:
                    pass
            # Nadaljuj WebSocket, če je bil zaustavljen in je vrsta izpraznjena.
            try:
                if self._ws_paused and len(self._pending_flows) < self._ws_resume_threshold:
                    self.logger.info(
                        "Pending flows drained (%s), resuming incoming flow handling",
                        len(self._pending_flows),
                    )
                    self._ws_paused = False
            except Exception:
                pass
            self._update_global_status_strip()
        except Exception as e:
            self.logger.debug("_flush_pending: exception %s", e)

    def _wire_ws_signals(self):
        if self._signals_wired:
            return
        self.threat_received_signal.connect(self._on_threat_received_ui)
        self._signals_wired = True

    def _on_threat_received_ui(self, data):
        """Obravnavaj prejete dogodke groženj iz vmesnika ali WebSocket.

        Dogodek usmeri v lokalni `ResponseEngine` in podatkovni cevovod,
        da ga vidijo vmesnik avtomatizacije in drugi porabniki.
        """
        try:
            # Vzorči grožnje nizke in srednje resnosti, da ne preobremeniš vmesnika.
            import random
            sev = (data.get('threat_level') or 'LOW').upper()
            rate = self.threat_sample_rates.get(sev, 1.0)
            if rate <= 0.0:
                # Izrecno onemogočeno: zavrzi.
                self._dropped_threats += 1
                return
            if rate < 1.0 and random.random() > rate:
                # Izločeno z vzorčenjem.
                self._dropped_threats += 1
                return
            payload = dict(data)
            already_processed = bool(payload.get("_automation_response_applied", False))
            payload["_automation_enabled"] = self._automation_enabled
            if self._threat_worker is not None:
                self.request_process_threat.emit(payload)
            else:
                if (
                    hasattr(self, 'response_engine')
                    and self.response_engine
                    and self._automation_enabled
                    and not already_processed
                ):
                    try:
                        self.response_engine.execute_response(payload)
                    except Exception:
                        pass
        except Exception:
            pass

    def _on_processed_threat_ready(self, data):
        try:
            if getattr(self, 'analytics_widget', None) and hasattr(self.analytics_widget, 'add_alert'):
                try:
                    self.analytics_widget.add_alert(dict(data))
                except Exception:
                    pass
        except Exception:
            pass

    def _on_tab_changed(self, index):
        print(f"[DEBUG] _on_tab_changed: index={index}")
        self._set_tab_widget_active('alerts', 'alerts_widget', index)
        self._set_tab_widget_active('flows', 'flows_widget', index)
        self._set_tab_widget_active('analytics', 'analytics_widget', index)
        self._set_tab_widget_active('automation', 'automation_widget', index)
        self._update_global_status_strip()

    def _set_tab_widget_active(self, key, attr_name, index):
        try:
            tab_index = self._placeholder_indices.get(key)
            widget = getattr(self, attr_name, None)
            if widget is not None and hasattr(widget, 'set_active'):
                widget.set_active(tab_index is not None and index == tab_index)
        except Exception:
            pass


class APIStatusWorker(QObject):
    finished = pyqtSignal(object)

    def __init__(self, api_client):
        super().__init__()
        self.api_client = api_client

    def run(self):
        try:
            status = self.api_client.get_status()
            self.finished.emit(status)
        except Exception:
            self.finished.emit(None)


class StatusSnapshotWorker(QObject):
    finished = pyqtSignal(object, object)

    def __init__(self, api_client):
        super().__init__()
        self.api_client = api_client

    def run(self):
        try:
            status = self.api_client.get_status()
            if isinstance(status, dict):
                try:
                    if int(status.get("flows", 0) or 0) == 0 or int(status.get("packets", 0) or 0) == 0:
                        recent_flows = self.api_client.get_flows(limit=50, timeout=1.0)
                        if recent_flows:
                            status = dict(status)
                            status["flows"] = max(int(status.get("flows", 0) or 0), len(recent_flows))
                            derived_packets = sum(int(flow.get("packets", 0) or 0) for flow in recent_flows)
                            if derived_packets and int(status.get("packets", 0) or 0) == 0:
                                status["packets"] = derived_packets
                                status["_derived_from_flows"] = True
                except Exception:
                    pass
            config = self.api_client.get_config() if status is not None else None
            self.finished.emit(status, config)
        except Exception:
            self.finished.emit(None, None)


class ThreatProcessingWorker(QObject):
    finished = pyqtSignal(object)

    def __init__(self, response_engine=None):
        super().__init__()
        self.response_engine = response_engine

    @pyqtSlot(object)
    def process(self, data):
        payload = dict(data or {})
        already_processed = bool(payload.pop("_automation_response_applied", False))
        automation_enabled = bool(payload.pop("_automation_enabled", False))
        try:
            if self.response_engine and automation_enabled and not already_processed:
                try:
                    self.response_engine.execute_response(payload)
                except Exception:
                    pass
        finally:
            self.finished.emit(payload)

def main():
    _configure_gui_logging()
    _terminal_status("OK", "NetSentinel GUI se zaganja.")
    _terminal_status("INFO", "Zaledni API: http://localhost:8080")
    try:
        app = QApplication(sys.argv)
        window = NetSentinelMainWindow()
        # Poskrbi, da se ob koncu QApplication izvede čiščenje okna.
        try:
            app.aboutToQuit.connect(window._on_app_about_to_quit)
        except Exception:
            pass
        try:
            # Ob izhodu ustavi register niti.
            from thread_registry import stop_all
            app.aboutToQuit.connect(lambda: stop_all())
        except Exception:
            pass
        window.setGeometry(100, 100, 1400, 900)
        window.show()
        window.raise_()  # Premakni okno v ospredje.
        window.activateWindow()  # Poskusi aktivirati okno.
        window.showMaximized()
        _terminal_status("OK", "Glavno okno prikazano.")
        ret = app.exec_()
        sys.exit(ret)
    except Exception as e:
        import traceback
        logging.getLogger(__name__).exception("Unhandled exception in main: %s", e)
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
