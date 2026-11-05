"""Odjemalec REST API-ja NetSentinel IDS."""

import requests
import logging
from typing import Dict, List, Optional, Any


class APIClient:
    """Odjemalec za komunikacijo z zaledjem NetSentinel IDS."""

    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        self.logger = logging.getLogger(__name__)

    def get_status(self) -> Optional[Dict[str, Any]]:
        """Vrne stanje sistema IDS."""
        try:
            self.logger.info("GET /api/status")
            response = self.session.get(f"{self.base_url}/api/status", timeout=2)
            if response.status_code == 200:
                self.logger.info("/api/status OK")
                return response.json()
            self.logger.warning("/api/status HTTP %s", response.status_code)
            return None
        except requests.RequestException as exc:
            self.logger.warning("/api/status error: %s", exc)
            return None

    def get_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Vrne zadnja opozorila."""
        try:
            self.logger.info("GET /api/alerts?limit=%s", limit)
            response = self.session.get(
                f"{self.base_url}/api/alerts?limit={limit}",
                timeout=2
            )
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    self.logger.info("/api/alerts OK (list size=%s)", len(data))
                    return data
                alerts = data.get("alerts", [])
                self.logger.info("/api/alerts OK (alerts=%s)", len(alerts))
                return alerts
            self.logger.warning("/api/alerts HTTP %s", response.status_code)
            return []
        except requests.RequestException as exc:
            self.logger.warning("/api/alerts error: %s", exc)
            return []

    def get_flows(self, limit: int = 50, timeout: float = 2.0) -> List[Dict[str, Any]]:
        """Vrne zadnje omrežne tokove."""
        try:
            self.logger.info("GET /api/flows?limit=%s", limit)
            response = self.session.get(
                f"{self.base_url}/api/flows?limit={limit}",
                timeout=timeout
            )
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    self.logger.info("/api/flows OK (list size=%s)", len(data))
                    return data
                flows = data.get("flows", [])
                self.logger.info("/api/flows OK (flows=%s)", len(flows))
                return flows
            self.logger.warning("/api/flows HTTP %s", response.status_code)
            return []
        except requests.RequestException as exc:
            self.logger.warning("/api/flows error: %s", exc)
            return []

    def get_statistics(self) -> Optional[Dict[str, Any]]:
        """Vrne statistiko sistema."""
        try:
            self.logger.info("GET /api/statistics")
            response = self.session.get(f"{self.base_url}/api/statistics", timeout=2)
            if response.status_code == 200:
                self.logger.info("/api/statistics OK")
                return response.json()
            self.logger.warning("/api/statistics HTTP %s", response.status_code)
            return None
        except requests.RequestException as exc:
            self.logger.warning("/api/statistics error: %s", exc)
            return None

    def get_config(self) -> Optional[Dict[str, Any]]:
        """Vrne trenutno konfiguracijo IDS."""
        try:
            self.logger.info("GET /api/config")
            response = self.session.get(f"{self.base_url}/api/config", timeout=2)
            if response.status_code == 200:
                self.logger.info("/api/config OK")
                return response.json()
            self.logger.warning("/api/config HTTP %s", response.status_code)
            return None
        except requests.RequestException as exc:
            self.logger.warning("/api/config error: %s", exc)
            return None

    def update_config(self, config: Dict[str, Any]) -> bool:
        """Posodobi konfiguracijo IDS."""
        try:
            self.logger.info("POST /api/config")
            response = self.session.post(
                f"{self.base_url}/api/config",
                json=config,
                timeout=2
            )
            if response.status_code != 200:
                self.logger.warning("/api/config update HTTP %s", response.status_code)
            return response.status_code == 200
        except requests.RequestException as exc:
            self.logger.warning("/api/config update error: %s", exc)
            return False

    def acknowledge_alert(self, alert_id: str) -> bool:
        """Označi opozorilo kot potrjeno."""
        try:
            self.logger.info("POST /api/alerts/%s/acknowledge", alert_id)
            response = self.session.post(
                f"{self.base_url}/api/alerts/{alert_id}/acknowledge",
                timeout=2
            )
            return response.status_code == 200
        except requests.RequestException as exc:
            self.logger.warning("/api/alerts acknowledge error: %s", exc)
            return False

    def resolve_alert(self, alert_id: str) -> bool:
        """Označi opozorilo kot razrešeno."""
        try:
            self.logger.info("POST /api/alerts/%s/resolve", alert_id)
            response = self.session.post(
                f"{self.base_url}/api/alerts/{alert_id}/resolve",
                timeout=2
            )
            return response.status_code == 200
        except requests.RequestException as exc:
            self.logger.warning("/api/alerts resolve error: %s", exc)
            return False

    def shutdown_backend(self) -> bool:
        """Varno ustavi lokalno zaledje."""
        try:
            response = self.session.post(f"{self.base_url}/api/shutdown", timeout=2)
            return response.status_code == 200
        except requests.RequestException as exc:
            self.logger.warning("/api/shutdown error: %s", exc)
            return False

    def get_alert_history(self, days: int = 7) -> List[Dict[str, Any]]:
        """Vrne zgodovino opozoril za določeno obdobje."""
        try:
            self.logger.info("GET /api/alerts/history?days=%s", days)
            response = self.session.get(
                f"{self.base_url}/api/alerts/history?days={days}",
                timeout=2
            )
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    self.logger.info("/api/alerts/history OK (list size=%s)", len(data))
                    return data
                history = data.get("history", [])
                self.logger.info("/api/alerts/history OK (history=%s)", len(history))
                return history
            self.logger.warning("/api/alerts/history HTTP %s", response.status_code)
            return []
        except requests.RequestException as exc:
            self.logger.warning("/api/alerts/history error: %s", exc)
            return []

    def is_connected(self) -> bool:
        """Preveri, ali je API dosegljiv."""
        return self.get_status() is not None
