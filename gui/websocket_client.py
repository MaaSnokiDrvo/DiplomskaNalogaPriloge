"""
Odjemalec WebSocket za podatke NetSentinel IDS v realnem času.
Uporablja dogodkovno arhitekturo namesto periodičnega preverjanja.
"""

import time
import json
import threading
import logging
from typing import Callable, Dict, Any, List
from datetime import datetime
import websocket


class WebSocketClient:
    """Odjemalec WebSocket v realnem času za zaledje NetSentinel IDS."""

    def __init__(self, base_url: str = "ws://localhost:8080/ws"):
        self.base_url = base_url
        self.logger = logging.getLogger(__name__)
        self.ws = None
        self.connected = False
        self.running = False
        self._closing = False
        self.thread = None
        self._state_lock = threading.Lock()
        self.callbacks: Dict[str, List[Callable]] = {
            "status": [],
            "alert": [],
            "flow": [],
            "metric": [],
            "error": []
        }
        self.last_data = {}

    def connect(self) -> bool:
        """Vzpostavi povezavo WebSocket."""
        try:
            with self._state_lock:
                if self.running and self.thread and self.thread.is_alive():
                    self.logger.debug("WS connect skipped: already running")
                    return True
                self._closing = False
                self.running = True
            self.logger.info("WS connect %s", self.base_url)
            self.ws = websocket.WebSocketApp(
                self.base_url,
                on_open=self._on_open,
                on_message=self._on_message,
                on_error=self._on_error,
                on_close=self._on_close
            )
            self.thread = threading.Thread(target=self._run_forever, daemon=True)
            self.thread.start()
            return True
        except Exception as e:
            with self._state_lock:
                self.running = False
            self.logger.warning("WS connect error: %s", e)
            self._emit("error", {"message": str(e)})
            return False

    def disconnect(self, wait: bool = True, timeout: float = 0.5):
        """Zapri povezavo WebSocket."""
        with self._state_lock:
            self.running = False
            self._closing = True
        if self.ws:
            try:
                self.ws.close()
            except Exception:
                pass
        if wait and self.thread and self.thread.is_alive():
            self.thread.join(timeout=timeout)
        self.connected = False

    def clear_callbacks(self):
        """Odstrani vse naročnine, predvsem za čisto zaustavitev."""
        for event_type in list(self.callbacks.keys()):
            self.callbacks[event_type].clear()

    def subscribe(self, event_type: str, callback: Callable):
        """Naroči se na dogodke v realnem času."""
        if event_type not in self.callbacks:
            self.callbacks[event_type] = []
        self.callbacks[event_type].append(callback)

    def unsubscribe(self, event_type: str, callback: Callable):
        """Odjavi se od dogodkov."""
        if event_type in self.callbacks and callback in self.callbacks[event_type]:
            self.callbacks[event_type].remove(callback)

    def _emit(self, event_type: str, data: Dict[str, Any]):
        """Pošlji dogodek vsem naročnikom."""
        if event_type in self.callbacks:
            for callback in list(self.callbacks[event_type]):
                try:
                    callback(data)
                except Exception as e:
                    self.logger.debug("WS callback error: %s", e)

    def _on_open(self, ws):
        """Obravnavaj odprtje povezave."""
        self.connected = True
        self.logger.info("WS connected")
        self._emit("status", {"type": "connected", "timestamp": datetime.now().isoformat()})

    def _on_message(self, ws, message: str):
        """Obravnavaj prejeto sporočilo WebSocket."""
        try:
            data = json.loads(message)
            event_type = data.get("type", "metric")
            payload = data.get("data", {})
            self.logger.debug("WS message type=%s", event_type)
            raw_ts = payload.get("timestamp", datetime.now().isoformat())
            if isinstance(raw_ts, str) and raw_ts.endswith("Z"):
                raw_ts = raw_ts[:-1] + "+00:00"
            try:
                payload["timestamp"] = datetime.fromisoformat(raw_ts)
            except Exception:
                payload["timestamp"] = datetime.now()
            self.last_data[event_type] = payload
            self._emit(event_type, payload)
        except Exception as e:
            self.logger.warning("WS message parse error: %s", e)
            self._emit("error", {"message": f"Message parse error: {str(e)}"})

    def _on_error(self, ws, error):
        """Obravnavaj napako WebSocket."""
        self.connected = False
        if self._closing:
            self.logger.debug("WS error during shutdown: %s", error)
            return
        self.logger.warning("WS error: %s", error)
        self._emit("error", {"message": str(error)})

    def _on_close(self, ws, close_status_code, close_msg):
        """Obravnavaj zaprto povezavo."""
        self.connected = False
        if self._closing:
            self.logger.debug("WS closed during shutdown")
            return
        self.logger.warning("WS closed code=%s msg=%s", close_status_code, close_msg)
        self._emit("status", {"type": "disconnected", "timestamp": datetime.now().isoformat()})

    def _run_forever(self):
        """Zaženi WebSocket v niti ozadja."""
        while self.running:
            try:
                self.ws.run_forever()
                if self.running:
                    time.sleep(0.25)
            except Exception as e:
                if self.running:
                    self.logger.warning("WS connection error: %s", e)
                    self._emit("error", {"message": f"Connection error: {str(e)}"})
                    time.sleep(0.5)
