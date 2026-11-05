"""Trajni lokalni zapisnik incidentov in demonstracijskih odzivov."""

import json
import logging
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


class IncidentJournal:
    """Shrani omejeno zgodovino incidentov zunaj delovnega prostora projekta."""

    def __init__(self, path: str = "", max_entries: int = 2000):
        self.logger = logging.getLogger(__name__)
        self.max_entries = max(1, max_entries)
        default_dir = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "NetSentinelIDS"
        self.path = Path(path) if path else default_dir / "incident_journal.json"
        self._lock = threading.RLock()
        self._entries: List[Dict[str, Any]] = []
        self._load()

    def _load(self) -> None:
        with self._lock:
            try:
                if not self.path.exists():
                    return
                data = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    self._entries = [item for item in data if isinstance(item, dict)]
                    self._entries = self._entries[: self.max_entries]
            except (OSError, json.JSONDecodeError) as exc:
                self.logger.warning("Incident journal could not be loaded: %s", exc)

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(self._entries, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        temporary.replace(self.path)

    def record(self, incident: Dict[str, Any], event: str, details: str) -> Dict[str, Any]:
        """Zabeleži en incident in vrni shranjeni vnos."""
        entry = {
            "entry_id": str(uuid.uuid4()),
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "details": details,
            "incident": dict(incident),
        }
        with self._lock:
            self._entries.insert(0, entry)
            del self._entries[self.max_entries :]
            self._save()
        return entry

    def list_entries(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Vrni najnovejše vnose zapisnika."""
        with self._lock:
            return [dict(entry) for entry in self._entries[: max(1, limit)]]
