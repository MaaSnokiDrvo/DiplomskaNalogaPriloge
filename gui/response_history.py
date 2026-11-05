from typing import List
import logging
from collections import deque
import json
import os

from PyQt5.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QTableView,
    QHeaderView,
    QLabel,
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtCore import QAbstractTableModel, QModelIndex, QVariant
import concurrent.futures

logger = logging.getLogger(__name__)


class ResponseHistoryWidget(QWidget):
    """Gradnik vmesnika za prikaz zgodovine avtomatiziranih odzivov v tabeli.

    Uporaba:
      - Ustvari gradnik in ga dodaj v postavitev.
      - Pokliči `register_engine(engine)` za samodejno posodabljanje ob povratnih klicih.
      - Ali pokliči `set_responses(list_of_dicts_or_objects)` za ročno polnjenje.
    """

    COLUMNS = [
        "ID odziva",
        "ID dogodka",
        "Akcija",
        "Cilj",
        "Status",
        "Resnost",
        "Sprožen ob",
        "Izveden ob",
        "Rezultat",
    ]

    FIELD_KEYS = [
        "response_id",
        "threat_id",
        "action",
        "target",
        "status",
        "severity",
        "triggered_at",
        "executed_at",
        "result",
    ]
    _MAX_HISTORY_FILE_BYTES = 10 * 1024 * 1024

    # Signal za varen prenos povratnih klicev odzivov v glavno nit Qt.
    response_received = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__(parent)

        # Poveži signal z obravnavo, da se povratni klici iz katerekoli niti
        # izvedejo v glavni niti Qt.
        try:
            self.response_received.connect(self._on_response)
        except Exception:
            pass

        self._engine = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)

        self.title = QLabel("Zgodovina samodejnih odzivov")
        self.title.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        layout.addWidget(self.title)

        # Uporabi lahek QAbstractTableModel v QTableView, da zmanjšaš porabo virov
        # in se izogneš ustvarjanju velikega števila elementov QTableWidget.
        self._model = None
        try:
            self._model = None
            layout_view = QTableView(self)
            layout_view.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
            layout_view.setSelectionBehavior(QTableView.SelectRows)
            layout.addWidget(layout_view)
            self._view = layout_view
        except Exception:
            # Rezerva: za združljivost uporabi osnovno tabelo, če QTableView odpove.
            self._view = None

        self._aggregated_counts = {"LOW": 0, "MEDIUM": 0}
        # Čakajoče vrstice se zbirajo iz povratnih klicev in se na časovniku pošljejo v vmesnik.
        self._pending_rows = deque()
        # Največje število vidnih vrstic v tabeli.
        try:
            self._display_limit = int(os.environ.get('NETSENTINEL_RESPONSE_HISTORY_LIMIT', '10'))
        except Exception:
            self._display_limit = 10

        # Celotna zgodovina je zapisana v datoteko kot dodajane vrstice JSON.
        # V vmesniku izriši le prvih N vrstic, da omejiš obremenitev pomnilnika in gradnikov.
        try:
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
            history_dir = os.path.join(base_dir, "data")
            os.makedirs(history_dir, exist_ok=True)
            self._history_file = os.path.join(history_dir, "response_history.log")
        except Exception:
            # Rezerva: uporabi trenutno mapo.
            self._history_file = os.path.abspath("response_history.log")

        # Časovnik za periodično praznjenje čakajočih vrstic v vidno tabelo.
        try:
            from PyQt5.QtCore import QTimer
            self._display_timer = QTimer(self)
            # Uporabi nekoliko daljši interval, da zmanjšaš nihanje vmesnika ob poplavi dogodkov.
            self._display_timer.setInterval(1000)  # 1000ms
            self._display_timer.timeout.connect(self._flush_display)
            self._display_timer.start()
        except Exception:
            self._display_timer = None

        # Izvajalnik zapisovanja za razbremenitev V/I operacij diska.
        try:
            self._writer_executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        except Exception:
            self._writer_executor = None

        # Vidni medpomnilnik, ki ga upravlja model.
        self._visible_rows = deque(maxlen=self._display_limit)
        # Zdaj pripravi model.
        try:
            self._model = ResponseHistoryModel(self._visible_rows, self.COLUMNS, self.FIELD_KEYS, parent=self)
            if getattr(self, "_view", None):
                self._view.setModel(self._model)
        except Exception:
            self._model = None
        # Združljivost: zagotovi atribut table za teste in starejšo kodo.
        try:
            self.table = _TableShim(self._model)
        except Exception:
            self.table = None

    @staticmethod
    def _response_key(resp: object) -> str:
        if isinstance(resp, dict):
            return str(resp.get("response_id") or "")
        return str(getattr(resp, "response_id", "") or "")

    def clear(self):
        if self._model:
            self._visible_rows.clear()
            self._model.beginResetModel()
            self._model.endResetModel()
        else:
            # Rezervna možnost z najboljšim možnim rezultatom.
            try:
                self.table.setRowCount(0)
            except Exception:
                pass

    def set_responses(self, responses: List[object]):
        """Napolni tabelo s seznamom zapisov odzivov.

        Vsak element je lahko podatkovni razred, objekt z atributi ali slovar.
        Podprta polja so: response_id, threat_id, action, target, status, severity,
        triggered_at, executed_at in result.
        """
        # Prednostno naloži celotno zgodovino iz datoteke na disku.
        self.clear()
        try:
            lines = []
            if os.path.exists(self._history_file):
                with open(self._history_file, "r", encoding="utf-8") as fh:
                    lines = fh.read().splitlines()

            # Za prikaz uporabi zadnjih N vnosov.
            if lines:
                selected = []
                seen = set()
                for ln in reversed(lines):
                    try:
                        obj = json.loads(ln)
                    except Exception:
                        continue
                    key = self._response_key(obj)
                    if key and key in seen:
                        continue
                    if key:
                        seen.add(key)
                    selected.append(obj)
                    if len(selected) >= self._display_limit:
                        break
                for obj in reversed(selected):
                    self.add_response(obj)
            else:
                # Rezerva: uporabi podani seznam, kar je uporabno pri testih.
                for resp in responses:
                    self._handle_incoming_response(resp)
        except Exception:
            # Previdna rezervna možnost.
            for resp in responses:
                self._handle_incoming_response(resp)

    def add_response(self, resp: object):
        """Dodaj eno vrstico odziva; sprejme objekt ali slovar."""
        def _get(attr, default=""):
            if isinstance(resp, dict):
                return resp.get(attr, default)
            return getattr(resp, attr, default)

        # Dodaj v vidni medpomnilnik in obvesti model.
        try:
            obj = resp if isinstance(resp, dict) else {
                "response_id": getattr(resp, "response_id", ""),
                "threat_id": getattr(resp, "threat_id", ""),
                "action": getattr(resp, "action", ""),
                "target": getattr(resp, "target", ""),
                "status": getattr(resp, "status", ""),
                "severity": getattr(resp, "severity", ""),
                "triggered_at": getattr(resp, "triggered_at", ""),
                "executed_at": getattr(resp, "executed_at", ""),
                "result": getattr(resp, "result", ""),
            }
            # Dodaj med vidne vrstice; deque ob polni kapaciteti odstrani najstarejšo.
            if self._model:
                try:
                    self._model.append_row(obj)
                except Exception:
                    # Rezerva: neposredno dodajanje in ponastavitev.
                    try:
                        self._visible_rows.append(obj)
                        self._model.beginResetModel()
                        self._model.endResetModel()
                    except Exception:
                        pass
            else:
                try:
                    self._visible_rows.append(obj)
                except Exception:
                    pass
        except Exception:
            # Rezerva: prvotna počasnejša pot.
            try:
                row = self.table.rowCount()
                self.table.insertRow(row)
            except Exception:
                pass

    def _handle_incoming_response(self, resp: object):
        """Določi, ali se vrstica odziva prikaže ali združi."""
        def _get(attr, default=""):
            if isinstance(resp, dict):
                return resp.get(attr, default)
            return getattr(resp, attr, default)

        sev = str(_get("severity", "")).upper()
        # V tabeli obdrži le HIGH in CRITICAL, LOW in MEDIUM pa združi.
        if sev in ("HIGH", "CRITICAL"):
            # Vrstico shrani v medpomnilnik in jo izprazni s časovnikom.
            try:
                # enqueue pending rows for periodic UI update; persist in background
                self._pending_rows.append(resp)
                if self._writer_executor:
                    try:
                        self._writer_executor.submit(self._append_to_history_file, resp)
                    except Exception:
                        # Rezerva: sinhrona obdelava.
                        try:
                            self._append_to_history_file(resp)
                        except Exception:
                            pass
            except Exception:
                # Rezerva: dodaj neposredno.
                self.add_response(resp)
        elif sev == "MEDIUM":
            self._aggregated_counts["MEDIUM"] = self._aggregated_counts.get("MEDIUM", 0) + 1
        else:
            # Privzeto uporabi LOW.
            self._aggregated_counts["LOW"] = self._aggregated_counts.get("LOW", 0) + 1

    def _flush_display(self):
        """Prenesi čakajoče vrstice HIGH/CRITICAL v vidno tabelo in ohrani prvih N."""
        try:
            max_batch = 5
            processed = 0
            # Časovna omejitev prepreči predolgo blokiranje glavne niti.
            import time
            start = time.perf_counter()
            max_time_s = 0.03  # 30ms
            while self._pending_rows and processed < max_batch:
                # Če je časovna omejitev dosežena, končaj prej.
                if (time.perf_counter() - start) > max_time_s:
                    break
                resp = self._pending_rows.popleft()
                # Dodaj v vidni medpomnilnik prek modela.
                try:
                    self.add_response(resp)
                except Exception:
                    pass
                processed += 1

            # Odstrani najstarejše vrstice nad omejitvijo prikaza.
            try:
                # Pogled, ki ga upravlja model, velikost ohranja z deque maxlen.
                pass
            except Exception:
                pass
        except Exception:
            logger.exception("Error flushing response history display")

    def register_engine(self, engine):
        """Poveži primerek ResponseEngine, da se tabela samodejno posodablja.

        Modul mora zagotavljati naslednja atributa oziroma metodi:
          - `responses` (slovar obstoječih odzivov),
          - `register_callback(callable)` za prejem prihodnjih odzivov.
        """
        try:
            # Napolni obstoječo zgodovino.
            # Naloži začetno zgodovino z diska in nato registriraj sprotne povratne klice.
            try:
                # Naloži zadnjih N vnosov v tabelo.
                self.set_responses([])
            except Exception:
                pass

            # Registriraj povratni klic; zapis na disk prepusti izvajalniku in oddaj signal Qt.
            if hasattr(engine, "register_callback"):
                def cb(r):
                    try:
                        self.response_received.emit(r)
                    except Exception:
                        try:
                            self._handle_incoming_response(r)
                        except Exception:
                            pass

                try:
                    engine.register_callback(cb)
                except Exception:
                    try:
                        engine.register_callback(lambda r: self.response_received.emit(r))
                    except Exception:
                        engine.register_callback(self.response_received.emit)

            self._engine = engine
        except Exception as e:
            logger.exception("Failed to register engine: %s", e)

    def _on_response(self, response):
        try:
            self._handle_incoming_response(response)
        except Exception:
            logger.exception("Error adding response to table")

    def _append_to_history_file(self, resp: object):
        """Dodaj predstavitev odziva v obliki vrstice JSON v datoteko zgodovine."""
        try:
            # Pretvori objekte v slovarje, ki jih je mogoče serializirati.
            if isinstance(resp, dict):
                obj = resp
            else:
                # best-effort extraction of known fields
                obj = {}
                for k in [
                    "response_id",
                    "threat_id",
                    "action",
                    "target",
                    "status",
                    "severity",
                    "triggered_at",
                    "executed_at",
                    "result",
                ]:
                    try:
                        obj[k] = getattr(resp, k)
                    except Exception:
                        obj[k] = None

            # Zapiši vrstico.
            with open(self._history_file, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(obj, default=str, ensure_ascii=False) + "\n")
            if os.path.getsize(self._history_file) > self._MAX_HISTORY_FILE_BYTES:
                with open(self._history_file, "rb") as fh:
                    fh.seek(-self._MAX_HISTORY_FILE_BYTES // 2, os.SEEK_END)
                    tail = fh.read().decode("utf-8", errors="ignore")
                tail = tail[tail.find("\n") + 1:] if "\n" in tail else tail
                with open(self._history_file, "w", encoding="utf-8") as fh:
                    fh.write(tail)
        except Exception:
            # Ostani tih; zgodovina je pomožna funkcija.
            logger.exception("Failed to append response to history file")


class ResponseHistoryModel(QAbstractTableModel):
    ACTION_LABELS = {
        "block_ip": "blokada IP",
        "isolate_host": "izolacija gostitelja",
        "rate_limit": "omejitev hitrosti",
        "terminate_flow": "prekinitev toka",
        "quarantine": "karantena",
        "alert": "opozorilo",
        "log": "zapis",
    }

    STATUS_LABELS = {
        "pending": "v teku",
        "running": "teče",
        "completed": "zaključeno",
        "failed": "neuspešno",
        "rolled_back": "povrnjeno",
        "success": "uspešno",
    }

    SEVERITY_LABELS = {
        "CRITICAL": "kritično",
        "HIGH": "visoko",
        "MEDIUM": "srednje",
        "LOW": "nizko",
        "INFO": "informativno",
    }

    def __init__(self, data_deque: deque, columns: List[str], field_keys: List[str], parent=None):
        super().__init__(parent)
        self._data = data_deque
        self._columns = columns
        self._field_keys = field_keys

    def rowCount(self, parent=QModelIndex()):
        return len(self._data)

    def columnCount(self, parent=QModelIndex()):
        return len(self._columns)

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid() or role != Qt.DisplayRole:
            return QVariant()
        try:
            row = list(self._data)[index.row()]
            col = self._field_keys[index.column()]
            value = row.get(col, '') if isinstance(row, dict) else getattr(row, col, '')
            return self._display_value(col, value)
        except Exception:
            return ""

    @classmethod
    def _display_value(cls, key: str, value) -> str:
        raw = getattr(value, "value", value)
        text = str(raw or "")
        lookup = text.upper() if key == "severity" else text.lower()
        if key == "action":
            return cls.ACTION_LABELS.get(lookup, text)
        if key == "status":
            return cls.STATUS_LABELS.get(lookup, text)
        if key == "severity":
            return cls.SEVERITY_LABELS.get(lookup, text)
        if key == "result":
            if text.startswith("Action executed:"):
                action = text.split(":", 1)[1].strip()
                return f"Izvedena akcija: {cls.ACTION_LABELS.get(action, action)}"
            return text.replace("Blocked", "Blokirano").replace("blocked", "blokirano")
        return text

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return QVariant()
        if orientation == Qt.Horizontal:
            try:
                return self._columns[section]
            except Exception:
                return ""
        return QVariant()

    def append_row(self, row_dict: dict):
        """Dodaj vrstico v osnovni deque in oddaj ustrezen
        beginInsertRows/endInsertRows ter odstranjevanje, ko je dosežen maxlen.
        """
        # Če ima deque omejeno dolžino in je poln, najprej odstrani najstarejšo vrstico.
        maxlen = getattr(self._data, 'maxlen', None)
        if maxlen and len(self._data) >= maxlen:
            # Odstrani najstarejšo vrstico (vrstico 0).
            self.beginRemoveRows(QModelIndex(), 0, 0)
            try:
                try:
                    self._data.popleft()
                except Exception:
                    # Rezerva: pretvori v seznam.
                    lst = list(self._data)[1:]
                    self._data.clear()
                    for it in lst:
                        self._data.append(it)
            finally:
                self.endRemoveRows()

        # Zdaj dodaj na konec.
        new_index = len(self._data)
        self.beginInsertRows(QModelIndex(), new_index, new_index)
        try:
            self._data.append(row_dict)
        finally:
            self.endInsertRows()

class _TableShim:
    """Združljivostni vmesnik z minimalnim API-jem `table` za teste.

    Zagotavlja `rowCount()` za združljivost z obstoječimi testi.
    """
    def __init__(self, model: QAbstractTableModel = None):
        self._model = model

    def rowCount(self):
        try:
            if self._model:
                return self._model.rowCount()
        except Exception:
            pass
        return 0

if __name__ == "__main__":
    # Hiter ročni preizkus.
    from PyQt5.QtWidgets import QApplication
    import sys

    app = QApplication(sys.argv)
    w = ResponseHistoryWidget()

    # Ponarejeni odzivi za demonstracijo.
    demo = [
        {
            "response_id": "r-1",
            "threat_id": 1,
            "action": "block_ip",
            "target": "192.168.1.100",
            "status": "SUCCESS",
            "severity": "CRITICAL",
            "triggered_at": "2026-04-08 12:00:00",
            "executed_at": "2026-04-08 12:00:01",
            "result": "Blocked",
        },
    ]
    w.set_responses(demo)
    w.show()
    sys.exit(app.exec_())
