"""
Odzivni modul za avtomatizacijo.
Izvaja blokiranje, izolacijo, omejevanje in odpravljanje posledic.
"""

import logging
import threading
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum


class ResponseAction(Enum):
    """Dejanja avtomatiziranega odziva."""
    ALERT = "alert"
    LOG = "log"
    BLOCK_IP = "block_ip"
    TERMINATE_FLOW = "terminate_flow"
    ISOLATE_HOST = "isolate_host"
    RATE_LIMIT = "rate_limit"
    QUARANTINE = "quarantine"


class ActionStatus(Enum):
    """Stanje dejanja odziva."""
    PENDING = "pending"
    EXECUTING = "executing"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class AutomatedResponse:
    """Zapis avtomatiziranega dejanja odziva."""
    response_id: str
    threat_id: int
    action: ResponseAction
    target: str  # IP, vrata, flow_id in podobno.
    status: ActionStatus
    severity: str
    triggered_at: datetime
    executed_at: Optional[datetime] = None
    result: str = ""
    rollback_after: int = 0  # Sekunde (0 pomeni trajno).
    rolled_back_at: Optional[datetime] = None


class ResponseEngine:
    """
    Sistem za avtomatizirani odziv na grožnje.
    Izvaja odzivna dejanja glede na raven in vrsto grožnje.
    """

    def __init__(self):
        """Inicializiraj odzivni modul."""
        self.logger = logging.getLogger(__name__)
        # Uporabi ponovno vstopno ključavnico, ker jo lahko uporabijo povratni klici ali notranje metode.
        # ista nit lahko ključavnico ponovno uporabi.
        self.lock = threading.RLock()

        # Blokirani IP-naslovi z rokom poteka.
        self.blocked_ips: Dict[str, datetime] = {}

        # Zgodovina odzivov.
        self.responses: Dict[str, AutomatedResponse] = {}
        self._max_response_history = 10000

        # Povratni klici odziva za zunanje sisteme.
        self.response_callbacks: List[Callable] = []

        # Statistika.
        self.actions_executed = 0
        self.actions_failed = 0
        self.blocks_active = 0

    def execute_response(self, threat: Dict) -> Optional[AutomatedResponse]:
        """
        Izvedi avtomatizirani odziv glede na grožnjo.

        Argumenti:
            threat: Slovar z lastnostmi grožnje.

        Vrne:
            AutomatedResponse, če je bilo izvedeno dejanje, sicer None.
        """
        import uuid

        threat_level = threat.get('threat_level', 'LOW')
        threat_score = threat.get('threat_score', 0.0)
        src_ip = threat.get('src_ip', 'neznano')

        # Določi dejanje odziva.
        action = self._determine_action(threat_level, threat_score, threat)

        if action is None:
            return None

        # Ustvari zapis odziva.
        response = AutomatedResponse(
            response_id=str(uuid.uuid4()),
            threat_id=threat.get('threat_id', 0),
            action=action,
            target=src_ip,
            status=ActionStatus.PENDING,
            severity=threat_level,
            triggered_at=datetime.now()
        )

        # Izvedi dejanje; zaščiteno s ponovno vstopno ključavnico.
        with self.lock:
            self._execute_action(response, threat)
            self.responses[response.response_id] = response
            if len(self.responses) > self._max_response_history:
                oldest_id = min(
                    self.responses,
                    key=lambda item: self.responses[item].triggered_at,
                )
                del self.responses[oldest_id]

            if response.status == ActionStatus.SUCCESS:
                self.actions_executed += 1
            else:
                self.actions_failed += 1

        # Sproži povratne klice.
        self._fire_callbacks(response)

        return response

    def _determine_action(self, threat_level: str, threat_score: float, threat: Dict) -> Optional[ResponseAction]:
        """Določi ustrezno dejanje odziva."""
        raw_indicators = threat.get('indicators', '')
        if isinstance(raw_indicators, (list, tuple, set)):
            indicator_text = ' '.join(str(item) for item in raw_indicators).lower()
        elif raw_indicators is None:
            indicator_text = ''
        else:
            indicator_text = str(raw_indicators).lower()

        if threat_level == "CRITICAL":
            # CRITICAL: takoj blokiraj.
            if 'exfiltration' in indicator_text:
                return ResponseAction.ISOLATE_HOST
            else:
                return ResponseAction.BLOCK_IP

        elif threat_level == "HIGH":
            # HIGH: blokiraj ob visoki zanesljivosti.
            if threat_score > 0.8:
                return ResponseAction.BLOCK_IP
            else:
                return ResponseAction.RATE_LIMIT

        elif threat_level == "MEDIUM":
            # MEDIUM: omeji hitrost.
            return ResponseAction.RATE_LIMIT

        elif threat_level == "LOW":
            # LOW: samo zabeleži.
            return ResponseAction.LOG

        return None

    def _execute_action(self, response: AutomatedResponse, threat: Dict):
        """Izvedi dejanje odziva."""
        response.status = ActionStatus.EXECUTING
        response.executed_at = datetime.now()

        try:
            if response.action == ResponseAction.BLOCK_IP:
                success = self._block_ip(response.target, threat)
                response.rollback_after = 3600  # Odblokiraj po eni uri.

            elif response.action == ResponseAction.ISOLATE_HOST:
                success = self._isolate_host(response.target)
                response.rollback_after = 1800 # Odstrani izolacijo po 30 minutah.

            elif response.action == ResponseAction.RATE_LIMIT:
                success = self._rate_limit(response.target, threat)
                response.rollback_after = 600  # Časovna omejitev 10 minut.

            elif response.action == ResponseAction.TERMINATE_FLOW:
                success = self._terminate_flow(response.target)

            elif response.action == ResponseAction.QUARANTINE:
                success = self._quarantine_system(response.target)
                response.rollback_after = 3600

            elif response.action == ResponseAction.LOG:
                success = self._log_threat(response.target, threat)

            else:
                success = False

            response.status = ActionStatus.SUCCESS if success else ActionStatus.FAILED
            action_labels = {
                "alert": "opozorilo",
                "log": "zapis",
                "block_ip": "blokada IP naslova",
                "terminate_flow": "prekinitev toka",
                "isolate_host": "izolacija gostitelja",
                "rate_limit": "omejitev hitrosti",
                "quarantine": "karantena",
            }
            response.result = f"Izvedena akcija: {action_labels.get(response.action.value, response.action.value)}"

            self.logger.info(f"Odziv {response.response_id}: {response.action.value} -> {response.target}")

        except Exception as e:
            response.status = ActionStatus.FAILED
            response.result = str(e)
            self.logger.error(f"Izvedba odziva ni uspela: {e}")

    def _block_ip(self, ip: str, threat: Dict) -> bool:
        """Blokiraj IP-naslov oziroma dodaj pravilo požarnega zidu."""
        try:
            with self.lock:
                self.blocked_ips[ip] = datetime.now() + timedelta(hours=1)
                self.blocks_active += 1

            # Prihodnja izboljšava: pokliči dejanski požarni zid ali nadzorno ravnino EDR.
            self.logger.warning(f"IP-naslov blokiran: {ip}")
            return True
        except Exception as e:
            self.logger.error(f"Blokiranje IP-naslova {ip} ni uspelo: {e}")
            return False

    def _isolate_host(self, ip: str) -> bool:
        """Izoliraj gostitelja iz omrežja."""
        try:
            # Prihodnja izboljšava: onemogoči vmesnik ali premakni gostitelja v izolacijski VLAN.
            self.logger.warning(f"Gostitelj izoliran: {ip}")
            return True
        except Exception as e:
            self.logger.error(f"Izolacija gostitelja {ip} ni uspela: {e}")
            return False

    def _rate_limit(self, ip: str, threat: Dict) -> bool:
        """Omeji promet z danega IP-naslova."""
        try:
            # Prihodnja izboljšava: uporabi pravila omejevanja hitrosti QoS ali SDN.
            self.logger.warning(f"Hitrost prometa omejena: {ip}")
            return True
        except Exception as e:
            self.logger.error(f"Omejevanje hitrosti za {ip} ni uspelo: {e}")
            return False

    def _terminate_flow(self, flow_id: str) -> bool:
        """Prekini omrežni tok."""
        try:
            # Prihodnja izboljšava: pošlji pakete RST ali zapri seje prek omrežne naprave.
            self.logger.warning(f"Tok prekinjen: {flow_id}")
            return True
        except Exception as e:
            self.logger.error(f"Prekinitev toka {flow_id} ni uspela: {e}")
            return False

    def _quarantine_system(self, ip: str) -> bool:
        """Postavi sistem v karanteno oziroma omrežno izolacijo."""
        try:
            # Prihodnja izboljšava: premakni sistem v karantenski VLAN ali blokiraj zunanji promet.
            self.logger.warning(f"Sistem v karanteni: {ip}")
            return True
        except Exception as e:
            self.logger.error(f"Namestitev sistema {ip} v karanteno ni uspela: {e}")
            return False

    def _log_threat(self, target: str, threat: Dict) -> bool:
        """Zabeleži grožnjo za preiskavo."""
        try:
            self.logger.info(f"Grožnja zabeležena: {target} - raven: {threat.get('threat_level')}")
            return True
        except Exception as e:
            self.logger.error(f"Beleženje grožnje ni uspelo: {e}")
            return False

    def rollback_response(self, response_id: str) -> bool:
        """Razveljavi avtomatizirani odziv."""
        with self.lock:
            if response_id not in self.responses:
                return False

            response = self.responses[response_id]

            try:
                if response.action == ResponseAction.BLOCK_IP:
                    del self.blocked_ips[response.target]
                    self.blocks_active -= 1

                response.status = ActionStatus.ROLLED_BACK
                response.rolled_back_at = datetime.now()

                self.logger.info(f"Odziv {response_id} razveljavljen")
                return True

            except Exception as e:
                self.logger.error(f"Razveljavitev odziva {response_id} ni uspela: {e}")
                return False

    def is_ip_blocked(self, ip: str) -> bool:
        """Preveri, ali je IP-naslov trenutno blokiran."""
        with self.lock:
            if ip not in self.blocked_ips:
                return False

            if datetime.now() > self.blocked_ips[ip]:
                # Rok poteka je dosežen.
                del self.blocked_ips[ip]
                self.blocks_active -= 1
                return False

            return True

    def get_blocked_ips(self) -> List[str]:
        """Pridobi seznam trenutno blokiranih IP-naslovov."""
        with self.lock:
            # Počisti potekle blokade.
            expired = [ip for ip, expiry in self.blocked_ips.items() if datetime.now() > expiry]
            for ip in expired:
                del self.blocked_ips[ip]
                self.blocks_active -= 1

            return list(self.blocked_ips.keys())

    def get_blocked_ip_details(self) -> List[Dict]:
        """Pridobi podatke o blokiranih IP-naslovih za tabele vmesnika."""
        with self.lock:
            expired = [ip for ip, expiry in self.blocked_ips.items() if datetime.now() > expiry]
            for ip in expired:
                del self.blocked_ips[ip]
                self.blocks_active = max(0, self.blocks_active - 1)

            rows = []
            for ip, expiry in sorted(self.blocked_ips.items(), key=lambda item: item[1]):
                response = None
                for item in reversed(list(self.responses.values())):
                    if item.target == ip and item.action == ResponseAction.BLOCK_IP:
                        response = item
                        break
                rows.append(
                    {
                        "ip": ip,
                        "blocked_at": response.executed_at if response and response.executed_at else None,
                        "expires_at": expiry,
                        "response_id": response.response_id if response else "",
                        "severity": response.severity if response else "",
                    }
                )
            return rows

    def get_average_response_time_ms(self) -> float:
        """Povprečna zakasnitev med časom sprožitve in izvedbe."""
        with self.lock:
            durations = []
            for response in self.responses.values():
                if response.executed_at and response.triggered_at:
                    durations.append((response.executed_at - response.triggered_at).total_seconds() * 1000.0)
            return sum(durations) / len(durations) if durations else 0.0

    def unblock_ip(self, ip: str) -> bool:
        """Odstrani zapis blokiranega IP-naslova, če obstaja."""
        with self.lock:
            if ip not in self.blocked_ips:
                return False
            del self.blocked_ips[ip]
            self.blocks_active = max(0, self.blocks_active - 1)
            self.logger.info("IP-naslov odblokiran: %s", ip)
            return True

    def register_callback(self, callback: Callable):
        """Registriraj povratni klic za dejanja odziva."""
        self.response_callbacks.append(callback)

    def _fire_callbacks(self, response: AutomatedResponse):
        """Sproži povratne klice odziva."""
        for callback in self.response_callbacks:
            try:
                callback(response)
            except Exception as e:
                self.logger.error(f"Povratni klic odziva ni uspel: {e}")

    def get_stats(self) -> Dict:
        """Pridobi statistiko odzivnega modula."""
        with self.lock:
            return {
                'actions_executed': self.actions_executed,
                'actions_failed': self.actions_failed,
                'blocks_active': self.blocks_active,
                'blocked_ips': len(self.blocked_ips),
                'total_responses': len(self.responses),
                'success_rate': self.actions_executed / max(self.actions_executed + self.actions_failed, 1),
                'avg_response_time_ms': self.get_average_response_time_ms(),
            }

    def export_stats(self) -> str:
        """Izvozi statistiko kot oblikovan niz."""
        stats = self.get_stats()

        lines = [
            "=== Statistika odzivnega modula ===",
            f"Izvedena dejanja: {stats['actions_executed']}",
            f"Neuspešna dejanja: {stats['actions_failed']}",
            f"Stopnja uspešnosti: {stats['success_rate']:.1%}",
            f"Aktivne blokade: {stats['blocks_active']}",
            f"Skupaj odzivov: {stats['total_responses']}"
        ]

        return "\n".join(lines)


if __name__ == "__main__":
    # Preizkusi odzivni modul.
    logging.basicConfig(level=logging.INFO)

    engine = ResponseEngine()

    # Registriraj povratni klic.
    def on_response(response: AutomatedResponse):
        print(f"⚡ Response: {response.action.value} -> {response.target} ({response.status.name})")

    engine.register_callback(on_response)

    # Preizkusi grožnje.
    threats = [
        {
            'threat_id': 1,
            'src_ip': '192.168.1.100',
            'threat_level': 'CRITICAL',
            'threat_score': 0.95,
            'indicators': 'Izvoz podatkov'
        },
        {
            'threat_id': 2,
            'src_ip': '10.0.0.1',
            'threat_level': 'HIGH',
            'threat_score': 0.85,
            'indicators': 'Vrata z zlonamerno programsko opremo'
        },
        {
            'threat_id': 3,
            'src_ip': '172.16.0.5',
            'threat_level': 'MEDIUM',
            'threat_score': 0.55,
            'indicators': 'Pregled vrat'
        }
    ]

    for threat in threats:
        response = engine.execute_response(threat)

    print(f"\nBlokirani IP-naslovi: {engine.get_blocked_ips()}")
    print(f"\n{engine.export_stats()}")
