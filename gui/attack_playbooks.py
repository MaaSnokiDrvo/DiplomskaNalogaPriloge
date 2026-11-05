"""
Ogrodje odzivnih načrtov napadov
Zaporedja avtomatiziranih odzivov za določene vzorce napadov.
"""

import logging
from typing import Dict, List, Callable, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class PlaybookStatus(Enum):
    """Stanje izvedbe odzivnega načrta."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ActionType(Enum):
    """Dejanja avtomatiziranega odziva."""
    # Dejanja blokiranja in izolacije.
    BLOCK_IP = "block_ip"
    UNBLOCK_IP = "unblock_ip"
    ISOLATE_HOST = "isolate_host"
    QUARANTINE_FLOW = "quarantine_flow"

    # Nadzor hitrosti in tokov.
    RATE_LIMIT = "rate_limit"
    TERMINATE_FLOW = "terminate_flow"
    REDIRECT_TRAFFIC = "redirect_traffic"

    # Beleženje in spremljanje.
    ENABLE_DEEP_INSPECTION = "enable_deep_inspection"
    INCREASE_LOGGING = "increase_logging"
    CAPTURE_TRAFFIC = "capture_traffic"

    # Preiskovalna dejanja.
    COLLECT_LOGS = "collect_logs"
    SNAPSHOT_MEMORY = "snapshot_memory"
    EXTRACT_FILES = "extract_files"

    # Obvestila.
    ALERT_SIEM = "alert_siem"
    NOTIFY_SECURITY_TEAM = "notify_security_team"
    ESCALATE_INCIDENT = "escalate_incident"


@dataclass
class PlaybookAction:
    """Posamezno dejanje v odzivnem načrtu."""
    action_id: str
    action_type: ActionType
    parameters: Dict[str, Any] = field(default_factory=dict)
    description: str = ""
    condition: Optional[Callable] = None # Pogojna izvedba.
    timeout_seconds: int = 60
    retry_on_failure: bool = True
    max_retries: int = 3


@dataclass
class PlaybookExecution:
    """Zapis izvedbe odzivnega načrta."""
    execution_id: str
    playbook_id: str
    trigger_event: Dict
    status: PlaybookStatus
    completed_actions: List[str] = field(default_factory=list)
    failed_actions: List[str] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    error_message: str = ""


class AttackPlaybook:
    """Določa zaporedje avtomatiziranih odzivov za določen vzorec napada."""

    def __init__(self, playbook_id: str, name: str, attack_pattern: str, severity: str):
        """
        Inicializiraj odzivni načrt napada.

        Argumenti:
            playbook_id: Enolični identifikator.
            name: Berljivo ime.
            attack_pattern: Vzorec napada, na primer "lateral_movement".
            severity: Resnost napada (CRITICAL, HIGH, MEDIUM).
        """
        self.playbook_id = playbook_id
        self.name = name
        self.attack_pattern = attack_pattern
        self.severity = severity

        self.actions: List[PlaybookAction] = []
        self.enabled = True
        self.created_at = datetime.now()
        self.last_updated = datetime.now()

    def add_action(self, action: PlaybookAction) -> str:
        """Dodaj dejanje v odzivni načrt."""
        self.actions.append(action)
        return action.action_id

    def remove_action(self, action_id: str) -> bool:
        """Odstrani dejanje iz odzivnega načrta."""
        for i, action in enumerate(self.actions):
            if action.action_id == action_id:
                self.actions.pop(i)
                return True
        return False

    def to_dict(self) -> Dict:
        """Pretvori v slovar."""
        return {
            'playbook_id': self.playbook_id,
            'name': self.name,
            'attack_pattern': self.attack_pattern,
            'severity': self.severity,
            'enabled': self.enabled,
            'action_count': len(self.actions),
            'created_at': self.created_at.isoformat()
        }


class PlaybookEngine:
    """Izvaja odzivne načrte kot odgovor na zaznane grožnje."""

    def __init__(self):
        """Inicializiraj modul odzivnih načrtov."""
        self.logger = logging.getLogger(__name__)

        self.playbooks: Dict[str, AttackPlaybook] = {}
        self.execution_history: Dict[str, PlaybookExecution] = {}
        self._max_execution_history = 10000
        self.action_handlers: Dict[ActionType, Callable] = {}

        # Statistika.
        self.total_executions = 0
        self.successful_executions = 0
        self.failed_executions = 0

        self._register_default_handlers()

    def _register_default_handlers(self):
        """Registriraj privzete obravnave dejanj."""
        self.action_handlers[ActionType.BLOCK_IP] = self._handle_block_ip
        self.action_handlers[ActionType.ISOLATE_HOST] = self._handle_isolate_host
        self.action_handlers[ActionType.RATE_LIMIT] = self._handle_rate_limit
        self.action_handlers[ActionType.ALERT_SIEM] = self._handle_alert_siem
        self.action_handlers[ActionType.NOTIFY_SECURITY_TEAM] = self._handle_notify
        self.action_handlers[ActionType.INCREASE_LOGGING] = self._handle_increase_logging
        for action_type in (
            ActionType.UNBLOCK_IP,
            ActionType.QUARANTINE_FLOW,
            ActionType.TERMINATE_FLOW,
            ActionType.REDIRECT_TRAFFIC,
            ActionType.ENABLE_DEEP_INSPECTION,
            ActionType.CAPTURE_TRAFFIC,
            ActionType.COLLECT_LOGS,
            ActionType.SNAPSHOT_MEMORY,
            ActionType.EXTRACT_FILES,
            ActionType.ESCALATE_INCIDENT,
        ):
            self.action_handlers[action_type] = self._make_demo_handler(action_type)

    def _make_demo_handler(self, action_type: ActionType) -> Callable:
        """Vrni varno demonstracijsko obravnavo dejanj, ki zahtevajo zunanje sisteme."""
        def _handler(params: Dict) -> bool:
            self.logger.info("DEMO ACTION %s: %s", action_type.value, params)
            return True
        return _handler

    def register_playbook(self, playbook: AttackPlaybook) -> str:
        """Registriraj odzivni načrt za napad."""
        self.playbooks[playbook.playbook_id] = playbook
        self.logger.info(f"Registered playbook: {playbook.name}")
        return playbook.playbook_id

    def create_default_playbooks(self) -> Dict[str, str]:
        """Ustvari standardne odzivne načrte za pogoste napade."""
        playbook_ids = {}

        lateral = AttackPlaybook(
            "pb_lateral", "Odziv na premik po omrežju",
            "lateral_movement", "CRITICAL"
        )
        lateral.add_action(PlaybookAction(
            "action_1", ActionType.ISOLATE_HOST,
            {"target_ip": "${src_ip}"},
            "Izoliraj kompromitiranega gostitelja"
        ))
        lateral.add_action(PlaybookAction(
            "action_2", ActionType.ENABLE_DEEP_INSPECTION,
            {"target_ip": "${src_ip}"},
            "Vključi okrepljen nadzor"
        ))
        lateral.add_action(PlaybookAction(
            "action_3", ActionType.INCREASE_LOGGING,
            {"level": "DEBUG"},
            "Povečaj podrobnost dnevnika"
        ))
        lateral.add_action(PlaybookAction(
            "action_4", ActionType.ALERT_SIEM,
            {"severity": "CRITICAL"},
            "Obvesti SIEM sistem"
        ))
        playbook_ids["lateral"] = self.register_playbook(lateral)

        portscan = AttackPlaybook(
            "pb_portscan", "Odziv na pregled vrat",
            "port_scanning", "HIGH"
        )
        portscan.add_action(PlaybookAction(
            "action_1", ActionType.BLOCK_IP,
            {"target_ip": "${src_ip}", "duration": 3600},
            "Blokiraj izvor pregledovanja"
        ))
        portscan.add_action(PlaybookAction(
            "action_2", ActionType.RATE_LIMIT,
            {"target_ip": "${src_ip}", "max_connections": 10},
            "Omeji hitrost povezav"
        ))
        portscan.add_action(PlaybookAction(
            "action_3", ActionType.NOTIFY_SECURITY_TEAM,
            {"priority": "HIGH"},
            "Obvesti varnostno ekipo"
        ))
        playbook_ids["portscan"] = self.register_playbook(portscan)

        c2 = AttackPlaybook(
            "pb_c2", "Odziv na C2 komunikacijo",
            "c2_beacon", "CRITICAL"
        )
        c2.add_action(PlaybookAction(
            "action_1", ActionType.ISOLATE_HOST,
            {"target_ip": "${src_ip}"},
            "Izoliraj okuženega gostitelja"
        ))
        c2.add_action(PlaybookAction(
            "action_2", ActionType.BLOCK_IP,
            {"target_ip": "${dst_ip}", "duration": 86400},
            "Blokiraj C2 strežnik (24 h)"
        ))
        c2.add_action(PlaybookAction(
            "action_3", ActionType.SNAPSHOT_MEMORY,
            {"target_ip": "${src_ip}"},
            "Zajemi pomnilnik za analizo"
        ))
        c2.add_action(PlaybookAction(
            "action_4", ActionType.ESCALATE_INCIDENT,
            {"severity": "CRITICAL", "team": "IR"},
            "Predaj v obravnavo incidenta"
        ))
        playbook_ids["c2"] = self.register_playbook(c2)

        ddos = AttackPlaybook(
            "pb_ddos", "Odziv na DDoS",
            "ddos_attack", "CRITICAL"
        )
        ddos.add_action(PlaybookAction(
            "action_1", ActionType.BLOCK_IP,
            {"target_ip": "${src_ip}", "duration": 7200},
            "Blokiraj napadalne izvore"
        ))
        ddos.add_action(PlaybookAction(
            "action_2", ActionType.RATE_LIMIT,
            {"target_ip": "${dst_ip}", "max_connections": 1000},
            "Vključi strožjo omejitev hitrosti"
        ))
        ddos.add_action(PlaybookAction(
            "action_3", ActionType.ALERT_SIEM,
            {"severity": "CRITICAL"},
            "Takoj obvesti SIEM"
        ))
        playbook_ids["ddos"] = self.register_playbook(ddos)

        exfil = AttackPlaybook(
            "pb_exfil", "Odziv na odtekanje podatkov",
            "exfiltration", "CRITICAL"
        )
        exfil.add_action(PlaybookAction(
            "action_1", ActionType.QUARANTINE_FLOW,
            {"src_ip": "${src_ip}", "dst_ip": "${dst_ip}"},
            "Premakni sumljiv tok v karanteno"
        ))
        exfil.add_action(PlaybookAction(
            "action_2", ActionType.CAPTURE_TRAFFIC,
            {"src_ip": "${src_ip}", "duration": 300},
            "Zajemi promet za forenzični pregled"
        ))
        exfil.add_action(PlaybookAction(
            "action_3", ActionType.ISOLATE_HOST,
            {"target_ip": "${src_ip}"},
            "Izoliraj izvornega gostitelja"
        ))
        exfil.add_action(PlaybookAction(
            "action_4", ActionType.ESCALATE_INCIDENT,
            {"severity": "CRITICAL", "team": "FORENSICS"},
            "Predaj v forenzično analizo"
        ))
        playbook_ids["exfil"] = self.register_playbook(exfil)

        self.logger.info(f"Created {len(playbook_ids)} default playbooks")
        return playbook_ids

    def execute_playbook(self, playbook_id: str, trigger_event: Dict) -> Optional[str]:
        """
        Izvedi odzivni načrt za zaznano grožnjo.

        Argumenti:
            playbook_id: Odzivni načrt za izvedbo.
            trigger_event: Dogodek grožnje, ki je sprožil odzivni načrt.

        Vrne:
            ID izvedbe.
        """
        if playbook_id not in self.playbooks:
            self.logger.error(f"Playbook not found: {playbook_id}")
            return None

        playbook = self.playbooks[playbook_id]
        if not playbook.enabled:
            self.logger.warning(f"Playbook disabled: {playbook.name}")
            return None

        # Ustvari zapis izvedbe.
        execution_id = f"exec_{datetime.now().timestamp()}"
        execution = PlaybookExecution(
            execution_id=execution_id,
            playbook_id=playbook_id,
            trigger_event=trigger_event,
            status=PlaybookStatus.RUNNING,
            start_time=datetime.now()
        )

        self.logger.info(f"Executing playbook: {playbook.name}")

        # Izvedi dejanja po vrsti.
        for action in playbook.actions:
            success = self._execute_action(action, trigger_event)

            if success:
                execution.completed_actions.append(action.action_id)
            else:
                execution.failed_actions.append(action.action_id)

                if not action.retry_on_failure:
                    execution.status = PlaybookStatus.FAILED
                    break

        # Označi izvedbo kot zaključeno.
        execution.end_time = datetime.now()
        if execution.failed_actions:
            execution.status = PlaybookStatus.FAILED
            self.failed_executions += 1
        else:
            execution.status = PlaybookStatus.COMPLETED
            self.successful_executions += 1

        self.total_executions += 1
        self.execution_history[execution_id] = execution
        if len(self.execution_history) > self._max_execution_history:
            oldest_id = min(
                self.execution_history,
                key=lambda item: self.execution_history[item].start_time,
            )
            del self.execution_history[oldest_id]

        duration = (execution.end_time - execution.start_time).total_seconds()
        self.logger.info(
            f"Playbook execution completed: {execution.status.value} "
            f"({duration:.1f}s, {len(execution.completed_actions)}/{len(playbook.actions)} actions)"
        )

        return execution_id

    def _execute_action(self, action: PlaybookAction, context: Dict) -> bool:
        """Izvedi posamezno dejanje."""
        try:
            # Preveri pogoj.
            if action.condition and not action.condition(context):
                self.logger.debug(f"Action {action.action_id} condition not met, skipping")
                return True

            # Razreši parametre in zamenjaj spremenljivke, kot je ${src_ip}.
            params = self._resolve_parameters(action.parameters, context)

            # Pridobi obravnavo dejanja.
            if action.action_type not in self.action_handlers:
                self.logger.warning(f"No handler for action type: {action.action_type}")
                return False

            handler = self.action_handlers[action.action_type]

            # Izvedi dejanje.
            self.logger.info(f"Executing action: {action.description} ({action.action_type.value})")
            result = handler(params)

            return result

        except Exception as e:
            self.logger.error(f"Action execution failed: {e}")
            return False

    def _resolve_parameters(self, params: Dict, context: Dict) -> Dict:
        """Razreši spremenljivke parametrov iz konteksta."""
        resolved = {}
        for key, value in params.items():
            if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
                var_name = value[2:-1]
                resolved[key] = context.get(var_name, value)
            else:
                resolved[key] = value
        return resolved

    # Obravnave dejanj.
    def _handle_block_ip(self, params: Dict) -> bool:
        """Blokiraj IP-naslov."""
        ip = params.get('target_ip')
        duration = params.get('duration', 3600)
        self.logger.info(f"BLOCKING IP: {ip} for {duration}s")
        return True

    def _handle_isolate_host(self, params: Dict) -> bool:
        """Izoliraj gostitelja iz omrežja."""
        ip = params.get('target_ip')
        self.logger.info(f"ISOLATING HOST: {ip}")
        return True

    def _handle_rate_limit(self, params: Dict) -> bool:
        """Uporabi omejevanje hitrosti."""
        ip = params.get('target_ip')
        max_conn = params.get('max_connections', 100)
        self.logger.info(f"RATE LIMITING: {ip} to {max_conn} connections")
        return True

    def _handle_alert_siem(self, params: Dict) -> bool:
        """Pošlji alarm sistemu SIEM."""
        severity = params.get('severity')
        self.logger.info(f"ALERTING SIEM: Severity={severity}")
        return True

    def _handle_notify(self, params: Dict) -> bool:
        """Obvesti varnostno ekipo."""
        priority = params.get('priority', 'HIGH')
        self.logger.info(f"NOTIFYING SECURITY TEAM: Priority={priority}")
        return True

    def _handle_increase_logging(self, params: Dict) -> bool:
        """Povečaj raven beleženja."""
        level = params.get('level', 'DEBUG')
        self.logger.info(f"INCREASING LOGGING: Level={level}")
        return True

    def get_execution_history(self, limit: int = 20) -> List[Dict]:
        """Pridobi nedavno zgodovino izvedb."""
        histories = sorted(
            self.execution_history.values(),
            key=lambda x: x.start_time,
            reverse=True
        )[:limit]

        return [
            {
                'execution_id': h.execution_id,
                'playbook_id': h.playbook_id,
                'status': h.status.value,
                'completed_actions': len(h.completed_actions),
                'failed_actions': len(h.failed_actions),
                'duration': (h.end_time - h.start_time).total_seconds() if h.end_time else 0
            }
            for h in histories
        ]

    def get_statistics(self) -> Dict:
        """Pridobi statistiko odzivnih načrtov."""
        return {
            'total_playbooks': len(self.playbooks),
            'total_executions': self.total_executions,
            'successful_executions': self.successful_executions,
            'failed_executions': self.failed_executions,
            'success_rate': self.successful_executions / max(1, self.total_executions)
        }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    engine = PlaybookEngine()
    engine.create_default_playbooks()

    # Simuliraj izvedbo.
    trigger = {
        'src_ip': '192.168.1.100',
        'dst_ip': '8.8.8.8',
        'threat_type': 'lateral_movement'
    }

    exec_id = engine.execute_playbook('pb_lateral', trigger)
    print(f"\nExecution ID: {exec_id}")
    print(f"Statistics: {engine.get_statistics()}")
