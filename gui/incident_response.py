"""Varni demonstracijski odzivi brez poseganja v operacijski sistem."""

from typing import Any, Dict


def simulate_response(alert: Dict[str, Any]) -> str:
    """Vrni pojasnilni odziv, ki ne izvede zunanjega dejanja."""
    severity = str(alert.get("severity", "LOW")).upper()
    source = str(alert.get("src_ip", "neznan vir"))
    if severity in {"CRITICAL", "HIGH"}:
        return f"Simulirano: predlagana blokada vira {source} in obvestilo operaterju."
    if severity == "MEDIUM":
        return f"Simulirano: predlagana omejitev vira {source} in podrobnejše beleženje."
    return f"Simulirano: alarm vira {source} je zabeležen brez ukrepa."
