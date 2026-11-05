#!/usr/bin/env python3
"""
Preverjanje in priprava PostgreSQL za demonstracijo NetSentinel IDS.

Demonstracija IDS lahko deluje brez PostgreSQL; ta skript preveri le izbirno
integracijo z bazo podatkov.
"""

from pathlib import Path
import os
import socket
import sys


ROOT = Path(__file__).resolve().parent


def _load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


def _port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def verify_connectivity() -> bool:
    host = os.getenv("POSTGRES_HOST", "localhost")
    port = int(os.getenv("POSTGRES_PORT", "5432"))
    connected = _port_open(host, port)
    print(f"- PostgreSQL: {'running' if connected else 'not reachable'} ({host}:{port})")
    return connected


def setup_postgresql() -> bool:
    try:
        import psycopg2
    except Exception:
        print("- PostgreSQL setup skipped: psycopg2 package is not installed.")
        return False

    pg_host = os.getenv("POSTGRES_HOST", "localhost")
    pg_port = int(os.getenv("POSTGRES_PORT", "5432"))
    pg_user = os.getenv("POSTGRES_USER", "netsentinel_user")
    pg_password = os.getenv("POSTGRES_PASSWORD", "nastavi_lokalno")
    pg_db = os.getenv("POSTGRES_DB", "netsentinel_db")

    try:
        conn = psycopg2.connect(
            host=pg_host,
            port=pg_port,
            user=pg_user,
            password=pg_password,
            database=pg_db,
            connect_timeout=3,
        )
        with conn.cursor() as cursor:
            schema_path = ROOT / "scripts" / "postgres_init.sql"
            if schema_path.exists():
                cursor.execute(schema_path.read_text(encoding="utf-8"))
                conn.commit()

            cursor.execute(
                "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'flows');"
            )
            has_flows = bool(cursor.fetchone()[0])
            cursor.execute(
                "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'incidents');"
            )
            has_incidents = bool(cursor.fetchone()[0])
            incident_count = 0
            latest_incident = None
            if has_incidents:
                cursor.execute("SELECT COUNT(*), MAX(timestamp) FROM incidents;")
                incident_count, latest_incident = cursor.fetchone()
        conn.close()
        print(
            "- PostgreSQL reachable; "
            f"flows table present: {has_flows}; "
            f"incidents table present: {has_incidents}; "
            f"incidents stored: {incident_count}; "
            f"zadnji incident: {latest_incident or 'brez'}"
        )
        return True
    except Exception as exc:
        print(f"- Preverjanje oziroma priprava PostgreSQL ni uspela: {exc}")
        return False


def main() -> int:
    env_file = ROOT / ".env.local"
    _load_env_file(env_file)

    print("Preverjanje PostgreSQL za NetSentinel")
    print(f"Vir nastavitev: {env_file if env_file.exists() else 'samo okolje'}")
    print("PostgreSQL je izbiren; demonstracija IDS lahko deluje brez njega.")

    connected = verify_connectivity()
    configured = setup_postgresql() if connected else False
    print(f"- Baza PostgreSQL: {'dosegljiva' if configured else 'izbirna/nedosegljiva'}")

    print("\nPriporočeni koraki za demonstracijo:")
    print("1. Po potrebi zgradi zaledje: cmake -S . -B build -DNPCAP_SDK_DIR=C:\\dev\\npcap-sdk-1.16")
    print("2. Zaženi celotno demonstracijo: .\\RUN_FULL.bat")
    return 0


if __name__ == "__main__":
    sys.exit(main())
