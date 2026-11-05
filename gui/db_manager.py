"""
Upravljalnik baze PostgreSQL
Trajna hramba groženj, tokov in analitičnih podatkov.
"""

import logging
import os
import threading
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False
    psycopg2 = None


@dataclass
class ThreatRecord:
    """Zapis grožnje v bazi podatkov."""
    threat_id: Optional[int] = None
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    protocol: str = ""
    threat_level: str = ""
    threat_score: float = 0.0
    ml_score: float = 0.0
    anomaly_score: float = 0.0
    behavioral_score: float = 0.0
    indicators: str = ""
    recommendation: str = ""
    timestamp: datetime = None
    resolved: bool = False
    tags: str = ""


class PostgreSQLManager:
    """Upravlja trajno hrambo groženj, shemo baze in analitične poizvedbe."""

    def __init__(self, host: str = None, database: str = None,
                 user: str = None, password: str = None, port: int = None):
        """
        Inicializiraj upravljalnik baze podatkov.

        Argumenti:
            host: Ime gostitelja strežnika PostgreSQL.
            database: Ime baze podatkov.
            user: Uporabnik baze podatkov.
            password: Geslo baze podatkov.
            port: Vrata PostgreSQL.
        """
        self.logger = logging.getLogger(__name__)
        self.host = host or os.getenv("POSTGRES_HOST", "localhost")
        self.database = database or os.getenv("POSTGRES_DB", "netsentinel_db")
        self.user = user or os.getenv("POSTGRES_USER", "netsentinel_user")
        self.password = password or os.getenv("POSTGRES_PASSWORD", "nastavi_lokalno")
        self.port = int(port or os.getenv("POSTGRES_PORT", "5432"))

        self.conn = None
        self.lock = threading.Lock()
        self.connected = False

        if POSTGRES_AVAILABLE:
            self.connect()
            self.create_schema()

    def connect(self) -> bool:
        """Poveži se z bazo PostgreSQL."""
        if not POSTGRES_AVAILABLE:
            self.logger.warning("psycopg2 not installed - database operations unavailable")
            return False

        try:
            self.conn = psycopg2.connect(
                host=self.host,
                database=self.database,
                user=self.user,
                password=self.password,
                port=self.port,
                connect_timeout=1
            )
            self.connected = True
            self.logger.info(f"Connected to PostgreSQL: {self.user}@{self.host}:{self.port}/{self.database}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to connect to PostgreSQL: {e}")
            self.connected = False
            return False

    def create_schema(self):
        """Ustvari shemo baze, če še ne obstaja."""
        if not self.connected:
            return

        try:
            with self.conn.cursor() as cur:
                # Tabela groženj.
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS threats (
                        threat_id SERIAL PRIMARY KEY,
                        src_ip INET,
                        dst_ip INET,
                        dst_port INTEGER,
                        protocol VARCHAR(10),
                        threat_level VARCHAR(20),
                        threat_score REAL,
                        ml_score REAL,
                        anomaly_score REAL,
                        behavioral_score REAL,
                        indicators TEXT,
                        recommendation TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        resolved BOOLEAN DEFAULT FALSE,
                        tags TEXT
                    )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats (timestamp)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_threats_level ON threats (threat_level)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_threats_src_ip ON threats (src_ip)")

                # Tabela tokov.
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS flows (
                        flow_id SERIAL PRIMARY KEY,
                        src_ip INET,
                        dst_ip INET,
                        src_port INTEGER,
                        dst_port INTEGER,
                        protocol VARCHAR(10),
                        bytes_sent BIGINT,
                        bytes_recv BIGINT,
                        packets BIGINT,
                        duration_sec REAL,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        threat_score REAL
                    )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON flows (timestamp)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON flows (src_ip)")

                # Tabela alarmov.
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS alerts (
                        alert_id SERIAL PRIMARY KEY,
                        threat_id INTEGER REFERENCES threats(threat_id),
                        alert_type VARCHAR(50),
                        severity VARCHAR(20),
                        message TEXT,
                        triggered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        acknowledged BOOLEAN DEFAULT FALSE,
                        ack_user VARCHAR(50),
                        ack_time TIMESTAMP
                    )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_triggered_at ON alerts (triggered_at)")

                # Povzetek analitike z urnim združevanjem.
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS analytics_hourly (
                        hour TIMESTAMP PRIMARY KEY,
                        total_flows BIGINT,
                        total_threats INTEGER,
                        critical_count INTEGER,
                        high_count INTEGER,
                        medium_count INTEGER,
                        unique_src_ips INTEGER,
                        unique_dst_ips INTEGER,
                        avg_threat_score REAL
                    )
                """)

                # Arhiv incidentov zaledja C++ za demonstracijo diplomske naloge.
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS incidents (
                        id BIGSERIAL PRIMARY KEY,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        src_ip INET,
                        src_port INTEGER,
                        dst_ip INET,
                        dst_port INTEGER,
                        protocol INTEGER,
                        anomaly_score REAL,
                        incident_type VARCHAR(80),
                        severity VARCHAR(20),
                        description TEXT,
                        status VARCHAR(20) DEFAULT 'open',
                        notes TEXT
                    )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents (timestamp)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents (severity)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_src_ip ON incidents (src_ip)")

                self.conn.commit()
                self.logger.info("Database schema created/verified")
        except Exception as e:
            self.logger.error(f"Failed to create schema: {e}")

    def insert_threat(self, threat: ThreatRecord) -> Optional[int]:
        """
        Vstavi zapis grožnje v bazo podatkov.

        Argumenti:
            threat: Objekt ThreatRecord.

        Vrne:
            ID grožnje ob uspehu, sicer None.
        """
        if not self.connected:
            return None

        try:
            with self.lock:
                with self.conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO threats (
                            src_ip, dst_ip, dst_port, protocol, threat_level,
                            threat_score, ml_score, anomaly_score, behavioral_score,
                            indicators, recommendation, timestamp, tags
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING threat_id
                    """, (
                        threat.src_ip, threat.dst_ip, threat.dst_port, threat.protocol,
                        threat.threat_level, threat.threat_score, threat.ml_score,
                        threat.anomaly_score, threat.behavioral_score,
                        threat.indicators, threat.recommendation,
                        threat.timestamp or datetime.now(), threat.tags
                    ))

                    threat_id = cur.fetchone()[0]
                    self.conn.commit()
                    return threat_id
        except Exception as e:
            self.logger.error(f"Failed to insert threat: {e}")
            self.conn.rollback()
            return None

    def get_threats(self, limit: int = 100, hours: int = 24,
                    threat_level: Optional[str] = None) -> List[Dict]:
        """
        Pridobi zadnje grožnje.

        Argumenti:
            limit: Največje število vrnjenih zapisov.
            hours: Samo grožnje iz zadnjih N ur.
            threat_level: Izbirni filter po ravni grožnje.

        Vrne:
            Seznam zapisov groženj.
        """
        if not self.connected:
            return []

        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                query = """
                    SELECT * FROM threats
                    WHERE timestamp > NOW() - INTERVAL '%s hours'
                """
                params = [hours]

                if threat_level:
                    query += " AND threat_level = %s"
                    params.append(threat_level)

                query += " ORDER BY timestamp DESC LIMIT %s"
                params.append(limit)

                cur.execute(query, params)
                return cur.fetchall()
        except Exception as e:
            self.logger.error(f"Failed to get threats: {e}")
            return []

    def get_threat_count_by_level(self, hours: int = 24) -> Dict:
        """Pridobi število groženj po ravni resnosti."""
        if not self.connected:
            return {}

        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT threat_level, COUNT(*) as count
                    FROM threats
                    WHERE timestamp > NOW() - INTERVAL '%s hours'
                    GROUP BY threat_level
                """, [hours])

                result = {}
                for row in cur.fetchall():
                    result[row['threat_level']] = row['count']
                return result
        except Exception as e:
            self.logger.error(f"Failed to get threat counts: {e}")
            return {}

    def get_top_source_ips(self, limit: int = 10, hours: int = 24) -> List[Dict]:
        """Pridobi najpogostejše izvorne IP-naslove glede na število groženj."""
        if not self.connected:
            return []

        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT src_ip, COUNT(*) as threat_count, AVG(threat_score) as avg_score
                    FROM threats
                    WHERE timestamp > NOW() - INTERVAL '%s hours'
                    GROUP BY src_ip
                    ORDER BY threat_count DESC
                    LIMIT %s
                """, [hours, limit])

                return cur.fetchall()
        except Exception as e:
            self.logger.error(f"Failed to get top IPs: {e}")
            return []

    def get_top_dst_ports(self, limit: int = 10, hours: int = 24) -> List[Dict]:
        """Pridobi najpogosteje napadena vrata glede na število groženj."""
        if not self.connected:
            return []

        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT dst_port, COUNT(*) as threat_count, AVG(threat_score) as avg_score
                    FROM threats
                    WHERE timestamp > NOW() - INTERVAL '%s hours'
                    GROUP BY dst_port
                    ORDER BY threat_count DESC
                    LIMIT %s
                """, [hours, limit])

                return cur.fetchall()
        except Exception as e:
            self.logger.error(f"Failed to get top ports: {e}")
            return []

    def get_threat_timeline(self, hours: int = 24) -> List[Dict]:
        """Pridobi število groženj skozi čas po urnih skupinah."""
        if not self.connected:
            return []

        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        DATE_TRUNC('hour', timestamp) as hour,
                        COUNT(*) as threat_count,
                        AVG(threat_score) as avg_score,
                        SUM(CASE WHEN threat_level = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
                        SUM(CASE WHEN threat_level = 'HIGH' THEN 1 ELSE 0 END) as high_count
                    FROM threats
                    WHERE timestamp > NOW() - INTERVAL '%s hours'
                    GROUP BY DATE_TRUNC('hour', timestamp)
                    ORDER BY hour DESC
                """, [hours])

                return cur.fetchall()
        except Exception as e:
            self.logger.error(f"Failed to get threat timeline: {e}")
            return []

    def get_incident_timeline(self, hours: int = 24) -> List[Dict]:
        """Pridobi število arhiviranih incidentov C++ skozi čas."""
        if not self.connected:
            return []

        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        DATE_TRUNC('hour', timestamp) as hour,
                        COUNT(*) as threat_count,
                        AVG(COALESCE(anomaly_score, 0.0)) as avg_score,
                        SUM(CASE WHEN UPPER(COALESCE(severity, '')) = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
                        SUM(CASE WHEN UPPER(COALESCE(severity, '')) = 'HIGH' THEN 1 ELSE 0 END) as high_count
                    FROM incidents
                    WHERE timestamp > NOW() - (%s * INTERVAL '1 hour')
                    GROUP BY DATE_TRUNC('hour', timestamp)
                    ORDER BY hour DESC
                """, [hours])
                return cur.fetchall()
        except Exception as e:
            self.logger.error(f"Failed to get incident timeline: {e}")
            return []

    def get_top_incident_source_ips(self, limit: int = 10, hours: int = 24) -> List[Dict]:
        """Pridobi najpogostejše izvorne IP-naslove iz arhiva incidentov C++."""
        if not self.connected:
            return []

        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT src_ip, COUNT(*) as threat_count, AVG(COALESCE(anomaly_score, 0.0)) as avg_score
                    FROM incidents
                    WHERE timestamp > NOW() - (%s * INTERVAL '1 hour')
                    GROUP BY src_ip
                    ORDER BY threat_count DESC, avg_score DESC
                    LIMIT %s
                """, [hours, limit])
                return cur.fetchall()
        except Exception as e:
            self.logger.error(f"Failed to get top incident IPs: {e}")
            return []

    def get_top_incident_dst_ports(self, limit: int = 10, hours: int = 24) -> List[Dict]:
        """Pridobi najpogostejša ciljna vrata iz arhiva incidentov C++."""
        if not self.connected:
            return []

        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT dst_port, COUNT(*) as threat_count, AVG(COALESCE(anomaly_score, 0.0)) as avg_score
                    FROM incidents
                    WHERE timestamp > NOW() - (%s * INTERVAL '1 hour')
                    GROUP BY dst_port
                    ORDER BY threat_count DESC, avg_score DESC
                    LIMIT %s
                """, [hours, limit])
                return cur.fetchall()
        except Exception as e:
            self.logger.error(f"Failed to get top incident ports: {e}")
            return []

    def get_incident_patterns(self, hours: int = 24, limit: int = 10) -> List[Dict]:
        """Povzemi ponavljajoče se razrede incidentov iz arhiva C++."""
        if not self.connected:
            return []

        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        COALESCE(incident_type, 'Incident') as incident_type,
                        COALESCE(severity, 'MEDIUM') as severity,
                        COUNT(*) as threat_count,
                        AVG(COALESCE(anomaly_score, 0.0)) as avg_score
                    FROM incidents
                    WHERE timestamp > NOW() - (%s * INTERVAL '1 hour')
                    GROUP BY incident_type, severity
                    ORDER BY threat_count DESC, avg_score DESC
                    LIMIT %s
                """, [hours, limit])
                rows = []
                for row in cur.fetchall():
                    label = f"{row.get('incident_type', 'Incident')} / {row.get('severity', 'MEDIUM')}"
                    rows.append({
                        "type": "incident-summary",
                        "label": label,
                        "source_ip": label,
                        "threat_count": row.get("threat_count", 0),
                        "avg_score": row.get("avg_score", 0.0),
                        "severity": row.get("severity", "MEDIUM"),
                    })
                return rows
        except Exception as e:
            self.logger.error(f"Failed to get incident patterns: {e}")
            return []

    def get_incident_stats(self, hours: int = 24) -> Dict:
        """Pridobi analitično statistiko iz arhiva incidentov C++."""
        if not self.connected:
            return {}

        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        COUNT(*) as total_threats,
                        COUNT(DISTINCT src_ip) as unique_sources,
                        COUNT(DISTINCT dst_port) as unique_ports,
                        AVG(COALESCE(anomaly_score, 0.0)) as risk_score
                    FROM incidents
                    WHERE timestamp > NOW() - (%s * INTERVAL '1 hour')
                """, [hours])
                row = cur.fetchone() or {}
                return {
                    "total_threats": int(row.get("total_threats", 0) or 0),
                    "unique_sources": int(row.get("unique_sources", 0) or 0),
                    "unique_ports": int(row.get("unique_ports", 0) or 0),
                    "risk_score": min(float(row.get("risk_score", 0.0) or 0.0), 1.0),
                    "source": "incidents",
                }
        except Exception as e:
            self.logger.error(f"Failed to get incident stats: {e}")
            return {}

    def resolve_threat(self, threat_id: int, tags: str = "") -> bool:
        """Označi grožnjo kot razrešeno."""
        if not self.connected:
            return False

        try:
            with self.lock:
                with self.conn.cursor() as cur:
                    cur.execute("""
                        UPDATE threats
                        SET resolved = TRUE, tags = %s
                        WHERE threat_id = %s
                    """, [tags, threat_id])

                    self.conn.commit()
                    return cur.rowcount > 0
        except Exception as e:
            self.logger.error(f"Failed to resolve threat: {e}")
            self.conn.rollback()
            return False

    def search_threats(self, query: str, limit: int = 100) -> List[Dict]:
        """Izvedi iskanje po celotnem besedilu groženj."""
        if not self.connected:
            return []

        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Preprosto iskanje LIKE; pozneje je smiselno dodati polno besedilno kazalo PostgreSQL.
                search_pattern = f"%{query}%"
                cur.execute("""
                    SELECT * FROM threats
                    WHERE indicators LIKE %s OR recommendation LIKE %s OR tags LIKE %s
                    ORDER BY timestamp DESC
                    LIMIT %s
                """, [search_pattern, search_pattern, search_pattern, limit])

                return cur.fetchall()
        except Exception as e:
            self.logger.error(f"Failed to search threats: {e}")
            return []

    def get_stats(self) -> Dict:
        """Pridobi statistiko baze podatkov."""
        if not self.connected:
            return {"connected": False}

        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT COUNT(*) as total FROM threats")
                total = cur.fetchone()['total']

                cur.execute("""
                    SELECT COUNT(*) as last_24h FROM threats
                    WHERE timestamp > NOW() - INTERVAL '24 hours'
                """)
                last_24h = cur.fetchone()['last_24h']

                return {
                    "connected": True,
                    "total_threats": total,
                    "threats_24h": last_24h,
                    "database": self.database,
                    "host": self.host
                }
        except Exception as e:
            self.logger.error(f"Failed to get stats: {e}")
            return {"connected": False, "error": str(e)}

    def close(self):
        """Zapri povezavo z bazo podatkov."""
        if self.conn:
            self.conn.close()
            self.connected = False
            self.logger.info("Database connection closed")


if __name__ == "__main__":
    # Preizkusi upravljalnik baze.
    logging.basicConfig(level=logging.INFO)

    # Poskusi vzpostaviti povezavo.
    db = PostgreSQLManager()

    if db.connected:
        print("Database connected successfully")
        print(f"Stats: {db.get_stats()}")

        # Pridobi zadnje grožnje.
        threats = db.get_threats(limit=5)
        print(f"Recent threats: {len(threats)}")

        # Pridobi število groženj.
        counts = db.get_threat_count_by_level()
        print(f"Threat counts by level: {counts}")

        # Pridobi najpogostejše IP-naslove.
        top_ips = db.get_top_source_ips(limit=5)
        print(f"Top source IPs: {top_ips}")
    else:
        print("Could not connect to PostgreSQL")
        print("Note: Database is optional. System works without it.")
