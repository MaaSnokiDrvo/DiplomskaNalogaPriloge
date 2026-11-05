"""
Analitični modul groženj
Zgodovinska analiza, trendi in napovedni vpogledi
"""

import logging
from typing import Dict, List
from datetime import datetime, timedelta
from collections import defaultdict
import statistics


class ThreatAnalytics:
    """
    Napredna analitika groženj.
    Trendi, vzorci, napovedi in povezave.
    """

    def __init__(self, db_manager=None):
        """
        Inicializiraj analitični modul.

        Argumenti:
            db_manager: Izbirni upravljalnik baze PostgreSQL.
        """
        self.logger = logging.getLogger(__name__)
        self.db_manager = db_manager

        # Statistika v pomnilniku za analizo v realnem času.
        self.threat_history = defaultdict(list)
        self.ip_threat_map = defaultdict(list)
        self.port_threat_map = defaultdict(list)

    def get_threat_trends(self, hours: int = 24, bucket_size: int = 60) -> List[Dict]:
        """
        Pridobi trende groženj skozi čas.

        Argumenti:
            hours: Časovno okno analize.
            bucket_size: Število minut v skupini.

        Vrne:
            Seznam časovnih skupin s podatki o grožnjah.
        """
        if self.db_manager and self.db_manager.connected:
            # Poizvedi v bazi in poenoti polja.
            timeline = self.db_manager.get_threat_timeline(hours=hours)
            if not timeline and hasattr(self.db_manager, "get_incident_timeline"):
                timeline = self.db_manager.get_incident_timeline(hours=hours)
            normalized = []
            for row in timeline:
                ts = row.get('timestamp') or row.get('hour')
                if isinstance(ts, str):
                    try:
                        ts = datetime.fromisoformat(ts)
                    except Exception:
                        ts = datetime.now()
                normalized.append({
                    'timestamp': ts or datetime.now(),
                    'threat_count': row.get('threat_count', 0),
                    'avg_score': row.get('avg_score', 0.0),
                    'critical_count': row.get('critical_count', 0),
                    'high_count': row.get('high_count', 0),
                })
            return normalized

        return self._calculate_trends_in_memory(hours, bucket_size)

    def _calculate_trends_in_memory(self, hours: int, bucket_size: int) -> List[Dict]:
        """Izračunaj trende iz podatkov v pomnilniku."""
        trends = []

        cutoff = datetime.now() - timedelta(hours=hours)
        bucket_seconds = bucket_size * 60

        # Group threats by bucket
        buckets = defaultdict(list)

        for threat_id, threats in self.threat_history.items():
            for threat in threats:
                if threat['timestamp'] > cutoff:
                    bucket_key = (threat['timestamp'].timestamp() // bucket_seconds) * bucket_seconds
                    buckets[bucket_key].append(threat)

        # Izračunaj statistiko po časovnih skupinah.
        for bucket_key in sorted(buckets.keys(), reverse=True):
            threats = buckets[bucket_key]
            scores = [t.get('threat_score', 0) for t in threats]

            critical = sum(1 for t in threats if t.get('threat_level') == 'CRITICAL')
            high = sum(1 for t in threats if t.get('threat_level') == 'HIGH')

            trends.append({
                'timestamp': datetime.fromtimestamp(bucket_key),
                'threat_count': len(threats),
                'avg_score': statistics.mean(scores) if scores else 0.0,
                'critical_count': critical,
                'high_count': high
            })

        return trends

    def get_threat_distribution(self, hours: int = 24) -> Dict:
        """Pridobi porazdelitev groženj po tipu, vratih in protokolu."""
        if self.db_manager and self.db_manager.connected:
            ports = []
            port_rows = self.db_manager.get_top_dst_ports(hours=hours)
            if not port_rows and hasattr(self.db_manager, "get_top_incident_dst_ports"):
                port_rows = self.db_manager.get_top_incident_dst_ports(hours=hours)
            for row in port_rows:
                ports.append({
                    'port': row.get('port', row.get('dst_port', 0)),
                    'threat_count': row.get('threat_count', 0),
                    'avg_score': row.get('avg_score', 0.0),
                })
            sources = []
            source_rows = self.db_manager.get_top_source_ips(hours=hours)
            if not source_rows and hasattr(self.db_manager, "get_top_incident_source_ips"):
                source_rows = self.db_manager.get_top_incident_source_ips(hours=hours)
            for row in source_rows:
                sources.append({
                    'ip': row.get('ip', row.get('src_ip', 'unknown')),
                    'threat_count': row.get('threat_count', 0),
                    'avg_score': row.get('avg_score', 0.0),
                })
            return {
                'by_port': ports,
                'by_source': sources,
            }

        return self._calculate_distribution_in_memory(hours)

    def _calculate_distribution_in_memory(self, hours: int) -> Dict:
        """Izračunaj porazdelitev iz podatkov v pomnilniku."""
        cutoff = datetime.now() - timedelta(hours=hours)

        port_stats = defaultdict(lambda: {'count': 0, 'total_score': 0})
        ip_stats = defaultdict(lambda: {'count': 0, 'total_score': 0})

        for threat_id, threats in self.threat_history.items():
            for threat in threats:
                if threat['timestamp'] > cutoff:
                    # Statistika vrat.
                    port = threat.get('dst_port', 0)
                    port_stats[port]['count'] += 1
                    port_stats[port]['total_score'] += threat.get('threat_score', 0)

                    # Statistika IP-naslovov.
                    src_ip = threat.get('src_ip', 'unknown')
                    ip_stats[src_ip]['count'] += 1
                    ip_stats[src_ip]['total_score'] += threat.get('threat_score', 0)

        # Razvrsti in oblikuj.
        top_ports = sorted(
            [{'port': p, 'threat_count': s['count'], 'avg_score': s['total_score'] / s['count']}
             for p, s in port_stats.items()],
            key=lambda x: x['threat_count'],
            reverse=True
        )[:10]

        top_ips = sorted(
            [{'ip': ip, 'threat_count': s['count'], 'avg_score': s['total_score'] / s['count']}
             for ip, s in ip_stats.items()],
            key=lambda x: x['threat_count'],
            reverse=True
        )[:10]

        return {
            'by_port': top_ports,
            'by_source': top_ips
        }

    def get_anomaly_patterns(self, hours: int = 24) -> List[Dict]:
        """Zaznaj anomalne vzorce."""
        if self.db_manager and self.db_manager.connected:
            if hasattr(self.db_manager, "get_incident_patterns"):
                patterns = self.db_manager.get_incident_patterns(hours=hours)
                if patterns:
                    return patterns

            distribution = self.get_threat_distribution(hours=hours)
            patterns = []
            for row in distribution.get("by_source", [])[:10]:
                count = int(row.get("threat_count", 0) or 0)
                avg_score = float(row.get("avg_score", 0.0) or 0.0)
                if count >= 2 or avg_score >= 0.7:
                    patterns.append({
                        "type": "source-concentration",
                        "source_ip": str(row.get("ip", row.get("src_ip", "N/A"))),
                        "threat_count": count,
                        "avg_score": avg_score,
                        "severity": "HIGH" if avg_score >= 0.7 else "MEDIUM",
                    })
            return patterns

        cutoff = datetime.now() - timedelta(hours=hours)

        patterns = []

        for threat_id, threats in self.threat_history.items():
            recent = [t for t in threats if t['timestamp'] > cutoff]

            if len(recent) >= 3:
                # Več groženj iz istega vira.
                src_ip = recent[0].get('src_ip')
                avg_score = statistics.mean([t.get('threat_score', 0) for t in recent])

                if avg_score > 0.6:
                    patterns.append({
                        'type': 'multi_threat_source',
                        'source_ip': src_ip,
                        'threat_count': len(recent),
                        'avg_score': avg_score,
                        'severity': 'HIGH'
                    })

        return patterns

    def predict_threat_escalation(self, src_ip: str, window_hours: int = 24) -> Dict:
        """
        Napovej, ali se grožnja z IP-naslova stopnjuje.

        Argumenti:
            src_ip: Izvorni IP-naslov za analizo.
            window_hours: Zgodovinsko časovno okno.

        Vrne:
            Napoved stopnjevanja.
        """
        cutoff = datetime.now() - timedelta(hours=window_hours)

        if src_ip not in self.ip_threat_map:
            return {'escalating': False, 'confidence': 0.0}

        threats = [t for t in self.ip_threat_map[src_ip] if t['timestamp'] > cutoff]

        if len(threats) < 2:
            return {'escalating': False, 'confidence': 0.0}

        # Preveri trend: ali se ocene sčasoma povečujejo?
        sorted_threats = sorted(threats, key=lambda x: x['timestamp'])

        first_half = sorted_threats[:len(sorted_threats)//2]
        second_half = sorted_threats[len(sorted_threats)//2:]

        if first_half and second_half:
            first_avg = statistics.mean([t.get('threat_score', 0) for t in first_half])
            second_avg = statistics.mean([t.get('threat_score', 0) for t in second_half])

            escalation = (second_avg - first_avg) / (first_avg + 0.001)

            return {
                'escalating': escalation > 0.2,
                'confidence': min(abs(escalation), 1.0),
                'trend': 'increasing' if escalation > 0 else 'decreasing',
                'first_avg': first_avg,
                'second_avg': second_avg
            }

        return {'escalating': False, 'confidence': 0.0}

    def get_similar_threats(self, threat_id: int, limit: int = 5) -> List[Dict]:
        """Find similar threats (similar characteristics)"""
        similar = []

        # Poišči grožnjo.
        target = None
        for tid, threats in self.threat_history.items():
            for t in threats:
                if t.get('threat_id') == threat_id:
                    target = t
                    break

        if not target:
            return []

        # Poišči podobne vnose.
        target_port = target.get('dst_port')
        target_score = target.get('threat_score', 0)

        for tid, threats in self.threat_history.items():
            for t in threats:
                if t.get('threat_id') != threat_id:
                    # Podobno, če so vrata enaka in je razlika ocene največ 0,2.
                    if t.get('dst_port') == target_port:
                        score_diff = abs(t.get('threat_score', 0) - target_score)
                        if score_diff < 0.2:
                            similar.append(t)

        return sorted(similar, key=lambda x: x['timestamp'], reverse=True)[:limit]

    def get_risk_score(self) -> float:
        """
        Izračunaj skupno oceno omrežnega tveganja (0–1).
        Temelji na nedavnih grožnjah in njihovi resnosti.
        """
        cutoff = datetime.now() - timedelta(hours=1)

        recent_threats = []
        for threat_id, threats in self.threat_history.items():
            recent_threats.extend([t for t in threats if t['timestamp'] > cutoff])

        if not recent_threats:
            return 0.0

        # Izračunaj tveganje kot uteženo povprečje ocen groženj.
        weights = {
            'CRITICAL': 1.0,
            'HIGH': 0.7,
            'MEDIUM': 0.4,
            'LOW': 0.2
        }

        total_weight = 0.0
        total_score = 0.0

        for threat in recent_threats:
            weight = weights.get(threat.get('threat_level', 'LOW'), 0.2)
            score = threat.get('threat_score', 0.0)
            total_weight += weight
            total_score += (score * weight)

        if total_weight == 0:
            return 0.0

        risk_score = total_score / total_weight / len(recent_threats)
        return min(risk_score, 1.0)

    def add_threat(self, threat: Dict):
        """Dodaj grožnjo v analitični modul."""
        threat_id = threat.get('threat_id', 0)
        src_ip = threat.get('src_ip', 'unknown')

        threat['timestamp'] = datetime.now()

        self.threat_history[threat_id].append(threat)
        self.ip_threat_map[src_ip].append(threat)

        dst_port = threat.get('dst_port', 0)
        if dst_port:
            self.port_threat_map[dst_port].append(threat)

    def get_stats(self, hours: int = 24) -> Dict:
        """Pridobi analitično statistiko."""
        if self.db_manager and self.db_manager.connected:
            if hasattr(self.db_manager, "get_incident_stats"):
                incident_stats = self.db_manager.get_incident_stats(hours=hours)
                if incident_stats.get("total_threats", 0) > 0:
                    return incident_stats

            db_stats = self.db_manager.get_stats()
            if db_stats.get("connected") and db_stats.get("total_threats", 0) > 0:
                distribution = self.get_threat_distribution(hours=24)
                return {
                    "total_threats": int(db_stats.get("total_threats", 0) or 0),
                    "unique_sources": len(distribution.get("by_source", [])),
                    "unique_ports": len(distribution.get("by_port", [])),
                    "risk_score": 0.0,
                    "source": "threats",
                }

        total_threats = sum(len(t) for t in self.threat_history.values())
        unique_sources = len(self.ip_threat_map)
        unique_ports = len(self.port_threat_map)

        return {
            'total_threats': total_threats,
            'unique_sources': unique_sources,
            'unique_ports': unique_ports,
            'risk_score': self.get_risk_score()
        }


if __name__ == "__main__":
    # Preizkusi analitiko.
    logging.basicConfig(level=logging.INFO)

    analytics = ThreatAnalytics()

    # Dodaj testne grožnje.
    for i in range(10):
        threat = {
            'threat_id': i,
            'src_ip': '192.168.1.100' if i < 5 else '10.0.0.1',
            'dst_ip': '8.8.8.8',
            'dst_port': 443,
            'threat_level': 'HIGH' if i % 3 == 0 else 'MEDIUM',
            'threat_score': 0.5 + (i * 0.05)
        }
        analytics.add_threat(threat)

    print("Analytics Stats:", analytics.get_stats())
    print("Risk Score:", analytics.get_risk_score())
    print("Distribution:", analytics.get_threat_distribution(hours=1))

    # Preizkusi napoved stopnjevanja.
    escalation = analytics.predict_threat_escalation('192.168.1.100')
    print("Escalation prediction:", escalation)
