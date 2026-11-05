"""
Podatkovni cevovod
Zbira, pripravlja in upravlja učne podatke iz dejanskih zaznav groženj.
"""

import logging
import threading
from typing import Dict, List
from datetime import datetime, timedelta
from collections import defaultdict
import json


class TrainingDataPoint:
    """Posamezna učna podatkovna točka."""

    def __init__(self, threat: Dict):
        self.threat_id = threat.get('threat_id', 0)
        self.src_ip = threat.get('src_ip', '')
        self.dst_ip = threat.get('dst_ip', '')
        self.src_port = threat.get('src_port', 0)
        self.dst_port = threat.get('dst_port', 0)
        self.protocol = threat.get('protocol', '')
        self.bytes_sent = threat.get('bytes_sent', 0)
        self.bytes_recv = threat.get('bytes_recv', 0)
        self.packets = threat.get('packets', 0)
        self.duration_sec = threat.get('duration_sec', 0)
        self.threat_score = threat.get('threat_score', 0.0)
        self.anomaly_score = threat.get('anomaly_score', 0.0)
        self.threat_level = threat.get('threat_level', 'INFO')
        self.timestamp = datetime.now()
        self.verified = False # Preveril človek.
        self.false_positive = False

    def to_dict(self) -> Dict:
        """Pretvori v slovar."""
        return {
            'threat_id': self.threat_id,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'bytes_sent': self.bytes_sent,
            'bytes_recv': self.bytes_recv,
            'packets': self.packets,
            'duration_sec': self.duration_sec,
            'threat_score': self.threat_score,
            'anomaly_score': self.anomaly_score,
            'threat_level': self.threat_level,
            'timestamp': self.timestamp.isoformat(),
            'verified': self.verified,
            'false_positive': self.false_positive
        }


class DataPipeline:
    """Zbira in upravlja učne podatke iz dejanskih zaznav IDS."""

    def __init__(self, retention_days: int = 30):
        """
        Inicializiraj podatkovni cevovod.

        Argumenti:
            retention_days: Določa, kako dolgo se hranijo učni podatki.
        """
        self.logger = logging.getLogger(__name__)
        self.lock = threading.RLock()

        self.retention_days = retention_days

        # Hramba učnih podatkov.
        self.all_data: Dict[int, TrainingDataPoint] = {}
        self.data_by_threat_level = defaultdict(list)
        self._max_data_points = 50000

        # Statistika podatkov.
        self.total_collected = 0
        self.verified_count = 0
        self.false_positives = 0

    def add_threat(self, threat: Dict) -> bool:
        """
        Dodaj grožnjo v učni cevovod.

        Argumenti:
            threat: Slovar z grožnjo.

        Vrne:
            True, če je bil vnos uspešno dodan.
        """
        try:
            threat_id = threat.get('threat_id', 0)

            with self.lock:
                if threat_id in self.all_data:
                    return False  # Vnos že obstaja.

                data_point = TrainingDataPoint(threat)
                self.all_data[threat_id] = data_point
                self.data_by_threat_level[data_point.threat_level].append(threat_id)
                if len(self.all_data) > self._max_data_points:
                    oldest_id, oldest = min(
                        self.all_data.items(),
                        key=lambda item: item[1].timestamp,
                    )
                    self.data_by_threat_level[oldest.threat_level].remove(oldest_id)
                    del self.all_data[oldest_id]

                self.total_collected += 1

                return True

        except Exception as e:
            self.logger.error(f"Dodajanje grožnje ni uspelo: {e}")
            return False

    def verify_threat(self, threat_id: int) -> bool:
        """Označi grožnjo kot preverjeno s strani človeka."""
        with self.lock:
            if threat_id in self.all_data:
                self.all_data[threat_id].verified = True
                self.verified_count += 1
                self.logger.info(f"Verified threat {threat_id}")
                return True
            return False

    def mark_false_positive(self, threat_id: int) -> bool:
        """Označi grožnjo kot lažni alarm."""
        with self.lock:
            if threat_id in self.all_data:
                self.all_data[threat_id].false_positive = True
                self.false_positives += 1
                self.logger.info(f"Marked threat {threat_id} as false positive")
                return True
            return False

    def get_balanced_training_set(self, size: int = 100, verified_only: bool = True) -> List[Dict]:
        """
        Pridobi uravnotežen učni nabor z enakomerno porazdelitvijo po ravneh grožnje.

        Argumenti:
            size: Število vzorcev.
            verified_only: Vključi samo preverjene grožnje.

        Vrne:
            Seznam slovarjev z grožnjami.
        """
        with self.lock:
            training_set = []

            # Določi število vzorcev po ravneh grožnje.
            threat_levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
            samples_per_level = size // len(threat_levels)

            for level in threat_levels:
                threat_ids = self.data_by_threat_level[level]

                # Filtriranje.
                if verified_only:
                    threat_ids = [tid for tid in threat_ids
                                 if self.all_data[tid].verified and not self.all_data[tid].false_positive]

                # Vzorčenje.
                sampled = threat_ids[:samples_per_level]
                for tid in sampled:
                    training_set.append(self.all_data[tid].to_dict())

            return training_set

    def get_new_samples_since(self, timestamp: datetime, limit: int = None) -> List[Dict]:
        """Pridobi nove podatke o grožnjah od podanega časovnega žiga."""
        with self.lock:
            new_data = []

            for data_point in self.all_data.values():
                if data_point.timestamp > timestamp and not data_point.false_positive:
                    new_data.append(data_point.to_dict())

                if limit and len(new_data) >= limit:
                    break

            return new_data

    def get_hard_examples(self, threshold: float = 0.5, limit: int = 50) -> List[Dict]:
        """
        Pridobi zahtevne primere z napovedmi blizu odločitvene meje.
        Ti primeri so najdragocenejši za učenje.

        Argumenti:
            threshold: Razdalja do meje; najboljši razpon je 0,45–0,55.
            limit: Največje število primerov.

        Vrne:
            Seznam groženj z zahtevnimi primeri.
        """
        with self.lock:
            hard_examples = []

            for data_point in self.all_data.values():
                # Zahteven vzorec, če bi bila napoved blizu meje.
                if abs(data_point.anomaly_score - 0.5) < threshold:
                    hard_examples.append(data_point.to_dict())

                if len(hard_examples) >= limit:
                    break

            return hard_examples

    def cleanup_old_data(self) -> int:
        """Odstrani podatke, starejše od obdobja hrambe."""
        cutoff = datetime.now() - timedelta(days=self.retention_days)

        with self.lock:
            to_delete = []

            for threat_id, data_point in self.all_data.items():
                if data_point.timestamp < cutoff:
                    to_delete.append(threat_id)

            for threat_id in to_delete:
                data_point = self.all_data[threat_id]
                self.data_by_threat_level[data_point.threat_level].remove(threat_id)
                del self.all_data[threat_id]

            self.logger.info(f"Cleaned up {len(to_delete)} old data points")
            return len(to_delete)

    def get_distribution(self) -> Dict:
        """Pridobi porazdelitev podatkov po ravni grožnje."""
        with self.lock:
            return {
                level: len(threat_ids)
                for level, threat_ids in self.data_by_threat_level.items()
            }

    def get_stats(self) -> Dict:
        """Pridobi statistiko podatkovnega cevovoda."""
        with self.lock:
            distribution = self.get_distribution()

            return {
                'total_collected': self.total_collected,
                'total_stored': len(self.all_data),
                'verified_count': self.verified_count,
                'false_positives': self.false_positives,
                'distribution': distribution,
                'retention_days': self.retention_days
            }

    def export_training_set(self, filename: str, verified_only: bool = True) -> bool:
        """Izvozi učni nabor v JSON."""
        try:
            training_set = self.get_balanced_training_set(verified_only=verified_only)

            with open(filename, 'w') as f:
                json.dump(training_set, f, indent=2, default=str)

            self.logger.info(f"{len(training_set)} vzorcev je izvoženih v {filename}")
            return True
        except Exception as e:
            self.logger.error(f"Izvoz ni uspel: {e}")
            return False


class ActiveLearning:
    """Aktivno učenje samodejno izbere najboljše vzorce za ponovno učenje."""

    def __init__(self, data_pipeline: DataPipeline):
        """
        Inicializiraj aktivno učenje.

        Argumenti:
            data_pipeline: Primerek DataPipeline.
        """
        self.logger = logging.getLogger(__name__)
        self.pipeline = data_pipeline

        # Razpored ponovnega učenja.
        self.retrain_threshold_samples = 100 # Ponovno učenje po N novih vzorcih.
        self.retrain_threshold_time = 3600  # Ponovno učenje vsakih N sekund.

        self.last_retrain = datetime.now()
        self.retrains_triggered = 0

    def select_samples_for_retraining(self, num_samples: int = 100) -> List[Dict]:
        """
        Izberi najboljše vzorce za ponovno učenje modela.
        Strategija: uravnoteženi, zahtevni in nedavno preverjeni podatki.

        Argumenti:
            num_samples: Število vzorcev za izbiro.

        Vrne:
            Izbrani vzorci groženj.
        """
        samples = []

        # Šestdeset odstotkov uravnoteženih vzorcev po ravni grožnje.
        balanced = self.pipeline.get_balanced_training_set(
            size=int(num_samples * 0.6),
            verified_only=True
        )
        samples.extend(balanced)

        # Trideset odstotkov zahtevnih primerov blizu odločitvene meje.
        hard = self.pipeline.get_hard_examples(
            threshold=0.1,
            limit=int(num_samples * 0.3)
        )
        samples.extend(hard)

        # Deset odstotkov nedavno preverjenih podatkov.
        recent = self.pipeline.get_new_samples_since(
            datetime.now() - timedelta(hours=24),
            limit=int(num_samples * 0.1)
        )
        samples.extend(recent)

        # Odstrani podvojene vnose.
        seen_ids = set()
        unique_samples = []
        for sample in samples:
            if sample['threat_id'] not in seen_ids:
                unique_samples.append(sample)
                seen_ids.add(sample['threat_id'])

        return unique_samples[:num_samples]

    def should_retrain(self) -> bool:
        """Določi, ali je treba model ponovno naučiti."""
        stats = self.pipeline.get_stats()

        # Preveri časovni prag.
        time_since_retrain = (datetime.now() - self.last_retrain).total_seconds()
        if time_since_retrain > self.retrain_threshold_time:
            return True

        # Preveri prag števila vzorcev.
        if stats['total_collected'] - (self.retrains_triggered * self.retrain_threshold_samples) > self.retrain_threshold_samples:
            return True

        return False

    def trigger_retrain(self) -> Dict:
        """Sproži ponovno učenje modela."""
        self.retrains_triggered += 1
        self.last_retrain = datetime.now()

        # Izberi vzorce.
        samples = self.select_samples_for_retraining(num_samples=200)

        return {
            'status': 'triggered',
            'retrain_id': self.retrains_triggered,
            'samples_selected': len(samples),
            'timestamp': datetime.now().isoformat()
        }

    def get_stats(self) -> Dict:
        """Pridobi statistiko aktivnega učenja."""
        return {
            'retrains_triggered': self.retrains_triggered,
            'last_retrain': self.last_retrain.isoformat(),
            'pipeline_stats': self.pipeline.get_stats()
        }


if __name__ == "__main__":
    # Preizkusi podatkovni cevovod.
    logging.basicConfig(level=logging.INFO)

    pipeline = DataPipeline(retention_days=7)
    active_learning = ActiveLearning(pipeline)

    # Dodaj vzorčne grožnje.
    for i in range(20):
        threat = {
            'threat_id': i,
            'src_ip': f'192.168.1.{i}',
            'dst_ip': '8.8.8.8',
            'src_port': 50000 + i,
            'dst_port': 443 if i % 2 == 0 else 445,
            'protocol': 'TCP',
            'bytes_sent': 100000 * (i + 1),
            'bytes_recv': 200000 * (i + 1),
            'packets': 1000 + i,
            'duration_sec': 60 + i,
            'threat_score': 0.5 + (i * 0.02),
            'anomaly_score': 0.4 + (i * 0.03),
            'threat_level': 'CRITICAL' if i % 5 == 0 else 'HIGH' if i % 3 == 0 else 'MEDIUM'
        }
        pipeline.add_threat(threat)

    # Verify some
    for i in range(10):
        pipeline.verify_threat(i)

    # Nekatere označi kot lažne alarme.
    pipeline.mark_false_positive(15)
    pipeline.mark_false_positive(16)

    print("Pipeline Stats:")
    print(pipeline.get_stats())

    print("\nTraining Set:")
    training_set = pipeline.get_balanced_training_set(size=10)
    print(f"Got {len(training_set)} samples")

    print("\nActive Learning:")
    print(f"Should retrain: {active_learning.should_retrain()}")
    if active_learning.should_retrain():
        retrain_info = active_learning.trigger_retrain()
        print(f"Retrain triggered: {retrain_info}")
