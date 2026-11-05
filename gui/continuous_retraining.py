"""
Razporejevalnik ponovnega učenja
Samodejno ponovno nauči model ML, ko prispejo novi podatki o grožnjah.
"""

import logging
import threading
import time
from typing import Dict, Optional, Callable
from datetime import datetime
from enum import Enum
import json

from model_trainer import ModelTrainer
from data_pipeline import DataPipeline, ActiveLearning


class RetrainStatus(Enum):
    """Stanje ponovnega učenja."""
    IDLE = "idle"
    PREPARING = "preparing"
    TRAINING = "training"
    EVALUATING = "evaluating"
    SAVING = "saving"
    COMPLETED = "completed"
    FAILED = "failed"


class RetainMetrics:
    """Metrike posamezne seje ponovnega učenja."""

    def __init__(self):
        self.start_time = datetime.now()
        self.end_time = None
        self.status = RetrainStatus.IDLE

        self.samples_used = 0
        self.epochs_run = 0

        # Učne metrike.
        self.train_loss = 0.0
        self.train_accuracy = 0.0

        # Metrike vrednotenja.
        self.eval_accuracy = 0.0
        self.eval_precision = 0.0
        self.eval_recall = 0.0
        self.eval_f1 = 0.0

        # Izboljšanje.
        self.accuracy_improvement = 0.0
        self.f1_improvement = 0.0
        self.error_message = ""

    def to_dict(self) -> Dict:
        """Pretvori v slovar."""
        return {
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_sec': (self.end_time - self.start_time).total_seconds() if self.end_time else None,
            'status': self.status.value,
            'samples_used': self.samples_used,
            'epochs_run': self.epochs_run,
            'train_loss': self.train_loss,
            'train_accuracy': self.train_accuracy,
            'eval_accuracy': self.eval_accuracy,
            'eval_precision': self.eval_precision,
            'eval_recall': self.eval_recall,
            'eval_f1': self.eval_f1,
            'accuracy_improvement': self.accuracy_improvement,
            'f1_improvement': self.f1_improvement,
            'error_message': self.error_message
        }


class ContinuousRetrainingScheduler:
    """Neprekinjeno ponovno uči model ob prihodu novih podatkov o grožnjah."""

    def __init__(self,
                 model_trainer: ModelTrainer,
                 data_pipeline: DataPipeline,
                 active_learning: ActiveLearning,
                 check_interval: int = 60):
        """
        Inicializiraj razporejevalnik neprekinjenega ponovnega učenja.

        Argumenti:
            model_trainer: Primerek ModelTrainer.
            data_pipeline: Primerek DataPipeline.
            active_learning: Primerek ActiveLearning.
            check_interval: Preverjanje potrebe po ponovnem učenju vsakih N sekund.
        """
        self.logger = logging.getLogger(__name__)

        self.trainer = model_trainer
        self.pipeline = data_pipeline
        self.active_learning = active_learning
        self.check_interval = check_interval

        # Stanje razporejevalnika.
        self.running = False
        self.thread = None
        self.lock = threading.RLock()

        # Metrike.
        self.retraining_history: Dict[int, RetainMetrics] = {}
        self.retrain_counter = 0
        self.baseline_metrics = {
            'accuracy': 0.0,
            'f1': 0.0
        }
        # Predpomnjeni posnetki preprečijo blokiranje vmesnika.
        self._last_status: Dict = {
            'running': False,
            'retrain_counter': 0,
            'baseline_metrics': self.baseline_metrics,
            'active_learning_stats': {}
        }
        self._last_history: list = []
        self._last_stats: Dict = {
            'scheduler_running': False,
            'total_retrains': 0,
            'successful_retrains': 0,
            'failed_retrains': 0,
            'total_training_time': 0.0,
            'avg_eval_accuracy': 0.0,
            'baseline_metrics': self.baseline_metrics,
            'check_interval': self.check_interval
        }

        # Povratni klici.
        self.on_retrain_start: Optional[Callable] = None
        self.on_retrain_complete: Optional[Callable] = None
        self.on_retrain_failed: Optional[Callable] = None

    def start(self) -> bool:
        """Zaženi razporejevalnik ponovnega učenja."""
        if self.running:
            return False

        with self.lock:
            self.running = True
            self.thread = threading.Thread(target=self._scheduler_loop, daemon=True)
            self.thread.start()

        self.logger.info("Continuous retraining scheduler started")
        self._update_snapshots()
        return True

    def stop(self) -> bool:
        """Ustavi razporejevalnik ponovnega učenja."""
        if not self.running:
            return False

        with self.lock:
            self.running = False

        if self.thread:
            self.thread.join(timeout=10)

        self.logger.info("Continuous retraining scheduler stopped")
        self._update_snapshots()
        return True

    def _scheduler_loop(self):
        """Glavna zanka razporejevalnika."""
        while self.running:
            try:
                # Preveri, ali je potrebno ponovno učenje.
                if self.active_learning.should_retrain():
                    self._perform_retrain()

                # Počakaj do naslednjega preverjanja.
                time.sleep(self.check_interval)

            except Exception as e:
                self.logger.error(f"Scheduler error: {e}")
                time.sleep(self.check_interval)

    def _perform_retrain(self):
        """Izvedi ponovno učenje modela."""
        with self.lock:
            self.retrain_counter += 1
            retrain_id = self.retrain_counter

        metrics = RetainMetrics()
        metrics.status = RetrainStatus.PREPARING

        self.retraining_history[retrain_id] = metrics

        try:
            # Povratni klic.
            if self.on_retrain_start:
                self.on_retrain_start(retrain_id)

            self.logger.info(f"Starting retrain #{retrain_id}")

            # 1. Izberi učne vzorce.
            metrics.status = RetrainStatus.PREPARING
            samples = self.active_learning.select_samples_for_retraining(num_samples=200)
            metrics.samples_used = len(samples)

            if len(samples) < 50:
                self.logger.warning(f"Too few samples ({len(samples)}), skipping retrain")
                metrics.status = RetrainStatus.FAILED
                metrics.end_time = datetime.now()
                metrics.error_message = f"Too few selected samples for retraining ({len(samples)}/50)"
                self._update_snapshots()
                return

            # 2. Nauči model.
            metrics.status = RetrainStatus.TRAINING
            train_metrics = self.trainer.train(samples, epochs=10, batch_size=32)

            if train_metrics:
                metrics.train_loss = train_metrics.get('loss', 0.0)
                metrics.train_accuracy = train_metrics.get('accuracy', 0.0)
                metrics.epochs_run = 10

            # 3. Ovrednoti model.
            metrics.status = RetrainStatus.EVALUATING
            eval_metrics = self.trainer.evaluate(samples)

            if eval_metrics:
                metrics.eval_accuracy = eval_metrics.get('accuracy', 0.0)
                metrics.eval_precision = eval_metrics.get('precision', 0.0)
                metrics.eval_recall = eval_metrics.get('recall', 0.0)
                metrics.eval_f1 = eval_metrics.get('f1', eval_metrics.get('f1_score', 0.0))

                # Izračunaj izboljšanje.
                metrics.accuracy_improvement = metrics.eval_accuracy - self.baseline_metrics['accuracy']
                metrics.f1_improvement = metrics.eval_f1 - self.baseline_metrics['f1']

                # Posodobi osnovno stanje.
                if metrics.eval_accuracy > self.baseline_metrics['accuracy']:
                    self.baseline_metrics['accuracy'] = metrics.eval_accuracy
                if metrics.eval_f1 > self.baseline_metrics['f1']:
                    self.baseline_metrics['f1'] = metrics.eval_f1

            # 4. Shrani model.
            metrics.status = RetrainStatus.SAVING
            model_path = f"models/trained_model_retrain_{self.retrain_counter}.pt"
            self.trainer.save_model(model_path)

            # Označi kot zaključeno.
            metrics.status = RetrainStatus.COMPLETED
            metrics.end_time = datetime.now()

            duration = (metrics.end_time - metrics.start_time).total_seconds()
            self.logger.info(
                f"Retrain #{retrain_id} completed in {duration:.1f}s: "
                f"samples={metrics.samples_used}, "
                f"accuracy={metrics.eval_accuracy:.3f}, "
                f"f1={metrics.eval_f1:.3f}"
            )

            # Povratni klic.
            if self.on_retrain_complete:
                self.on_retrain_complete(retrain_id, metrics)
            self._update_snapshots()

        except Exception as e:
            metrics.status = RetrainStatus.FAILED
            metrics.end_time = datetime.now()
            metrics.error_message = str(e)

            self.logger.error(f"Ponovno učenje #{retrain_id} ni uspelo: {e}")

            if self.on_retrain_failed:
                self.on_retrain_failed(retrain_id, str(e))
            self._update_snapshots()

    def _update_snapshots(self) -> None:
        """Posodobi predpomnjene posnetke za neblokirajoče branje vmesnika."""
        with self.lock:
            self._last_status = {
                'running': self.running,
                'retrain_counter': self.retrain_counter,
                'baseline_metrics': self.baseline_metrics,
                'active_learning_stats': self.active_learning.get_stats()
            }
            recent_ids = sorted(self.retraining_history.keys())[-100:]
            self._last_history = [
                self.retraining_history[rid].to_dict()
                for rid in recent_ids
            ]
            successful = sum(1 for h in self._last_history if h['status'] == 'completed')
            failed = sum(1 for h in self._last_history if h['status'] == 'failed')
            total_duration = sum(h['duration_sec'] or 0 for h in self._last_history)
            avg_accuracy = sum(h['eval_accuracy'] for h in self._last_history) / len(self._last_history) if self._last_history else 0
            self._last_stats = {
                'scheduler_running': self.running,
                'total_retrains': self.retrain_counter,
                'successful_retrains': successful,
                'failed_retrains': failed,
                'total_training_time': total_duration,
                'avg_eval_accuracy': avg_accuracy,
                'baseline_metrics': self.baseline_metrics,
                'check_interval': self.check_interval
            }

    def get_current_status(self) -> Dict:
        """Pridobi trenutno stanje razporejevalnika."""
        if not self.lock.acquire(blocking=False):
            return self._last_status
        try:
            status = {
                'running': self.running,
                'retrain_counter': self.retrain_counter,
                'baseline_metrics': self.baseline_metrics,
                'active_learning_stats': self.active_learning.get_stats()
            }
            self._last_status = status
            return status
        finally:
            self.lock.release()

    def get_retrain_history(self, limit: int = 10) -> list:
        """Pridobi nedavno zgodovino ponovnega učenja."""
        if not self.lock.acquire(blocking=False):
            return self._last_history[-limit:]
        try:
            recent_ids = sorted(self.retraining_history.keys())[-limit:]
            history = [
                self.retraining_history[rid].to_dict()
                for rid in recent_ids
            ]
            self._last_history = history
            return history
        finally:
            self.lock.release()

    def get_retrain_metrics(self, retrain_id: int) -> Optional[Dict]:
        """Pridobi metrike določene seje ponovnega učenja."""
        with self.lock:
            if retrain_id in self.retraining_history:
                return self.retraining_history[retrain_id].to_dict()
            return None

    def set_retrain_thresholds(self,
                              samples_threshold: int = 100,
                              time_threshold: int = 3600):
        """
        Prilagodi pragova ponovnega učenja.

        Argumenti:
            samples_threshold: Število novih vzorcev za sprožitev ponovnega učenja.
            time_threshold: Število sekund med samodejnimi ponovnimi učenji.
        """
        self.active_learning.retrain_threshold_samples = samples_threshold
        self.active_learning.retrain_threshold_time = time_threshold
        self.logger.info(f"Retrain thresholds set: samples={samples_threshold}, time={time_threshold}s")

    def manual_retrain(self) -> int:
        """Ročno sproži ponovno učenje."""
        self._perform_retrain()
        return self.retrain_counter

    def export_history(self, filename: str) -> bool:
        """Izvozi zgodovino ponovnega učenja v JSON."""
        try:
            with self.lock:
                history = {
                    'total_retrains': self.retrain_counter,
                    'baseline_metrics': self.baseline_metrics,
                    'retraining_sessions': [
                        self.retraining_history[rid].to_dict()
                        for rid in sorted(self.retraining_history.keys())
                    ]
                }

            with open(filename, 'w') as f:
                json.dump(history, f, indent=2, default=str)

            self.logger.info(f"Zgodovina ponovnega učenja je izvožena v {filename}")
            return True

        except Exception as e:
            self.logger.error(f"Izvoz zgodovine ni uspel: {e}")
            return False

    def get_stats(self) -> Dict:
        """Pridobi celovito statistiko."""
        if not self.lock.acquire(blocking=False):
            return self._last_stats
        try:
            recent_ids = sorted(self.retraining_history.keys())[-100:]
            history_list = [
                self.retraining_history[rid].to_dict()
                for rid in recent_ids
            ]
            successful = sum(1 for h in history_list if h['status'] == 'completed')
            failed = sum(1 for h in history_list if h['status'] == 'failed')
            total_duration = sum(h['duration_sec'] or 0 for h in history_list)
            avg_accuracy = sum(h['eval_accuracy'] for h in history_list) / len(history_list) if history_list else 0
            stats = {
                'scheduler_running': self.running,
                'total_retrains': self.retrain_counter,
                'successful_retrains': successful,
                'failed_retrains': failed,
                'total_training_time': total_duration,
                'avg_eval_accuracy': avg_accuracy,
                'baseline_metrics': self.baseline_metrics,
                'check_interval': self.check_interval
            }
            self._last_stats = stats
            return stats
        finally:
            self.lock.release()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("Continuous retraining scheduler module")
