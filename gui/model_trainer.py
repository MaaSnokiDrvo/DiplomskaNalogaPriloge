"""
Učilnik modelov
Uči in ponovno uči modele ML na dejanskih podatkih o grožnjah iz sistema IDS.
"""

import logging
import threading
import os
from typing import Dict, List, Optional, Tuple
import numpy as np

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    torch = None


class NeuralNetworkModel(nn.Module):
    """Preprosta nevronska mreža za zaznavanje groženj."""

    def __init__(self, input_size: int = 10, hidden_size: int = 64):
        """
        Inicializiraj model.

        Argumenti:
            input_size: Število vhodnih značilk.
            hidden_size: Velikost skrite plasti.
        """
        super().__init__()

        self.fc1 = nn.Linear(input_size, hidden_size)
        self.dropout1 = nn.Dropout(0.2)
        self.fc2 = nn.Linear(hidden_size, hidden_size // 2)
        self.dropout2 = nn.Dropout(0.2)
        self.fc3 = nn.Linear(hidden_size // 2, 1)

        self.relu = nn.ReLU()
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        """Izvedi prehod naprej."""
        x = self.relu(self.fc1(x))
        x = self.dropout1(x)
        x = self.relu(self.fc2(x))
        x = self.dropout2(x)
        x = self.sigmoid(self.fc3(x))
        return x


class ModelTrainer:
    """Uči in ponovno uči modele za zaznavanje groženj na podatkih IDS."""

    def __init__(self, device: str = "cpu"):
        """
        Inicializiraj učilnik modela.

        Argumenti:
            device: 'cpu' ali 'cuda'.
        """
        self.logger = logging.getLogger(__name__)
        self.device = device
        self.model = None
        self.lock = threading.Lock()

        if TORCH_AVAILABLE:
            self.model = NeuralNetworkModel(input_size=10).to(device)
            self.logger.info(f"Model trainer initialized on {device}")
        else:
            self.logger.warning("PyTorch not available - model training disabled")

        # Statistika učenja.
        self.training_count = 0
        self.total_samples = 0
        self.model_accuracy = 0.0

    def prepare_training_data(self, threats: List[Dict]) -> Optional[Tuple[np.ndarray, np.ndarray]]:
        """
        Pripravi učne podatke iz zapisov groženj.

        Argumenti:
            threats: Seznam slovarjev z grožnjami.

        Vrne:
            Terko (značilke, oznake).
        """
        if not threats:
            self.logger.warning("No threats provided for training")
            return None

        features = []
        labels = []

        for threat in threats:
            # Pretvori grožnjo v vhodne značilke modela.
            feature_vector = self._extract_features(threat)

            if feature_vector is not None:
                features.append(feature_vector)

                # Oznaka: 1 za grožnjo, 0 za neškodljiv promet.
                label = 1.0 if threat.get('threat_level') in ['CRITICAL', 'HIGH'] else 0.0
                labels.append(label)

        if not features:
            return None

        return np.array(features, dtype=np.float32), np.array(labels, dtype=np.float32)

    def _extract_features(self, threat: Dict) -> Optional[np.ndarray]:
        """Izloči vektor značilk iz grožnje."""
        try:
            features = []

            # Značilke vrat.
            features.append(threat.get('src_port', 0) / 65535.0)
            features.append(threat.get('dst_port', 0) / 65535.0)

            # Količina prometa.
            bytes_sent = float(threat.get('bytes_sent', 0))
            bytes_recv = float(threat.get('bytes_recv', 0))
            features.append(min(bytes_sent / 1e7, 1.0))
            features.append(min(bytes_recv / 1e7, 1.0))
            features.append(min((bytes_sent + bytes_recv) / 1e8, 1.0))

            # Trajanje in hitrost.
            duration = float(threat.get('duration_sec', 1))
            packets = float(threat.get('packets', 1))
            features.append(min(duration / 3600, 1.0))
            features.append(min(packets / 10000, 1.0))
            features.append(min(packets / (duration + 0.1), 1.0))

            # Ocena grožnje iz zgodovinskih podatkov.
            features.append(threat.get('threat_score', 0.0))
            features.append(threat.get('anomaly_score', 0.0))

            return np.array(features, dtype=np.float32)

        except Exception as e:
            self.logger.error(f"Feature extraction failed: {e}")
            return None

    def train(self, threats: List[Dict], epochs: int = 10, batch_size: int = 32,
              learning_rate: float = 0.001) -> Dict:
        """
        Uči model na podatkih o grožnjah.

        Argumenti:
            threats: Seznam zapisov groženj.
            epochs: Število učnih epoh.
            batch_size: Velikost učnega paketa.
            learning_rate: Učna stopnja.

        Vrne:
            Statistiko učenja.
        """
        if not TORCH_AVAILABLE or self.model is None:
            return {'error': 'PyTorch not available'}

        # Pripravi podatke.
        data = self.prepare_training_data(threats)
        if data is None:
            return {'error': 'Could not prepare training data'}

        features, labels = data

        with self.lock:
            try:
                # Pretvori v tenzorje.
                features_tensor = torch.from_numpy(features).to(self.device)
                labels_tensor = torch.from_numpy(labels).reshape(-1, 1).to(self.device)

                # Ustvari podatkovni nalagalnik.
                dataset = TensorDataset(features_tensor, labels_tensor)
                dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

                # Priprava učenja.
                criterion = nn.BCELoss()
                optimizer = optim.Adam(self.model.parameters(), lr=learning_rate)

                # Učna zanka.
                losses = []
                for epoch in range(epochs):
                    epoch_loss = 0.0
                    for batch_features, batch_labels in dataloader:
                        # Prehod naprej.
                        predictions = self.model(batch_features)
                        loss = criterion(predictions, batch_labels)

                        # Povratni prehod.
                        optimizer.zero_grad()
                        loss.backward()
                        optimizer.step()

                        epoch_loss += loss.item()

                    avg_loss = epoch_loss / len(dataloader)
                    losses.append(avg_loss)

                    self.logger.info(f"Epoch {epoch+1}/{epochs} - Loss: {avg_loss:.4f}")

                # Izračunaj natančnost.
                with torch.no_grad():
                    predictions = self.model(features_tensor)
                    predicted_classes = (predictions > 0.5).float()
                    accuracy = (predicted_classes == labels_tensor).float().mean().item()

                self.model_accuracy = accuracy
                self.total_samples += len(threats)
                self.training_count += 1

                stats = {
                    'status': 'success',
                    'samples': len(threats),
                    'epochs': epochs,
                    'final_loss': losses[-1],
                    'accuracy': accuracy,
                    'training_id': self.training_count
                }

                self.logger.info(f"Training complete: {stats}")
                return stats

            except Exception as e:
                self.logger.error(f"Training failed: {e}")
                return {'error': str(e), 'status': 'failed'}

    def evaluate(self, threats: List[Dict]) -> Dict:
        """
        Ovrednoti model na podatkih o grožnjah.

        Argumenti:
            threats: Testni podatki o grožnjah.

        Vrne:
            Metrike vrednotenja.
        """
        if not TORCH_AVAILABLE or self.model is None:
            return {'error': 'Model not available'}

        data = self.prepare_training_data(threats)
        if data is None:
            return {'error': 'Could not prepare evaluation data'}

        features, labels = data

        with self.lock:
            try:
                with torch.no_grad():
                    features_tensor = torch.from_numpy(features).to(self.device)
                    labels_tensor = torch.from_numpy(labels).reshape(-1, 1).to(self.device)

                    predictions = self.model(features_tensor)
                    predicted_classes = (predictions > 0.5).float()

                    # Metrike.
                    accuracy = (predicted_classes == labels_tensor).float().mean().item()

                    # Precision, recall
                    tp = ((predicted_classes == 1) & (labels_tensor == 1)).float().sum().item()
                    fp = ((predicted_classes == 1) & (labels_tensor == 0)).float().sum().item()
                    fn = ((predicted_classes == 0) & (labels_tensor == 1)).float().sum().item()

                    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
                    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
                    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

                    return {
                        'status': 'success',
                        'accuracy': accuracy,
                        'precision': precision,
                        'recall': recall,
                        'f1_score': f1,
                        'samples': len(threats)
                    }

            except Exception as e:
                self.logger.error(f"Evaluation failed: {e}")
                return {'error': str(e), 'status': 'failed'}

    def save_model(self, path: str) -> bool:
        """Shrani model v datoteko."""
        if not TORCH_AVAILABLE or self.model is None:
            return False

        try:
            with self.lock:
                directory = os.path.dirname(path)
                if directory:
                    os.makedirs(directory, exist_ok=True)
                torch.save(self.model.state_dict(), path)
                self.logger.info(f"Model saved to {path}")
                return True
        except Exception as e:
            self.logger.error(f"Failed to save model: {e}")
            return False

    def load_model(self, path: str) -> bool:
        """Naloži model iz datoteke."""
        if not TORCH_AVAILABLE or self.model is None:
            return False

        try:
            with self.lock:
                self.model.load_state_dict(torch.load(path, map_location=self.device))
                self.logger.info(f"Model loaded from {path}")
                return True
        except Exception as e:
            self.logger.error(f"Failed to load model: {e}")
            return False

    def get_stats(self) -> Dict:
        """Pridobi statistiko učilnika."""
        with self.lock:
            return {
                'training_count': self.training_count,
                'total_samples': self.total_samples,
                'model_accuracy': self.model_accuracy,
                'device': self.device,
                'torch_available': TORCH_AVAILABLE
            }


if __name__ == "__main__":
    # Preizkusi učilnik modela.
    logging.basicConfig(level=logging.INFO)

    trainer = ModelTrainer(device="cpu")

    # Ustvari sintetične učne podatke.
    training_threats = [
        {
            'src_port': 54000 + i,
            'dst_port': 443 if i % 2 == 0 else 445,
            'bytes_sent': 100000 if i % 3 == 0 else 50000,
            'bytes_recv': 200000 if i % 3 == 0 else 100000,
            'packets': 1000 if i % 3 == 0 else 500,
            'duration_sec': 60 if i % 3 == 0 else 30,
            'threat_score': 0.8 if i % 2 == 0 else 0.2,
            'anomaly_score': 0.7 if i % 3 == 0 else 0.1,
            'threat_level': 'CRITICAL' if i % 3 == 0 else 'LOW'
        }
        for i in range(50)
    ]

    # Učenje.
    if TORCH_AVAILABLE:
        result = trainer.train(training_threats, epochs=5, batch_size=16)
        print(f"Training result: {result}")

        # Vrednotenje.
        eval_result = trainer.evaluate(training_threats[:10])
        print(f"Evaluation result: {eval_result}")

        # Shranjevanje.
        trainer.save_model("threat_model_trained.pt")

        print(f"Stats: {trainer.get_stats()}")
    else:
        print("PyTorch not available - skipping training test")
