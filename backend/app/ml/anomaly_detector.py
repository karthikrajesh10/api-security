import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pickle
import os
from typing import Optional

MODEL_PATH = os.path.join(os.path.dirname(__file__), "isolation_forest.pkl")
SCALER_PATH = os.path.join(os.path.dirname(__file__), "scaler.pkl")

class AnomalyDetector:
    """
    Isolation Forest based anomaly detector.
    Trained on normal traffic feature vectors.
    Produces anomaly scores between 0.0 (normal) and 1.0 (anomalous).
    """

    def __init__(self):
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.is_trained = False
        self._load()

    def train(self, feature_vectors: list[list[float]]):
        """
        Train the model on a batch of feature vectors.
        Called automatically when enough data is available (min 20 samples).
        """
        if len(feature_vectors) < 20:
            print(f"[AnomalyDetector] Not enough samples ({len(feature_vectors)}), need 20+")
            return False

        X = np.array(feature_vectors)

        # Scale features to zero mean, unit variance
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        # Train Isolation Forest
        # contamination=0.1 means we expect ~10% of traffic to be anomalous
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42
        )
        self.model.fit(X_scaled)
        self.is_trained = True

        # Persist to disk so it survives server restarts
        self._save()
        print(f"[AnomalyDetector] Trained on {len(feature_vectors)} samples ✅")
        return True

    def score(self, feature_vector: list[float]) -> float:
        """
        Score a single request. Returns 0.0–1.0.
        Higher = more anomalous.
        Returns 0.0 if model not trained yet.
        """
        if not self.is_trained:
            return 0.0

        X = np.array([feature_vector])
        X_scaled = self.scaler.transform(X)

        # Isolation Forest returns -1 (anomaly) or 1 (normal)
        # decision_function returns negative scores for anomalies
        raw_score = self.model.decision_function(X_scaled)[0]

        # Convert to 0–1 range where 1 = most anomalous
        # Raw scores typically range from -0.5 to 0.5
        normalized = 1.0 - (raw_score + 0.5)
        return float(max(0.0, min(1.0, normalized)))

    def risk_level(self, score: float) -> str:
        if score >= 0.7:
            return "high"
        elif score >= 0.4:
            return "medium"
        return "low"

    def _save(self):
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(self.model, f)
        with open(SCALER_PATH, "wb") as f:
            pickle.dump(self.scaler, f)

    def _load(self):
        """Load persisted model on startup if it exists."""
        try:
            if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
                with open(MODEL_PATH, "rb") as f:
                    self.model = pickle.load(f)
                with open(SCALER_PATH, "rb") as f:
                    self.scaler = pickle.load(f)
                self.is_trained = True
                print("[AnomalyDetector] Loaded existing model from disk ✅")
        except Exception as e:
            print(f"[AnomalyDetector] Could not load model: {e}")

# Singleton
anomaly_detector = AnomalyDetector()