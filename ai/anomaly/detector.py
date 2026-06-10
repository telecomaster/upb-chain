"""
UPB-Chain — Detector de Anomalías con Machine Learning
Universidad Privada Boliviana · Carrera de Ingeniería en IA

Detecta transacciones y bloques anómalos usando Isolation Forest,
un algoritmo de aprendizaje no supervisado basado en árboles de aislamiento.

Principio (Liu et al., 2008):
    Las anomalías son "pocas y distintas" → se aíslan en menos particiones
    que los puntos normales. El score de anomalía es inversamente proporcional
    a la profundidad promedio del árbol de aislamiento.

    Score s(x) = 2^{-E[h(x)] / c(n)}
    donde h(x) = profundidad de aislamiento, c(n) = normalización.

Pipeline:
    1. Feature extraction → O(1) por TX (5 características numéricas)
    2. StandardScaler → media 0, std 1 sobre datos de entrenamiento
    3. IsolationForest → O(n log n) entrenamiento, O(log n) inferencia
    4. Explicación heurística → reglas interpretables en lenguaje natural

Características de entrada:
    x₁ = tamaño del payload (bytes)   — ataque: spam de datos
    x₂ = tarifa (fee)                 — ataque: lavado de dinero
    x₃ = hora del día (0–23)          — ataque: actividad nocturna
    x₄ = día de la semana (0–6)       — patrón temporal
    x₅ = tipo de TX codificado (0–6)  — distribución esperada

Rendimiento esperado en RPi5 (16 GB RAM):
    Entrenamiento (1000 TXs): < 30 s
    Inferencia por TX:        < 5 ms
    RAM durante entrenamiento: < 200 MB

Referencias:
    Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). Isolation Forest. ICDM'08.
    Chandola, V., Banerjee, A., & Kumar, V. (2009). Anomaly detection: A survey. ACM CSUR.
"""
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

import numpy as np

logger = logging.getLogger("upb_chain.ai.anomaly")


@dataclass
class AnomalyReport:
    entity_id: str
    entity_type: str  # "transaction" | "block" | "node"
    score: float       # 0 = normal, 1 = muy anómalo
    is_anomaly: bool
    features: dict
    explanation: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "score": self.score,
            "is_anomaly": self.is_anomaly,
            "features": self.features,
            "explanation": self.explanation,
            "timestamp": self.timestamp,
        }


class TransactionAnomalyDetector:
    """
    Isolation Forest para detección de transacciones anómalas.
    Se entrena sobre el historial de la cadena y detecta outliers en tiempo real.
    """

    FEATURE_NAMES = [
        "payload_size",
        "fee",
        "hour_of_day",
        "day_of_week",
        "tx_type_encoded",
    ]

    def __init__(self, contamination: float = 0.05, threshold: float = 0.6):
        self.contamination = contamination
        self.threshold = threshold
        self._model = None
        self._scaler = None
        self._training_data: List[List[float]] = []
        self._is_trained = False

    def extract_features(self, tx: dict) -> List[float]:
        import json as _json
        payload_size = len(_json.dumps(tx.get("payload", {})))
        fee = float(tx.get("fee", 0.0))
        ts = tx.get("timestamp", time.time())
        from datetime import datetime
        dt = datetime.fromtimestamp(ts)
        hour = dt.hour
        dow = dt.weekday()
        type_map = {
            "CREDENTIAL_ISSUE": 0,
            "CREDENTIAL_REVOKE": 1,
            "CREDENTIAL_VERIFY": 2,
            "VOTE": 3,
            "DATA_RECORD": 4,
            "TOKEN_TRANSFER": 5,
            "SMART_CONTRACT": 6,
        }
        tx_type = type_map.get(tx.get("type", "DATA_RECORD"), 4)
        return [payload_size, fee, hour, dow, tx_type]

    def train(self, transactions: List[dict]) -> dict:
        if len(transactions) < 10:
            logger.warning("Datos insuficientes para entrenamiento (mínimo 10)")
            return {"trained": False, "reason": "insufficient_data"}

        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler
        except ImportError:
            logger.error("scikit-learn no instalado. Ejecutar: pip install scikit-learn")
            return {"trained": False, "reason": "missing_dependency"}

        features = [self.extract_features(tx) for tx in transactions]
        X = np.array(features)

        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)

        self._model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100,
        )
        self._model.fit(X_scaled)
        self._training_data = features
        self._is_trained = True

        logger.info(f"Modelo entrenado con {len(transactions)} transacciones")
        return {
            "trained": True,
            "samples": len(transactions),
            "features": self.FEATURE_NAMES,
            "contamination": self.contamination,
        }

    def predict(self, tx: dict) -> AnomalyReport:
        features = self.extract_features(tx)
        feat_dict = dict(zip(self.FEATURE_NAMES, features))

        if not self._is_trained:
            score = self._heuristic_score(features)
            is_anomaly = score > self.threshold
        else:
            X = np.array([features])
            X_scaled = self._scaler.transform(X)
            raw_score = self._model.score_samples(X_scaled)[0]
            # Isolation Forest: más negativo = más anómalo; normalizar a [0, 1]
            score = max(0.0, min(1.0, (0.5 - raw_score)))
            is_anomaly = self._model.predict(X_scaled)[0] == -1

        explanation = self._explain(feat_dict, is_anomaly)

        return AnomalyReport(
            entity_id=tx.get("tx_id", "unknown"),
            entity_type="transaction",
            score=round(score, 4),
            is_anomaly=is_anomaly,
            features=feat_dict,
            explanation=explanation,
        )

    def _heuristic_score(self, features: List[float]) -> float:
        payload_size, fee, hour, dow, tx_type = features
        score = 0.0
        if payload_size > 10000:
            score += 0.4
        if fee > 100:
            score += 0.3
        if hour < 2 or hour > 23:
            score += 0.1
        return min(score, 1.0)

    def _explain(self, features: dict, is_anomaly: bool) -> List[str]:
        reasons = []
        if not is_anomaly:
            return ["Transacción dentro de parámetros normales"]
        if features.get("payload_size", 0) > 5000:
            reasons.append(f"Tamaño de payload inusualmente grande: {features['payload_size']} bytes")
        if features.get("fee", 0) > 50:
            reasons.append(f"Tarifa elevada: {features['fee']}")
        hour = features.get("hour_of_day", 12)
        if hour < 3:
            reasons.append(f"Transacción enviada en horario inusual: {hour}:00 hrs")
        if not reasons:
            reasons.append("Patrón general inusual detectado por modelo ML")
        return reasons

    def get_stats(self) -> dict:
        return {
            "is_trained": self._is_trained,
            "training_samples": len(self._training_data),
            "threshold": self.threshold,
            "contamination": self.contamination,
            "features": self.FEATURE_NAMES,
        }


class BlockAnomalyDetector:
    """Detecta bloques con tiempos de minado, dificultades o tamaños anómalos."""

    def __init__(self, window: int = 20):
        self._window = window
        self._block_times: List[float] = []
        self._block_sizes: List[int] = []

    def record_block(self, block: dict) -> AnomalyReport:
        header = block.get("header", {})
        timestamp = header.get("timestamp", time.time())
        n_tx = len(block.get("transactions", []))
        difficulty = header.get("difficulty", 4)

        self._block_times.append(timestamp)
        self._block_sizes.append(n_tx)

        if len(self._block_times) > self._window:
            self._block_times.pop(0)
            self._block_sizes.pop(0)

        score, explanation = self._evaluate(timestamp, n_tx, difficulty)

        return AnomalyReport(
            entity_id=block.get("hash", "")[:16],
            entity_type="block",
            score=score,
            is_anomaly=score > 0.7,
            features={
                "n_transactions": n_tx,
                "difficulty": difficulty,
                "timestamp": timestamp,
            },
            explanation=explanation,
        )

    def _evaluate(self, ts: float, n_tx: int, difficulty: int) -> Tuple[float, List[str]]:
        score = 0.0
        explanation = []

        if len(self._block_times) >= 3:
            intervals = [
                self._block_times[i] - self._block_times[i - 1]
                for i in range(1, len(self._block_times))
            ]
            mean_interval = np.mean(intervals)
            std_interval = np.std(intervals)
            last_interval = ts - self._block_times[-2] if len(self._block_times) >= 2 else mean_interval
            if std_interval > 0 and abs(last_interval - mean_interval) > 3 * std_interval:
                score += 0.5
                explanation.append(f"Intervalo de bloque anómalo: {last_interval:.1f}s (media={mean_interval:.1f}s)")

        if n_tx == 0:
            score += 0.2
            explanation.append("Bloque vacío (posible minado estratégico)")
        elif n_tx > 200:
            score += 0.3
            explanation.append(f"Bloque con {n_tx} transacciones inusualmente lleno")

        if not explanation:
            explanation.append("Bloque dentro de parámetros normales")

        return min(score, 1.0), explanation
