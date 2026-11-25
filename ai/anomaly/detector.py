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
import hashlib
import json
import logging
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import Deque, List, Optional, Tuple

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


BOLIVIA_TZ = timezone(timedelta(hours=-4))   # La Paz, sin horario de verano: determinista en cualquier máquina
VENTANA_CONTEXTO = 60.0                      # segundos de historia para las características de contexto
HORA_NOCTURNA_MAX = 5                        # "horario inusual" = antes de las 05:00 (hora de Bolivia)

TYPE_MAP = {
    "CREDENTIAL_ISSUE": 0, "CREDENTIAL_REVOKE": 1, "CREDENTIAL_VERIFY": 2, "VOTE": 3,
    "DATA_RECORD": 4, "TOKEN_TRANSFER": 5, "SMART_CONTRACT": 6, "ISSUER_REGISTER": 7,
    "TOKEN_MINT": 8,
}


def _hash_payload(payload) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]


class ContextoTx:
    """
    Historia reciente (ventana deslizante) para características que una TX aislada no tiene:
    cuántas TX envió el mismo emisor, cuántas veces se vio el mismo payload y cuántas
    direcciones nuevas aparecieron. `features()` es de sólo lectura; `observe()` registra.
    """

    def __init__(self, ventana: float = VENTANA_CONTEXTO):
        self.ventana = ventana
        self._recientes: Deque[Tuple[float, str, str]] = deque()   # (ts, sender, hash payload)
        self._nuevos: Deque[float] = deque()                       # ts de primeras apariciones
        self._vistos: set = set()

    def _purgar(self, ahora: float) -> None:
        lim = ahora - self.ventana
        while self._recientes and self._recientes[0][0] < lim:
            self._recientes.popleft()
        while self._nuevos and self._nuevos[0] < lim:
            self._nuevos.popleft()

    def features(self, tx: dict) -> List[float]:
        ahora = float(tx.get("timestamp", 0.0))
        self._purgar(ahora)
        sender = tx.get("sender", "")
        h = _hash_payload(tx.get("payload", {}))
        sender_rate = sum(1 for _, s, _ in self._recientes if s == sender)
        repeats = sum(1 for _, _, ph in self._recientes if ph == h)
        es_nuevo = 0 if sender in self._vistos else 1
        return [sender_rate, repeats, len(self._nuevos) + es_nuevo, es_nuevo]

    def observe(self, tx: dict) -> None:
        ahora = float(tx.get("timestamp", 0.0))
        self._purgar(ahora)
        sender = tx.get("sender", "")
        if sender not in self._vistos:
            self._vistos.add(sender)
            self._nuevos.append(ahora)
        self._recientes.append((ahora, sender, _hash_payload(tx.get("payload", {}))))


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
        "sender_rate",          # TX del mismo emisor en los últimos 60 s
        "payload_repeats",      # veces que se vio el mismo payload en los últimos 60 s
        "new_senders_recent",   # direcciones nuevas vistas en los últimos 60 s (incluye ésta)
        "is_new_sender",
    ]
    N_BASE = 5            # las primeras 5 no dependen del contexto (las usa la heurística)
    MIN_SAMPLES = 10
    MODEL_VERSION = 1

    def __init__(self, contamination: float = 0.05, threshold: float = 0.6):
        self.contamination = contamination
        self.threshold = threshold
        self._model = None
        self._scaler = None
        self._training_samples = 0
        self._is_trained = False
        self.context = ContextoTx()

    # ── Características ──────────────────────────────────────────────────────

    @staticmethod
    def base_features(tx: dict) -> List[float]:
        payload_size = len(json.dumps(tx.get("payload", {})))
        fee = int(tx.get("fee", 0))
        dt = datetime.fromtimestamp(float(tx.get("timestamp", time.time())), tz=BOLIVIA_TZ)
        return [payload_size, fee, dt.hour, dt.weekday(), TYPE_MAP.get(tx.get("type", "DATA_RECORD"), 4)]

    def extract_features(self, tx: dict, context: Optional[ContextoTx] = None) -> List[float]:
        ctx = context if context is not None else self.context
        return self.base_features(tx) + ctx.features(tx)

    def observe(self, tx: dict) -> None:
        """Registra una TX admitida en el contexto en vivo (predict nunca muta estado)."""
        self.context.observe(tx)

    @staticmethod
    def _matrix(X) -> np.ndarray:
        """log1p en las magnitudes con cola larga (payload, fee, tasas) para que ningún eje domine."""
        X = np.array(X, dtype=float)
        for j in (0, 1, 5, 6, 7):
            X[:, j] = np.log1p(X[:, j])
        return X

    # ── Entrenamiento ────────────────────────────────────────────────────────

    def fit_features(self, features: List[List[float]], seed: int = 42) -> dict:
        """Entrena sobre una matriz de características ya extraída."""
        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler
        except ImportError:
            logger.error("scikit-learn no instalado. Ejecutar: pip install scikit-learn")
            return {"trained": False, "reason": "missing_dependency"}
        X = self._matrix(features)
        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)
        self._model = IsolationForest(
            contamination=self.contamination, random_state=seed, n_estimators=100)
        self._model.fit(X_scaled)
        self._training_samples = len(features)
        self._is_trained = True
        return {"trained": True, "samples": len(features), "features": self.FEATURE_NAMES,
                "contamination": self.contamination}

    def train(self, transactions: List[dict]) -> dict:
        if len(transactions) < self.MIN_SAMPLES:
            logger.warning("Datos insuficientes para entrenamiento (mínimo 10)")
            return {"trained": False, "reason": "insufficient_data"}
        ctx = ContextoTx()
        features = []
        for tx in sorted(transactions, key=lambda t: t.get("timestamp", 0)):
            features.append(self.extract_features(tx, ctx))
            ctx.observe(tx)
        result = self.fit_features(features)
        if result.get("trained"):
            self.context = ContextoTx()
            logger.info(f"Modelo entrenado con {len(transactions)} transacciones")
        return result

    def scores_from_features(self, features: List[List[float]]) -> np.ndarray:
        """Score de anomalía crudo (mayor = más anómalo) para una matriz de características."""
        return -self._model.score_samples(self._scaler.transform(self._matrix(features)))

    # ── Persistencia (joblib) ────────────────────────────────────────────────

    def save(self, path) -> None:
        import joblib
        if not self._is_trained:
            raise ValueError("No hay modelo entrenado que guardar")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        joblib.dump({
            "version": self.MODEL_VERSION, "features": self.FEATURE_NAMES,
            "model": self._model, "scaler": self._scaler,
            "contamination": self.contamination, "threshold": self.threshold,
            "training_samples": self._training_samples,
        }, tmp)
        tmp.replace(path)

    def load(self, path) -> bool:
        """Carga un modelo guardado. False si no existe o no es compatible (queda la heurística)."""
        import joblib
        path = Path(path)
        if not path.exists():
            return False
        try:
            data = joblib.load(path)
            if data.get("version") != self.MODEL_VERSION or data.get("features") != self.FEATURE_NAMES:
                logger.warning("Modelo guardado incompatible; se ignora")
                return False
            self._model, self._scaler = data["model"], data["scaler"]
            self.contamination = data["contamination"]
            self.threshold = data["threshold"]
            self._training_samples = data["training_samples"]
            self._is_trained = True
            return True
        except Exception:
            logger.exception("No se pudo cargar el modelo de anomalías")
            return False

    # ── Inferencia ───────────────────────────────────────────────────────────

    def predict(self, tx: dict) -> AnomalyReport:
        """Evalúa una TX sin modificar el estado del detector."""
        features = self.extract_features(tx)
        feat_dict = dict(zip(self.FEATURE_NAMES, features))

        if not self._is_trained:
            score = self._heuristic_score(features)
            is_anomaly = score > self.threshold
        else:
            X_scaled = self._scaler.transform(self._matrix([features]))
            raw_score = self._model.score_samples(X_scaled)[0]
            # Isolation Forest: más negativo = más anómalo; normalizar a [0, 1]
            score = max(0.0, min(1.0, (0.5 - raw_score)))
            is_anomaly = bool(self._model.predict(X_scaled)[0] == -1)

        explanation = self._explain(feat_dict, is_anomaly)

        return AnomalyReport(
            entity_id=tx.get("tx_id", "unknown"),
            entity_type="transaction",
            score=round(score, 4),
            is_anomaly=is_anomaly,
            features=feat_dict,
            explanation=explanation,
        )

    @staticmethod
    def _heuristic_score(features: List[float]) -> float:
        """Línea base por reglas fijas; sólo usa las 5 características base."""
        payload_size, fee, hour = features[0], features[1], features[2]
        score = 0.0
        if payload_size > 10000:
            score += 0.4
        if fee > 100:
            score += 0.3
        if hour < HORA_NOCTURNA_MAX:     # antes: `hour > 23`, que nunca se cumplía
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
        if hour < HORA_NOCTURNA_MAX:
            reasons.append(f"Transacción enviada en horario inusual: {int(hour)}:00 hrs")
        if features.get("sender_rate", 0) > 20:
            reasons.append(f"Ráfaga del mismo emisor: {int(features['sender_rate'])} TX en 60 s")
        if features.get("payload_repeats", 0) > 3:
            reasons.append(f"Payload repetido {int(features['payload_repeats'])} veces en 60 s")
        if features.get("new_senders_recent", 0) > 15:
            reasons.append(f"Oleada de direcciones nuevas: {int(features['new_senders_recent'])} en 60 s")
        if not reasons:
            reasons.append("Patrón general inusual detectado por modelo ML")
        return reasons

    def get_stats(self) -> dict:
        return {
            "is_trained": self._is_trained,
            "training_samples": self._training_samples,
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

    def peek_block(self, block: dict) -> AnomalyReport:
        """Evalúa un bloque contra la ventana actual SIN registrarlo (las lecturas no mutan, P1-6)."""
        return self.record_block(block, record=False)

    def record_block(self, block: dict, record: bool = True) -> AnomalyReport:
        header = block.get("header", {})
        timestamp = header.get("timestamp", time.time())
        n_tx = len(block.get("transactions", []))
        difficulty = header.get("difficulty", 4)

        times, sizes = self._block_times, self._block_sizes
        if not record:
            times, sizes = list(times), list(sizes)
        times.append(timestamp)
        sizes.append(n_tx)
        if len(times) > self._window:
            times.pop(0)
            sizes.pop(0)

        score, explanation = self._evaluate(timestamp, n_tx, difficulty, times)

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

    def _evaluate(self, ts: float, n_tx: int, difficulty: int, times: List[float]) -> Tuple[float, List[str]]:
        score = 0.0
        explanation = []

        if len(times) >= 3:
            intervals = [
                times[i] - times[i - 1]
                for i in range(1, len(times))
            ]
            mean_interval = np.mean(intervals)
            std_interval = np.std(intervals)
            last_interval = ts - times[-2] if len(times) >= 2 else mean_interval
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
