"""
Monitor de seguridad en tiempo real para UPB-Chain.
Detecta patrones anómalos en la red: reorganizaciones, spamming de transacciones,
nodos maliciosos y cambios bruscos de dificultad.
"""
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Deque, Dict, List, Optional

logger = logging.getLogger("upb_chain.security.monitor")


class AlertLevel(str, Enum):
    INFO     = "INFO"
    WARNING  = "WARNING"
    CRITICAL = "CRITICAL"


@dataclass
class SecurityAlert:
    level: AlertLevel
    event_type: str
    message: str
    timestamp: float = field(default_factory=time.time)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "level": self.level,
            "event_type": self.event_type,
            "message": self.message,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


class SecurityMonitor:
    TX_RATE_WINDOW   = 60    # segundos para ventana de tasa de TX
    TX_RATE_LIMIT    = 100   # TX por ventana por dirección
    REORG_THRESHOLD  = 3     # bloques reorganizados = alerta crítica
    DIFF_DELTA_PCT   = 50    # % cambio de dificultad = sospechoso

    # Mapeo event_type → categoría para get_alert_categories()
    _CATEGORY_MAP: Dict[str, str] = {
        "CHAIN_REORG":    "consensus",
        "INVALID_BLOCK":  "network",
        "UNKNOWN_PEER":   "network",
        "TX_RATE_LIMIT":  "application",
        "HIGH_FEE":       "application",
        "DIFFICULTY_SPIKE": "consensus",
        "ORPHAN_BLOCK":   "consensus",
    }
    # Prioridad numérica para comparar niveles de alerta
    _LEVEL_PRIORITY: Dict[str, int] = {
        AlertLevel.INFO: 0,
        AlertLevel.WARNING: 1,
        AlertLevel.CRITICAL: 2,
    }

    def __init__(self, alert_callback: Optional[Callable[[SecurityAlert], None]] = None):
        self._alerts: List[SecurityAlert] = []
        self._alert_callback = alert_callback

        # Estado para detección
        self._tx_timestamps: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=1000))
        self._block_times: Deque[float] = deque(maxlen=100)
        self._difficulties: Deque[int] = deque(maxlen=20)
        self._suspicious_addresses: Dict[str, int] = defaultdict(int)
        self._reorg_count = 0
        self._orphan_count = 0

        # Buffer global de eventos TX: (timestamp, sender, is_anomaly)
        # para cálculo de estadísticas de ventana deslizante
        self._all_tx_events: Deque[tuple] = deque(maxlen=50_000)

        # Historial de fees para cálculo de percentil 95
        self._fee_history: Deque[float] = deque(maxlen=10_000)

    # ── Eventos de entrada ────────────────────────────────────────────────────

    def on_transaction(self, tx: dict) -> None:
        sender = tx.get("sender", "")
        now = time.time()

        self._tx_timestamps[sender].append(now)
        window_start = now - self.TX_RATE_WINDOW
        recent = [t for t in self._tx_timestamps[sender] if t >= window_start]
        self._tx_timestamps[sender] = deque(recent, maxlen=1000)

        # Registrar fee en historial para cálculo de percentil
        fee = tx.get("fee", 0.0)
        if isinstance(fee, (int, float)) and fee >= 0:
            self._fee_history.append(float(fee))

        is_anomaly = len(recent) > self.TX_RATE_LIMIT
        # Registrar en buffer global para get_rolling_stats()
        self._all_tx_events.append((now, sender, is_anomaly))

        if is_anomaly:
            self._suspicious_addresses[sender] += 1
            self._fire(SecurityAlert(
                level=AlertLevel.WARNING if self._suspicious_addresses[sender] < 5 else AlertLevel.CRITICAL,
                event_type="TX_RATE_LIMIT",
                message=f"Dirección {sender[:16]}… enviando {len(recent)} TX en {self.TX_RATE_WINDOW}s",
                metadata={"sender": sender, "tx_count": len(recent), "offenses": self._suspicious_addresses[sender]},
            ))

    def on_block(self, block: dict) -> None:
        header = block.get("header", {})
        now = time.time()
        self._block_times.append(now)
        difficulty = header.get("difficulty", 0)
        self._difficulties.append(difficulty)

        if len(self._difficulties) >= 3:
            prev_diff = self._difficulties[-2]
            if prev_diff and abs(difficulty - prev_diff) / prev_diff * 100 > self.DIFF_DELTA_PCT:
                self._fire(SecurityAlert(
                    level=AlertLevel.WARNING,
                    event_type="DIFFICULTY_SPIKE",
                    message=f"Cambio brusco de dificultad: {prev_diff} → {difficulty}",
                    metadata={"previous": prev_diff, "current": difficulty},
                ))

    def on_chain_reorg(self, depth: int) -> None:
        self._reorg_count += 1
        level = AlertLevel.CRITICAL if depth >= self.REORG_THRESHOLD else AlertLevel.WARNING
        self._fire(SecurityAlert(
            level=level,
            event_type="CHAIN_REORG",
            message=f"Reorganización de cadena detectada: profundidad={depth} bloques",
            metadata={"depth": depth, "total_reorgs": self._reorg_count},
        ))

    def on_invalid_block(self, reason: str, node_id: str) -> None:
        self._fire(SecurityAlert(
            level=AlertLevel.WARNING,
            event_type="INVALID_BLOCK",
            message=f"Bloque inválido recibido de {node_id}: {reason}",
            metadata={"node_id": node_id, "reason": reason},
        ))

    def on_unknown_peer(self, peer_address: str) -> None:
        self._fire(SecurityAlert(
            level=AlertLevel.INFO,
            event_type="UNKNOWN_PEER",
            message=f"Nuevo par no registrado intenta conectarse: {peer_address}",
            metadata={"peer": peer_address},
        ))

    # ── Consultas ─────────────────────────────────────────────────────────────

    def get_alerts(
        self,
        level: Optional[AlertLevel] = None,
        limit: int = 50,
    ) -> List[dict]:
        alerts = self._alerts
        if level:
            alerts = [a for a in alerts if a.level == level]
        return [a.to_dict() for a in alerts[-limit:]]

    def get_threat_summary(self) -> dict:
        critical = sum(1 for a in self._alerts if a.level == AlertLevel.CRITICAL)
        warnings = sum(1 for a in self._alerts if a.level == AlertLevel.WARNING)
        suspicious = {k: v for k, v in self._suspicious_addresses.items() if v >= 3}
        block_rate = self._compute_block_rate()

        threat_level = "BAJO"
        if critical > 0:
            threat_level = "CRÍTICO"
        elif warnings > 5 or len(suspicious) > 2:
            threat_level = "MEDIO"

        return {
            "threat_level": threat_level,
            "total_alerts": len(self._alerts),
            "critical_alerts": critical,
            "warning_alerts": warnings,
            "suspicious_addresses": suspicious,
            "chain_reorgs": self._reorg_count,
            "avg_block_rate_per_min": block_rate,
        }

    def on_orphan_block(self, block_hash: str, reason: str) -> None:
        """
        Alerta cuando un bloque válido no puede conectarse a la cadena actual.

        Los bloques huérfanos frecuentes pueden indicar:
          - Latencia de red elevada entre nodos.
          - Un intento de ataque del 51 % con reorganizaciones en curso.
          - Mineros mal sincronizados publicando sobre bloques obsoletos.

        Args:
            block_hash: Hash del bloque huérfano.
            reason:     Razón por la que no pudo conectarse (ej. "parent not found").
        """
        self._orphan_count += 1
        level = AlertLevel.CRITICAL if self._orphan_count >= 3 else AlertLevel.WARNING
        self._fire(SecurityAlert(
            level=level,
            event_type="ORPHAN_BLOCK",
            message=(
                f"Bloque huérfano detectado (#{self._orphan_count}): "
                f"{block_hash[:16]}… — {reason}"
            ),
            metadata={
                "block_hash":    block_hash,
                "reason":        reason,
                "total_orphans": self._orphan_count,
            },
        ))

    def on_high_fee_transaction(self, tx: dict, percentile_95: float) -> None:
        """
        Alerta cuando una TX tiene fee superior al percentil 95 del historial.

        Fees anómalamente altas pueden indicar:
          - Un atacante intentando priorizar transacciones maliciosas.
          - Error de configuración del cliente que envía fees excesivas.
          - Intento de incentivo para que mineros incluyan una TX específica.

        Args:
            tx:            Diccionario de la transacción con al menos 'sender' y 'fee'.
            percentile_95: Valor del percentil 95 de fees históricas (calculado externamente
                           o mediante compute_fee_percentile()).
        """
        sender = tx.get("sender", "unknown")
        fee    = tx.get("fee", 0.0)

        # Actualizar historial interno
        if isinstance(fee, (int, float)) and fee >= 0:
            self._fee_history.append(float(fee))

        ratio = fee / percentile_95 if percentile_95 > 0 else 0.0
        level = AlertLevel.CRITICAL if ratio >= 5.0 else AlertLevel.WARNING

        self._fire(SecurityAlert(
            level=level,
            event_type="HIGH_FEE",
            message=(
                f"Fee anómala detectada: {fee} "
                f"({ratio:.1f}× el percentil 95 = {percentile_95}). "
                f"Emisor: {sender[:16]}…"
            ),
            metadata={
                "sender":        sender,
                "fee":           fee,
                "percentile_95": percentile_95,
                "fee_ratio":     round(ratio, 2),
            },
        ))

    def compute_fee_percentile(self, percentile: float = 95.0) -> float:
        """
        Calcula el percentil indicado del historial de fees.

        Args:
            percentile: Percentil a calcular (0–100). Por defecto 95.

        Returns:
            Valor de fee en el percentil indicado, o 0.0 si no hay datos.
        """
        if not self._fee_history:
            return 0.0
        sorted_fees = sorted(self._fee_history)
        idx = max(0, int(len(sorted_fees) * percentile / 100) - 1)
        return sorted_fees[idx]

    def get_rolling_stats(self, window_minutes: int = 5) -> dict:
        """
        Retorna estadísticas de la ventana de tiempo más reciente.

        Args:
            window_minutes: Tamaño de la ventana en minutos (por defecto 5).

        Returns:
            Diccionario con:
              tx_rate_per_minute:    tasa de TXs en los últimos N minutos.
              alert_rate_per_minute: alertas generadas en la ventana.
              unique_senders:        número de emisores únicos.
              anomaly_ratio:         proporción de TXs marcadas como anómalas.
              total_tx_in_window:    conteo de TXs en la ventana.
              total_alerts_in_window: conteo de alertas en la ventana.
        """
        now          = time.time()
        window_s     = window_minutes * 60
        window_start = now - window_s

        # Filtrar eventos dentro de la ventana
        recent_tx = [
            (ts, sender, anom)
            for ts, sender, anom in self._all_tx_events
            if ts >= window_start
        ]
        recent_alerts = [a for a in self._alerts if a.timestamp >= window_start]

        tx_count    = len(recent_tx)
        window_mins = max(window_minutes, 1)

        unique_senders = len({sender for _, sender, _ in recent_tx})
        anomaly_count  = sum(1 for _, _, anom in recent_tx if anom)
        anomaly_ratio  = anomaly_count / max(tx_count, 1)

        return {
            "window_minutes":        window_minutes,
            "tx_rate_per_minute":    round(tx_count / window_mins, 2),
            "alert_rate_per_minute": round(len(recent_alerts) / window_mins, 2),
            "unique_senders":        unique_senders,
            "anomaly_ratio":         round(anomaly_ratio, 4),
            "total_tx_in_window":    tx_count,
            "total_alerts_in_window": len(recent_alerts),
        }

    def get_alert_categories(self) -> dict:
        """
        Agrupa todas las alertas acumuladas por categoría temática.

        Categorías:
          network:     INVALID_BLOCK, UNKNOWN_PEER
          application: TX_RATE_LIMIT, HIGH_FEE
          consensus:   CHAIN_REORG, DIFFICULTY_SPIKE, ORPHAN_BLOCK

        Returns:
            Diccionario con conteo y nivel de alerta más alto por categoría.
        """
        categories: Dict[str, dict] = {
            "network":     {"count": 0, "max_level": None},
            "application": {"count": 0, "max_level": None},
            "consensus":   {"count": 0, "max_level": None},
        }

        for alert in self._alerts:
            cat = self._CATEGORY_MAP.get(alert.event_type, "network")
            if cat not in categories:
                categories[cat] = {"count": 0, "max_level": None}

            categories[cat]["count"] += 1
            current_max = categories[cat]["max_level"]
            current_priority = self._LEVEL_PRIORITY.get(current_max, -1)
            new_priority     = self._LEVEL_PRIORITY.get(alert.level, 0)
            if new_priority > current_priority:
                categories[cat]["max_level"] = alert.level

        return {
            cat: {
                "count":     data["count"],
                "max_level": data["max_level"] if data["max_level"] is not None else "NONE",
            }
            for cat, data in categories.items()
        }

    # ── Internos ──────────────────────────────────────────────────────────────

    def _fire(self, alert: SecurityAlert) -> None:
        self._alerts.append(alert)
        logger.log(
            logging.CRITICAL if alert.level == AlertLevel.CRITICAL else logging.WARNING,
            f"[SECURITY] {alert.level} {alert.event_type}: {alert.message}",
        )
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                logger.exception("Error en callback de alerta")

    def _compute_block_rate(self) -> float:
        if len(self._block_times) < 2:
            return 0.0
        elapsed = self._block_times[-1] - self._block_times[0]
        if elapsed <= 0:
            return 0.0
        return round(len(self._block_times) / (elapsed / 60), 2)
