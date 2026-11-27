"""
Prueba de Trabajo (PoW) adaptativa para UPB-Chain.
Implementa SHA-256 con dificultad variable y métricas de rendimiento.

La dificultad se mide en BITS (P2-5): un bloque es válido si el hash, leído
como entero de 256 bits, es menor que el objetivo 2**(256 - bits)
(`blockchain.core.block.target_for_bits`). Trabajo esperado: 2**bits intentos.
"""
import hashlib
import logging
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from blockchain.core.block import Block, hash_meets_bits, target_for_bits, work_for_bits

logger = logging.getLogger("upb_chain.pow")

# Nonces entre pausas del freno térmico (pausas cortas: la API sigue respondiendo).
LOTE_FRENO = 2048


@dataclass
class MiningResult:
    block: Block
    nonce: int
    hash: str
    time_elapsed: float
    hash_rate: float  # hashes/segundo
    attempts: int


class ProofOfWork:
    def __init__(self, difficulty: int = 16, freno=None,
                 dormir: Callable[[float], None] = time.sleep,
                 reloj: Callable[[], float] = time.perf_counter):
        self.difficulty = difficulty  # bits
        # Freno térmico local (opcional, `termico.FrenoTermico`): solo pausa el hilo entre
        # lotes de nonces; no cambia la dificultad ni qué bloques son válidos.
        self.freno = freno
        self._dormir = dormir
        self._reloj = reloj
        self._stats: list[MiningResult] = []
        self.last_difficulty = difficulty  # última dificultad usada al minar

    def mine(
        self,
        block: Block,
        max_nonce: int = 2 ** 32,
        timeout: Optional[float] = 120.0,
        difficulty: Optional[int] = None,
        stop_event: Optional[threading.Event] = None,
        on_progress: Optional[Callable[[int, float], None]] = None,
    ) -> Optional[MiningResult]:
        """Mina `block`. `difficulty` es la que dicta la regla de la cadena
        (`Blockchain._calculate_difficulty()`); si se omite se usa la del
        constructor (sólo uso autónomo: demos y benchmarks). No se muta el
        estado del motor. Si `stop_event` se activa, el minado aborta (None).
        `on_progress(nonce, segundos)` (opcional, P2-7) se invoca cada 4096 intentos; no
        altera el resultado."""
        start = time.perf_counter()
        diff = self.difficulty if difficulty is None else difficulty
        target = target_for_bits(diff)
        self.last_difficulty = diff
        block.header.difficulty = diff
        nonce = 0
        t_lote = self._reloj()

        while nonce < max_nonce:
            if self.freno is not None and nonce > 0 and nonce % LOTE_FRENO == 0:
                pausa = self.freno.pausa_para(self._reloj() - t_lote)
                if pausa > 0:
                    self._dormir(pausa)
                t_lote = self._reloj()
            if stop_event is not None and nonce % 256 == 0 and stop_event.is_set():
                logger.info("Minado abortado por stop_event")
                return None
            if on_progress is not None and nonce & 0xFFF == 0 and nonce > 0:
                on_progress(nonce, time.perf_counter() - start)
            if timeout and (time.perf_counter() - start) > timeout:
                logger.warning("Mining timeout alcanzado")
                return None

            block.header.nonce = nonce
            block.hash = block.compute_hash()

            if int(block.hash, 16) < target:
                elapsed = time.perf_counter() - start
                hash_rate = nonce / elapsed if elapsed > 0 else 0
                result = MiningResult(
                    block=block,
                    nonce=nonce,
                    hash=block.hash,
                    time_elapsed=elapsed,
                    hash_rate=hash_rate,
                    attempts=nonce + 1,
                )
                self._stats.append(result)
                logger.info(
                    f"Bloque minado: nonce={nonce} hash={block.hash[:16]}… "
                    f"tiempo={elapsed:.2f}s hash_rate={hash_rate:.0f} H/s"
                )
                return result
            nonce += 1

        logger.warning("Max nonce alcanzado sin solución")
        return None

    def mine_async_friendly(
        self,
        block: Block,
        on_progress: Callable[[int, float], None],
        max_nonce: int = 2 ** 32,
        timeout: Optional[float] = 120.0,
        progress_interval: int = 10_000,
    ) -> Optional[MiningResult]:
        """Minado con callback de progreso cada `progress_interval` hashes.

        Útil para dashboards y WebSocket que necesiten mostrar el avance en tiempo
        real sin bloquear el event loop (se recomienda ejecutar en un ThreadPoolExecutor).

        Args:
            block:             Bloque candidato a minar (se modifica in-place).
            on_progress:       Callable(nonce_actual: int, elapsed_seconds: float).
                               Se invoca cada `progress_interval` intentos.
            max_nonce:         Límite de nonce antes de rendirse.
            timeout:           Timeout en segundos; None = sin límite.
            progress_interval: Frecuencia de llamadas al callback (default 10 000).

        Returns:
            MiningResult si se encontró solución; None si se agotó el nonce o timeout.
        """
        start = time.perf_counter()
        block.header.difficulty = self.difficulty
        target = target_for_bits(self.difficulty)
        nonce = 0

        while nonce < max_nonce:
            elapsed = time.perf_counter() - start
            if timeout and elapsed > timeout:
                logger.warning("mine_async_friendly: timeout alcanzado")
                return None

            block.header.nonce = nonce
            block.hash = block.compute_hash()

            if int(block.hash, 16) < target:
                hash_rate = nonce / elapsed if elapsed > 0 else 0
                result = MiningResult(
                    block=block,
                    nonce=nonce,
                    hash=block.hash,
                    time_elapsed=elapsed,
                    hash_rate=hash_rate,
                    attempts=nonce + 1,
                )
                self._stats.append(result)
                on_progress(nonce, elapsed)
                logger.info(
                    f"mine_async_friendly: bloque minado nonce={nonce} "
                    f"hash={block.hash[:16]}… tiempo={elapsed:.2f}s"
                )
                return result

            if nonce % progress_interval == 0 and nonce > 0:
                on_progress(nonce, elapsed)

            nonce += 1

        logger.warning("mine_async_friendly: max nonce alcanzado sin solución")
        return None

    def validate_proof(self, block: Block) -> bool:
        recomputed = block.compute_hash()
        return recomputed == block.hash and hash_meets_bits(block.hash, block.header.difficulty)

    def get_avg_hash_rate(self) -> float:
        if not self._stats:
            return 0.0
        return sum(r.hash_rate for r in self._stats) / len(self._stats)

    def get_mining_stats(self) -> dict:
        if not self._stats:
            return {}
        times = [r.time_elapsed for r in self._stats]
        rates = [r.hash_rate for r in self._stats]
        return {
            "blocks_mined": len(self._stats),
            "avg_time_s": sum(times) / len(times),
            "min_time_s": min(times),
            "max_time_s": max(times),
            "avg_hash_rate": sum(rates) / len(rates),
            "last_difficulty_bits": self.last_difficulty,
        }


def difficulty_to_expected_time(difficulty: int, hash_rate: float) -> float:
    """Estima el tiempo esperado de minado en segundos dado el hash rate (estimación).

    Cada intento cumple con probabilidad 2**-bits, así que el número esperado de
    intentos hasta el primer éxito es 2**bits (distribución geométrica).

    Args:
        difficulty: Bits iniciales en cero exigidos al hash.
        hash_rate:  Hash rate medido en hashes por segundo (H/s). Debe ser > 0.

    Returns:
        Tiempo esperado en segundos. Retorna float('inf') si hash_rate <= 0.

    Example:
        >>> difficulty_to_expected_time(16, 65_536)
        1.0  # 2**16 intentos a 65 536 H/s
    """
    if hash_rate <= 0:
        return float("inf")
    return work_for_bits(difficulty) / hash_rate


def estimate_rpi5_performance() -> dict:
    """Benchmarking rápido de hashes SHA-256 en el hardware ACTUAL (no necesariamente un RPi5)."""
    iterations = 100_000
    start = time.perf_counter()
    for i in range(iterations):
        hashlib.sha256(f"bench_{i}".encode()).hexdigest()
    elapsed = time.perf_counter() - start
    hash_rate = iterations / elapsed
    return {
        "hash_rate_per_second": round(hash_rate),
        "expected_time_16_bits_s": round(difficulty_to_expected_time(16, hash_rate), 3),
        "expected_time_20_bits_s": round(difficulty_to_expected_time(20, hash_rate), 3),
        "hardware": "Raspberry Pi 5 (estimado)",
    }
