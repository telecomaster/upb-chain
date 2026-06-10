"""
Prueba de Trabajo (PoW) adaptativa para UPB-Chain.
Implementa SHA-256 con dificultad variable y métricas de rendimiento.
"""
import hashlib
import logging
import time
from dataclasses import dataclass
from typing import Callable, Optional

from blockchain.core.block import Block

logger = logging.getLogger("upb_chain.pow")


@dataclass
class MiningResult:
    block: Block
    nonce: int
    hash: str
    time_elapsed: float
    hash_rate: float  # hashes/segundo
    attempts: int


class ProofOfWork:
    def __init__(self, difficulty: int = 4):
        self.difficulty = difficulty
        self.target_prefix = "0" * difficulty
        self._stats: list[MiningResult] = []

    def mine(
        self,
        block: Block,
        max_nonce: int = 10_000_000,
        timeout: Optional[float] = 120.0,
    ) -> Optional[MiningResult]:
        start = time.perf_counter()
        block.header.difficulty = self.difficulty
        nonce = 0

        while nonce < max_nonce:
            if timeout and (time.perf_counter() - start) > timeout:
                logger.warning("Mining timeout alcanzado")
                return None

            block.header.nonce = nonce
            block.hash = block.compute_hash()

            if block.hash.startswith(self.target_prefix):
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
        max_nonce: int = 10_000_000,
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
        nonce = 0

        while nonce < max_nonce:
            elapsed = time.perf_counter() - start
            if timeout and elapsed > timeout:
                logger.warning("mine_async_friendly: timeout alcanzado")
                return None

            block.header.nonce = nonce
            block.hash = block.compute_hash()

            if block.hash.startswith(self.target_prefix):
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
        expected_prefix = "0" * block.header.difficulty
        recomputed = block.compute_hash()
        return recomputed == block.hash and block.hash.startswith(expected_prefix)

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
            "current_difficulty": self.difficulty,
        }


def difficulty_to_expected_time(difficulty: int, hash_rate: float) -> float:
    """Estima el tiempo esperado de minado en segundos dado el hash rate.

    Utiliza la fórmula probabilística: E[intentos] = 16^difficulty / 2
    (promedio de intentos hasta encontrar un hash con `difficulty` ceros hex).

    Args:
        difficulty: Número de ceros hexadecimales requeridos al inicio del hash.
        hash_rate:  Hash rate medido en hashes por segundo (H/s). Debe ser > 0.

    Returns:
        Tiempo esperado en segundos. Retorna float('inf') si hash_rate <= 0.

    Example:
        >>> difficulty_to_expected_time(4, 50_000)
        0.13107...  # ~131 ms a 50 kH/s con dificultad 4
    """
    if hash_rate <= 0:
        return float("inf")
    expected_hashes = (16 ** difficulty) / 2
    return expected_hashes / hash_rate


def estimate_rpi5_performance() -> dict:
    """Benchmarking rápido de hashes SHA-256 en el hardware actual."""
    iterations = 100_000
    start = time.perf_counter()
    for i in range(iterations):
        hashlib.sha256(f"bench_{i}".encode()).hexdigest()
    elapsed = time.perf_counter() - start
    hash_rate = iterations / elapsed
    expected_time_d4 = (16 ** 4) / (2 * hash_rate)
    expected_time_d6 = (16 ** 6) / (2 * hash_rate)
    return {
        "hash_rate_per_second": round(hash_rate),
        "expected_time_difficulty_4_s": round(expected_time_d4, 3),
        "expected_time_difficulty_6_s": round(expected_time_d6, 3),
        "hardware": "Raspberry Pi 5 (estimado)",
    }
