"""
Simulador de ataques para UPB-Chain — entorno educativo y de investigación.
Implementa los vectores de ataque más conocidos en blockchain para demostrar
vulnerabilidades y validar contramedidas.

USO EXCLUSIVO ACADÉMICO — no utilizar contra redes reales sin autorización.
"""
import hmac
import logging
import random
import secrets
import statistics
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

logger = logging.getLogger("upb_chain.security.attacks")


@dataclass
class AttackResult:
    attack_type: str
    success: bool
    duration_s: float
    description: str
    metrics: dict = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)


# ── Ataque del 51 % ───────────────────────────────────────────────────────────

class FiftyOnePercentAttack:
    """
    Simula un ataque de mayoría de hash.
    El atacante con >50 % del poder de cómputo puede reorganizar la cadena.
    """

    def simulate(
        self,
        honest_hash_rate: float,
        attacker_hash_rate: float,
        blocks_to_reorg: int = 6,
        iterations: int = 1000,
    ) -> AttackResult:
        start = time.perf_counter()

        total = honest_hash_rate + attacker_hash_rate
        attacker_share = attacker_hash_rate / total

        successes = 0
        for _ in range(iterations):
            if self._can_reorg(attacker_share, blocks_to_reorg):
                successes += 1

        success_rate = successes / iterations
        elapsed = time.perf_counter() - start
        success = attacker_share > 0.5

        return AttackResult(
            attack_type="51% Attack",
            success=success,
            duration_s=elapsed,
            description=(
                f"Atacante con {attacker_share*100:.1f}% del hash rate intenta "
                f"reorganizar {blocks_to_reorg} bloques."
            ),
            metrics={
                "attacker_share": attacker_share,
                "honest_share": 1 - attacker_share,
                "simulated_success_rate": success_rate,
                "blocks_to_reorg": blocks_to_reorg,
                "vulnerable": success,
            },
            recommendations=[
                "Aumentar el número de nodos mineros distribuidos",
                "Requerir ≥12 confirmaciones para transacciones de alto valor",
                "Implementar monitoreo de concentración de hash rate",
                "Considerar migración a PBFT para redes permisionadas (sin 51 %)",
            ],
        )

    @staticmethod
    def _can_reorg(attacker_share: float, depth: int) -> bool:
        if attacker_share >= 1.0:
            return True
        # Probabilidad de éxito en reorganización (Nakamoto 2008)
        q = attacker_share
        p = 1 - q
        prob = 1 - sum(
            (pow(q / p, k) * pow(p, depth - k) * pow(q, k))
            for k in range(depth)
        )
        return random.random() < max(0, min(1, prob))


# ── Ataque Sybil ─────────────────────────────────────────────────────────────

class SybilAttack:
    """
    Simula la creación de identidades falsas para influir en la red P2P.
    """

    def simulate(
        self,
        total_nodes: int,
        sybil_nodes: int,
        require_pow: bool = False,
        require_stake: bool = False,
    ) -> AttackResult:
        start = time.perf_counter()

        sybil_ratio = sybil_nodes / total_nodes
        mitigations_active = []

        if require_pow:
            mitigations_active.append("PoW")
            sybil_ratio *= 0.1

        if require_stake:
            mitigations_active.append("PoS/Stake")
            sybil_ratio *= 0.05

        success = sybil_ratio > 0.33
        elapsed = time.perf_counter() - start

        return AttackResult(
            attack_type="Sybil Attack",
            success=success,
            duration_s=elapsed,
            description=(
                f"{sybil_nodes} nodos Sybil vs {total_nodes - sybil_nodes} honestos. "
                f"Mitigaciones: {mitigations_active or 'ninguna'}."
            ),
            metrics={
                "sybil_nodes": sybil_nodes,
                "honest_nodes": total_nodes - sybil_nodes,
                "effective_sybil_ratio": sybil_ratio,
                "network_compromised": success,
                "mitigations_active": mitigations_active,
            },
            recommendations=[
                "Requerir depósito (stake) para unirse a la red",
                "Implementar lista blanca de nodos para redes permisionadas",
                "Usar certificados TLS mutuo para autenticar nodos",
                "Monitorear comportamiento anómalo de nodos nuevos con IA",
            ],
        )


# ── Ataque de doble gasto ─────────────────────────────────────────────────────

class DoubleSpendAttack:
    """
    Simula intentos de doble gasto en función de confirmaciones requeridas.
    """

    def simulate(
        self,
        confirmations_required: int,
        attacker_hash_rate_percent: float,
    ) -> AttackResult:
        start = time.perf_counter()
        q = attacker_hash_rate_percent / 100.0
        p = 1 - q

        if q >= 1.0:
            success_prob = 1.0
        elif q == 0:
            success_prob = 0.0
        else:
            # Probabilidad de éxito de Nakamoto para z confirmaciones
            lam = confirmations_required * (q / p)
            import math
            success_prob = 0.0
            for k in range(confirmations_required):
                poisson = math.exp(-lam) * (lam ** k) / math.factorial(k)
                success_prob += poisson * (1 - pow(q / p, confirmations_required - k))
            success_prob = 1 - success_prob

        elapsed = time.perf_counter() - start

        return AttackResult(
            attack_type="Double Spend",
            success=success_prob > 0.5,
            duration_s=elapsed,
            description=(
                f"Con {confirmations_required} confirmaciones y {attacker_hash_rate_percent}% "
                f"del hash rate, probabilidad de éxito: {success_prob*100:.4f}%"
            ),
            metrics={
                "confirmations_required": confirmations_required,
                "attacker_hash_rate_pct": attacker_hash_rate_percent,
                "success_probability": success_prob,
                "risk_level": "ALTO" if success_prob > 0.01 else "BAJO",
            },
            recommendations=[
                f"Con {attacker_hash_rate_percent}% hash rate enemigo, requerir ≥{_safe_confirmations(q)} confirmaciones",
                "Implementar monitoreo de transacciones de alto valor en tiempo real",
                "Usar PBFT para finalidad instantánea y eliminar riesgo de reorg",
            ],
        )


def _safe_confirmations(q: float) -> int:
    """Confirmaciones mínimas para reducir éxito del doble gasto a <0.1 %."""
    if q <= 0.1:
        return 6
    if q <= 0.2:
        return 12
    if q <= 0.3:
        return 30
    return 100


# ── Helper: comparación NO segura (demostración de vulnerabilidad) ────────────

def _naive_compare(a: str, b: str) -> bool:
    """
    Comparación carácter a carácter que sale en cuanto encuentra una diferencia.
    VULNERABLE a timing attacks: el tiempo de ejecución revela la posición
    del primer carácter incorrecto, permitiendo reconstruir el secreto de a 1 char.
    """
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if x != y:
            return False  # Salida temprana → tiempo variable = información filtrada
    return True


# ── Ataque de Timing ──────────────────────────────────────────────────────────

class TimingAttack:
    """
    Simula ataques de timing en operaciones criptográficas.

    Principio: si la comparación de hashes no es en tiempo constante,
    un atacante puede inferir el hash correcto midiendo tiempos de respuesta.
    Con suficientes muestras puede reconstruir el secreto carácter a carácter.

    Demuestra la diferencia entre:
      - Comparación naive: sale al primer mismatch → tiempo variable → VULNERABLE
      - Comparación segura: hmac.compare_digest() → tiempo constante → SEGURO

    Método de detección: se mide el tiempo de comparación para strings que
    difieren en la posición 0 (mismatch temprano) vs la posición final
    (mismatch tardío). Si la diferencia de tiempos es estadísticamente
    significativa, el sistema es vulnerable.

    Ref: Crosby, S. A., et al. (2009). Opportunities and Limits of Remote
         Timing Attacks. ACM TISSEC.
    """

    def simulate(
        self,
        iterations: int = 10_000,
        hash_length: int = 64,
    ) -> AttackResult:
        """
        Mide y compara tiempos de comparación naive vs hmac.compare_digest.

        Args:
            iterations:  Número total de comparaciones por método (se divide
                         en grupos de mismatch temprano / tardío / coincidencia).
            hash_length: Longitud en caracteres del hash simulado (hex).

        Returns:
            AttackResult con métricas de timing y recomendación.
        """
        start = time.perf_counter()

        # Hash objetivo (simula el hash almacenado en el servidor)
        target = secrets.token_hex(hash_length // 2)

        # Generar variantes con mismatch en distintas posiciones
        per_group = max(iterations // 4, 100)

        def _mutate(s: str, pos: int) -> str:
            """Cambia un carácter en la posición indicada."""
            chars = list(s)
            chars[pos] = "x" if chars[pos] != "x" else "y"
            return "".join(chars)

        early_variants = [_mutate(target, 0)] * per_group
        late_variants  = [_mutate(target, hash_length - 1)] * per_group
        match_variants = [target] * per_group

        def _measure(fn, variants: list) -> List[float]:
            times = []
            for v in variants:
                t0 = time.perf_counter_ns()
                fn(target, v)
                times.append(time.perf_counter_ns() - t0)
            return times

        # Medir comparación naive
        naive_early  = _measure(_naive_compare, early_variants)
        naive_late   = _measure(_naive_compare, late_variants)
        naive_match  = _measure(_naive_compare, match_variants)

        # Medir comparación segura
        secure_early = _measure(hmac.compare_digest, early_variants)
        secure_late  = _measure(hmac.compare_digest, late_variants)

        # ── Estadísticas ─────────────────────────────────────────────────────
        mean_naive_early  = statistics.mean(naive_early)
        mean_naive_late   = statistics.mean(naive_late)
        mean_naive_match  = statistics.mean(naive_match)
        mean_secure_early = statistics.mean(secure_early)
        mean_secure_late  = statistics.mean(secure_late)

        # Filtrado de outliers: usar mediana para robustez
        med_naive_early  = statistics.median(naive_early)
        med_naive_late   = statistics.median(naive_late)
        med_secure_early = statistics.median(secure_early)
        med_secure_late  = statistics.median(secure_late)

        # Fuga de timing (ns): diferencia entre mismatch tardío y temprano
        timing_leak_ns      = mean_naive_late - mean_naive_early
        secure_timing_diff  = abs(mean_secure_late - mean_secure_early)

        # Coeficiente de variación de la comparación naive (mide inconsistencia)
        all_naive = naive_early + naive_late
        std_naive = statistics.stdev(all_naive) if len(all_naive) > 1 else 0.0
        mean_naive_all = statistics.mean(all_naive)
        cv_naive = std_naive / max(mean_naive_all, 1.0)

        # Vulnerable si la fuga de timing es ≥100 ns o CV > 20 %
        vulnerable = timing_leak_ns >= 100.0 or cv_naive > 0.20

        elapsed = time.perf_counter() - start

        return AttackResult(
            attack_type="Timing Attack",
            success=vulnerable,
            duration_s=elapsed,
            description=(
                f"Comparación naive — fuga de timing: {timing_leak_ns:.0f} ns "
                f"(temprano vs tardío). compare_digest — diferencia: {secure_timing_diff:.0f} ns "
                f"(idealmente ~0)."
            ),
            metrics={
                "naive_mean_early_mismatch_ns":  round(mean_naive_early, 1),
                "naive_mean_late_mismatch_ns":   round(mean_naive_late, 1),
                "naive_mean_match_ns":           round(mean_naive_match, 1),
                "timing_leak_ns":                round(timing_leak_ns, 1),
                "secure_mean_early_ns":          round(mean_secure_early, 1),
                "secure_mean_late_ns":           round(mean_secure_late, 1),
                "secure_timing_diff_ns":         round(secure_timing_diff, 1),
                "cv_naive":                      round(cv_naive, 4),
                "vulnerable":                    vulnerable,
                "hash_length":                   hash_length,
                "iterations":                    iterations,
            },
            recommendations=[
                "Usar hmac.compare_digest() para TODA comparación de hashes y tokens",
                "Nunca usar '==' para comparar secretos, hashes o tokens de autenticación",
                "En Python, secrets.compare_digest() es equivalente y también es seguro",
                "Agregar jitter (random sleep) puede reducir pero NO elimina la vulnerabilidad",
                "Revisar crypto_utils.py: verify_password() ya usa hmac.compare_digest [OK]",
            ],
        )


# ── Ataque de Storage Bloat ───────────────────────────────────────────────────

class StorageAttack:
    """
    Simula un ataque de llenado de disco (storage bloat).

    Relevante para RPi5 con almacenamiento limitado (ej. 128 GB): un atacante
    puede spamear transacciones con payloads de gran tamaño para llenar el disco,
    provocando denegación de servicio por falta de espacio.

    Calcula los días hasta el llenado del disco dado el tamaño promedio de TX,
    la tasa de TX diaria y la capacidad disponible del disco, tanto en
    condiciones normales como bajo ataque con payloads maximales.
    """

    def simulate(
        self,
        disk_gb: float = 128.0,
        reserved_gb: float = 20.0,
        avg_tx_bytes: int = 500,
        tx_per_day: int = 1_000,
        max_payload_bytes: int = 10_000,
    ) -> AttackResult:
        """
        Calcula el impacto de un ataque de llenado de disco.

        Args:
            disk_gb:           Capacidad total del disco en GB.
            reserved_gb:       GB reservados para OS y otros usos.
            avg_tx_bytes:      Tamaño promedio de TX en condiciones normales (bytes).
            tx_per_day:        Transacciones por día enviadas por el atacante.
            max_payload_bytes: Tamaño máximo de payload por TX (el atacante usa el máximo).

        Returns:
            AttackResult con días hasta llenado y factor de bloat.
        """
        start = time.perf_counter()

        available_gb    = max(disk_gb - reserved_gb, 0.0)
        available_bytes = available_gb * 1024 ** 3

        daily_normal_bytes = tx_per_day * avg_tx_bytes
        daily_attack_bytes = tx_per_day * max_payload_bytes

        # Días hasta llenado en condiciones normales
        days_normal = available_bytes / daily_normal_bytes if daily_normal_bytes > 0 else float("inf")
        # Días hasta llenado bajo ataque con payloads máximos
        days_attack = available_bytes / daily_attack_bytes if daily_attack_bytes > 0 else float("inf")

        bloat_factor = max_payload_bytes / max(avg_tx_bytes, 1)

        # Vulnerable si el disco se llena en menos de 30 días bajo ataque
        vulnerable = days_attack < 30.0

        elapsed = time.perf_counter() - start

        return AttackResult(
            attack_type="Storage Bloat Attack",
            success=vulnerable,
            duration_s=elapsed,
            description=(
                f"Con {tx_per_day} TX/día de {max_payload_bytes} bytes cada una, "
                f"el disco ({available_gb:.0f} GB disponibles) se llenaría en "
                f"{days_attack:.1f} días (factor de bloat: {bloat_factor:.0f}x)."
            ),
            metrics={
                "available_gb":         round(available_gb, 2),
                "days_to_fill_normal":  round(days_normal, 1),
                "days_to_fill_attack":  round(days_attack, 1),
                "bloat_factor":         round(bloat_factor, 1),
                "daily_normal_mb":      round(daily_normal_bytes / 1024 ** 2, 2),
                "daily_attack_mb":      round(daily_attack_bytes / 1024 ** 2, 2),
                "vulnerable":           vulnerable,
                "tx_per_day":           tx_per_day,
                "max_payload_bytes":    max_payload_bytes,
            },
            recommendations=[
                f"Limitar el payload máximo de TX a ≤{avg_tx_bytes * 10} bytes (10× el tamaño normal)",
                "Implementar cuota de disco para los datos de la blockchain en una partición separada",
                "Aplicar rate limiting por dirección para limitar TX/día a un máximo razonable",
                "Agregar validación de MAX_CONTENT_LENGTH en el endpoint de nueva transacción",
                "Monitorear el uso de disco con alertas al superar el 80 % de capacidad",
            ],
        )


# ── Resumen de análisis de seguridad ─────────────────────────────────────────

def full_security_analysis(
    node_count: int = 2,
    honest_hash_rate: float = 70.0,
    attacker_hash_rate: float = 30.0,
) -> dict:
    """
    Ejecuta todos los simuladores de ataque y retorna un análisis consolidado.

    Nuevos campos respecto a la versión anterior:
        overall_risk_score  (float 0.0–1.0): promedio ponderado de riesgos.
        mitigation_coverage (float 0.0–1.0): fracción de escenarios con
                                             al menos una mitigación activa.

    Pesos por escenario:
        51 %         0.25
        Sybil (sin)  0.08  /  Sybil (con stake) 0.07
        DblSpend 6c  0.15  /  DblSpend 12c       0.05
        Eclipse      0.15
        Timing       0.10
        Storage      0.15
    """
    # Importación diferida para evitar ciclo de importación con eclipse.py
    from security.attacks.eclipse import EclipseAttack  # noqa: PLC0415

    results: dict = {}

    # ── Ataques existentes ────────────────────────────────────────────────────
    pow_attack = FiftyOnePercentAttack()
    results["51_percent"] = pow_attack.simulate(
        honest_hash_rate, attacker_hash_rate
    ).__dict__

    sybil_attack = SybilAttack()
    results["sybil_no_mitigation"] = sybil_attack.simulate(
        total_nodes=node_count + 5, sybil_nodes=5
    ).__dict__
    results["sybil_with_stake"] = sybil_attack.simulate(
        total_nodes=node_count + 5, sybil_nodes=5, require_stake=True
    ).__dict__

    ds_attack = DoubleSpendAttack()
    results["double_spend_6conf"]  = ds_attack.simulate(6,  attacker_hash_rate).__dict__
    results["double_spend_12conf"] = ds_attack.simulate(12, attacker_hash_rate).__dict__

    # ── Nuevos ataques ────────────────────────────────────────────────────────
    eclipse_attack = EclipseAttack()
    results["eclipse"] = eclipse_attack.simulate(
        max_connections=32,
        attacker_nodes=max(node_count * 3, 10),
        network_size=max(node_count * 10, 50),
    ).__dict__

    timing_attack = TimingAttack()
    results["timing"] = timing_attack.simulate(iterations=4_000).__dict__

    storage_attack = StorageAttack()
    results["storage"] = storage_attack.simulate(
        disk_gb=128.0, reserved_gb=20.0, tx_per_day=1_000
    ).__dict__

    # ── Métricas de resumen ───────────────────────────────────────────────────
    _weights = {
        "51_percent":          0.25,
        "sybil_no_mitigation": 0.08,
        "sybil_with_stake":    0.07,
        "double_spend_6conf":  0.15,
        "double_spend_12conf": 0.05,
        "eclipse":             0.15,
        "timing":              0.10,
        "storage":             0.15,
    }

    risk_sum   = 0.0
    weight_sum = 0.0
    with_mitigation = 0
    total_scenarios = len(_weights)

    for key, weight in _weights.items():
        r = results.get(key, {})
        risk_value = 1.0 if r.get("success", False) else 0.0
        risk_sum   += risk_value * weight
        weight_sum += weight

        # Tiene mitigación si no tuvo éxito o si hay mitigaciones_active no vacías
        metrics = r.get("metrics", {})
        has_mitigation = (
            not r.get("success", True)
            or bool(metrics.get("mitigations_active"))
        )
        if has_mitigation:
            with_mitigation += 1

    overall_risk_score  = round(risk_sum / weight_sum, 4) if weight_sum > 0 else 0.0
    mitigation_coverage = round(with_mitigation / total_scenarios, 4)

    results["_summary"] = {
        "overall_risk_score":  overall_risk_score,
        "mitigation_coverage": mitigation_coverage,
        "risk_label": (
            "CRÍTICO" if overall_risk_score >= 0.70
            else "ALTO"   if overall_risk_score >= 0.40
            else "MEDIO"  if overall_risk_score >= 0.20
            else "BAJO"
        ),
    }

    return results
