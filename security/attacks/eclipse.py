"""
UPB-Chain — Simulación de Ataque Eclipse
Universidad Privada Boliviana · Área de Ciberseguridad

El ataque Eclipse (Heilman et al., 2015) consiste en:
    1. El atacante controla suficientes nodos para llenar todas las
       conexiones entrantes y salientes de la víctima.
    2. La víctima queda aislada de la red honesta.
    3. El atacante puede mostrar a la víctima una cadena falsa.
    4. Permite: doble gasto de 0-confirmaciones, minado egoísta, censura de TX.

Modelo de conexiones para UPB-Chain (RPi5):
    max_connections_default = 32  (límite típico de sockets TCP simultáneos)
    attacker_nodes_needed   = max_connections + 1

Vectores de ataque estudiados:
    - Inundación de la tabla de peers con IPs del atacante.
    - Explotación del reinicio del nodo para poblar con peers maliciosos.
    - Uso de múltiples IPs desde la misma subred /24 para saturar conexiones.

Referencias:
    Heilman, E., Kendler, A., Zohar, A., & Goldberg, S. (2015).
        Eclipse Attacks on Bitcoin's Peer-to-Peer Network.
        Proceedings of the 24th USENIX Security Symposium, pp. 129-144.

    Marcus, Y., Heilman, E., & Goldberg, S. (2018).
        Low-Resource Eclipse Attacks on Ethereum's Peer-to-Peer Network.
        IACR Cryptology ePrint Archive, Report 2018/236.

    Tran, M., Choi, I., Moon, G. J., Vu, A. V., & Kang, M. S. (2020).
        EREBUS: A Stealthy Network-level Attack Against Ethereum's
        Peer-to-Peer Network. IEEE Symposium on Security and Privacy.

    Heilman, E., et al. (2015). Eclipse Attacks on Bitcoin's Peer-to-Peer
        Network. USENIX Security '15.

USO EXCLUSIVO ACADÉMICO — no utilizar contra redes reales sin autorización.
"""
import math
import time
from typing import List

from security.attacks.simulator import AttackResult


class EclipseAttack:
    """
    Simula el aislamiento de un nodo mediante un ataque Eclipse.

    El atacante llena todas las ranuras de conexión de la víctima con nodos
    propios, impidiendo que reciba bloques y transacciones de la red honesta.
    Especialmente relevante para dispositivos con recursos limitados (RPi5)
    que mantienen pocos peers simultáneos.

    Parámetros clave:
        max_connections: ranuras TCP disponibles en el nodo víctima.
        attacker_nodes:  nodos bajo control del atacante en la red.
        network_size:    total de nodos (honestos + atacante).

    Mitigaciones modeladas:
        has_peer_diversity:          exigir peers de distintas subredes /24.
        has_connection_limit_per_ip: limitar conexiones entrantes por subred.
    """

    # Tiempo promedio por intento de conexión TCP (segundos)
    _AVG_CONNECT_S: float = 3.0
    # Umbral de probabilidad por encima del cual se considera el nodo vulnerable
    _VULNERABLE_THRESHOLD: float = 0.30

    def simulate(
        self,
        max_connections: int = 32,
        attacker_nodes: int = 10,
        network_size: int = 50,
        has_peer_diversity: bool = False,
        has_connection_limit_per_ip: bool = False,
    ) -> AttackResult:
        """
        Simula el ataque Eclipse y calcula la probabilidad de éxito.

        Args:
            max_connections: Número máximo de peers simultáneos del nodo víctima.
            attacker_nodes:  Nodos bajo control del atacante en la red.
            network_size:    Total de nodos en la red (incluye atacante y víctima).
            has_peer_diversity:         El nodo exige peers de distintas subredes /24.
            has_connection_limit_per_ip: El nodo limita conexiones entrantes por IP.

        Returns:
            AttackResult con métricas de riesgo, tiempo estimado y recomendaciones.

        Metrics incluidas:
            attacker_control_ratio: attacker_nodes / max_connections (ratio crudo).
            eclipse_probability:    probabilidad modelada de éxito (0.0–1.0).
            time_to_eclipse_s:      tiempo estimado en segundos para completar el eclipse.
            mitigations_active:     lista de mitigaciones activas detectadas.
            vulnerable:             True si eclipse_probability > _VULNERABLE_THRESHOLD.
        """
        start = time.perf_counter()
        mitigations_active: List[str] = []

        # ── 1. Ratio de control base ────────────────────────────────────────────
        attacker_control_ratio = attacker_nodes / max(max_connections, 1)

        # ── 2. Capacidad efectiva del atacante tras aplicar mitigaciones ────────
        effective_attacker = float(attacker_nodes)

        if has_connection_limit_per_ip:
            mitigations_active.append("Límite de conexiones por IP/subred (/24)")
            # Con límite por IP, cada subred /24 del atacante sólo puede ocupar
            # 1-2 slots. Reducimos la capacidad efectiva al 50 % de max_connections
            # como cota superior (peor caso con mitigación activa).
            effective_attacker = min(effective_attacker, max_connections * 0.50)

        if has_peer_diversity:
            mitigations_active.append("Diversidad de subredes requerida")
            # El nodo requiere peers de max_connections subredes /24 distintas.
            # Asumimos que el atacante dispone de ceil(attacker_nodes / 3) subredes únicas.
            attacker_subnets = math.ceil(attacker_nodes / 3)
            diversity_ratio = attacker_subnets / max(max_connections, 1)
            effective_attacker *= min(diversity_ratio, 1.0)

        # ── 3. Probabilidad de eclipse ──────────────────────────────────────────
        eclipse_probability = self._compute_eclipse_probability(
            max_connections=max_connections,
            effective_attacker=effective_attacker,
            network_size=network_size,
        )

        # ── 4. Tiempo estimado para completar el eclipse ────────────────────────
        # Con más nodos propios el atacante realiza intentos en paralelo;
        # la red más grande requiere más intentos antes de desplazar peers honestos.
        time_to_eclipse_s = round(
            max_connections * self._AVG_CONNECT_S * (network_size / max(attacker_nodes, 1)),
            1,
        )

        vulnerable = eclipse_probability > self._VULNERABLE_THRESHOLD
        elapsed = time.perf_counter() - start

        return AttackResult(
            attack_type="Eclipse Attack",
            success=vulnerable,
            duration_s=elapsed,
            description=(
                f"Atacante con {attacker_nodes}/{network_size} nodos intenta eclipsar "
                f"un nodo con {max_connections} conexiones máximas. "
                f"Mitigaciones activas: {mitigations_active or ['ninguna']}."
            ),
            metrics={
                "attacker_control_ratio": round(attacker_control_ratio, 4),
                "eclipse_probability": eclipse_probability,
                "time_to_eclipse_s": time_to_eclipse_s,
                "mitigations_active": mitigations_active,
                "vulnerable": vulnerable,
                "max_connections": max_connections,
                "attacker_nodes": attacker_nodes,
                "network_size": network_size,
            },
            recommendations=[
                "Limitar conexiones entrantes de la misma subred /24 (máx. 2 por /24)",
                "Mantener lista blanca de peers UPB para conexiones salientes prioritarias",
                "Rotar peers periódicamente (cada 24 h) para evitar acumulación de nodos maliciosos",
                "Usar múltiples interfaces de red (Ethernet + WiFi) en RPi5",
                "Incrementar max_connections a ≥64 para elevar el umbral de recursos del atacante",
                "Monitorear intentos de conexión reiterados desde la misma IP/subred",
            ],
        )

    # ── Métodos internos ──────────────────────────────────────────────────────────

    @staticmethod
    def _compute_eclipse_probability(
        max_connections: int,
        effective_attacker: float,
        network_size: int,
    ) -> float:
        """
        Calcula P(eclipse) a partir de la capacidad efectiva del atacante.

        Modelo por tramos sobre el ratio effective_attacker / max_connections:
            ratio >= 1.0  →  0.90  (atacante puede llenar todos los slots)
            ratio >= 0.75 →  0.65
            ratio >= 0.50 →  0.40
            ratio >= 0.25 →  0.18
            ratio <  0.25 →  ratio * 0.55

        Factor de dilución: la fracción de nodos honestos en la red reduce la
        probabilidad de que los peers seleccionados sean todos del atacante.
        Fórmula: eclipse_prob = base_prob * (1 - honest_fraction * 0.30)
        """
        if network_size <= 0 or max_connections <= 0 or effective_attacker <= 0:
            return 0.0

        ratio = effective_attacker / max_connections

        if ratio >= 1.0:
            base_prob = 0.90
        elif ratio >= 0.75:
            base_prob = 0.65
        elif ratio >= 0.50:
            base_prob = 0.40
        elif ratio >= 0.25:
            base_prob = 0.18
        else:
            base_prob = ratio * 0.55

        honest_fraction = max(network_size - effective_attacker, 0.0) / network_size
        dilution_factor = 1.0 - honest_fraction * 0.30

        return round(max(0.0, min(1.0, base_prob * dilution_factor)), 4)
