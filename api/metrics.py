"""Métricas Prometheus del nodo (P2-10).

Cada app tiene su propio ``CollectorRegistry`` (nunca el global: dos apps en un proceso no
colisionan). Los valores de cadena, mempool, pares y alertas se leen al momento del
*scrape* desde el ``NodeState``; solo los contadores de eventos (bloques minados, TX
admitidas/rechazadas/limitadas) se incrementan en el camino de la petición.
"""
import threading
import time
from typing import Dict

from prometheus_client import CollectorRegistry, generate_latest
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


class EventCounters:
    """Contadores de eventos del nodo (seguros entre hilos)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values: Dict[str, int] = {}

    def inc(self, name: str, n: int = 1) -> None:
        with self._lock:
            self._values[name] = self._values.get(name, 0) + n

    def get(self, name: str) -> int:
        with self._lock:
            return self._values.get(name, 0)


class NodeCollector:
    """Colector que lee el estado del nodo en cada scrape."""

    def __init__(self, node) -> None:
        self.node = node

    def collect(self):
        node = self.node
        bc = node.blockchain
        nid = node.settings.node_id
        ev = node.counters

        def gauge(name, doc, value):
            g = GaugeMetricFamily(name, doc)
            g.add_metric([], value)
            return g

        info = GaugeMetricFamily("upb_node_info", "Información del nodo (valor siempre 1)",
                                 labels=["node_id"])
        info.add_metric([nid], 1)
        yield info
        yield gauge("upb_chain_height", "Altura de la cadena (génesis = 0)", bc.height)
        # Gauge = float64: el trabajo acumulado (suma de 2^bits) pierde precisión por
        # encima de 2^53; basta para graficar, no para comparar cadenas.
        yield gauge("upb_chain_work", "Trabajo acumulado de la cadena (2^bits por bloque)",
                    float(bc.total_work))
        yield gauge("upb_difficulty_bits", "Dificultad vigente en bits para el próximo bloque",
                    bc._calculate_difficulty())
        yield gauge("upb_mempool_size", "Transacciones pendientes en el mempool", len(bc.mempool))
        net = node.p2p.get_network_stats()
        yield gauge("upb_peers_total", "Pares conocidos", net["total_peers"])
        yield gauge("upb_peers_active", "Pares activos", net["active_peers"])
        yield gauge("upb_mining_in_progress", "1 si hay un minado en curso",
                    1 if node.mining_lock.locked() else 0)
        yield gauge("upb_last_block_age_seconds", "Segundos desde el timestamp del último bloque",
                    max(0.0, time.time() - bc.last_block.header.timestamp))
        yield CounterMetricFamily("upb_blocks_mined", "Bloques minados localmente",
                                  value=ev.get("blocks_mined"))
        tx = CounterMetricFamily("upb_tx", "Transacciones recibidas por la API según resultado",
                                 labels=["result"])
        for result in ("admitted", "rejected", "rate_limited"):
            tx.add_metric([result], ev.get("tx_" + result))
        yield tx
        alerts = GaugeMetricFamily("upb_alerts", "Alertas de seguridad registradas por severidad",
                                   labels=["severity"])
        conteo: Dict[str, int] = {"INFO": 0, "WARNING": 0, "CRITICAL": 0}
        for a in node.security_monitor.get_alerts(limit=10**9):
            nivel = str(getattr(a["level"], "value", a["level"])).upper()
            conteo[nivel] = conteo.get(nivel, 0) + 1
        for nivel, n in conteo.items():
            alerts.add_metric([nivel], n)
        yield alerts


def build_registry(node) -> CollectorRegistry:
    registry = CollectorRegistry()
    registry.register(NodeCollector(node))
    return registry


def render(registry: CollectorRegistry) -> bytes:
    return generate_latest(registry)
