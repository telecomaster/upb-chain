"""Correcciones de la auditoría de IA/analítica (P1-6 / P1-5): detector de bloques, modelo, estadísticas."""
import os

os.environ.setdefault("NODE_PORT", "0")

from tests.helpers import make_app


def _bloque(i, ts, n_tx=1):
    return {"hash": f"{i:064x}", "header": {"index": i, "timestamp": ts, "difficulty": 1},
            "transactions": [{}] * n_tx}


def test_detector_de_bloques_alimentado_por_el_nodo(tmp_path):
    import time
    node = make_app(tmp_path).state.node
    ts = time.time() - 300.0                     # recientes: los bloques viejos no alertan
    for i in range(1, 13):                      # intervalos regulares de 10 s
        ts += 10 + (i % 2)
        node.announce_block(_bloque(i, ts))
    assert not [a for a in node.security_monitor.get_alerts() if a["event_type"] == "BLOCK_ANOMALY"]
    ts += 600                                    # bloque tras 10 minutos de silencio
    node.announce_block(_bloque(13, ts))
    node.announce_block(_bloque(13, ts))         # el mismo bloque dos veces cuenta una sola
    alertas = [a for a in node.security_monitor.get_alerts() if a["event_type"] == "BLOCK_ANOMALY"]
    assert len(alertas) == 1
    assert alertas[0]["metadata"]["explicacion"]
    assert len(node.block_anomaly_detector._block_times) == 13


def test_reorg_vacia_la_ventana(tmp_path):
    node = make_app(tmp_path).state.node
    node.announce_block(_bloque(1, 10.0))
    node.on_chain_reorg(1, [], [])
    assert node.block_anomaly_detector._block_times == []
