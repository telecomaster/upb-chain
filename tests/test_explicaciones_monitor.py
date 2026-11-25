"""Idea 7 (extensión): explicaciones en anomalías de bloque y en todas las alertas del monitor."""
import os

os.environ.setdefault("NODE_PORT", "0")

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from ai.anomaly.detector import BlockAnomalyDetector
from security.monitor import SecurityMonitor
from tests.helpers import make_app


def _bloque(ts, n_tx, h="ab" * 32):
    return {"hash": h, "header": {"timestamp": ts, "difficulty": 4}, "transactions": [{}] * n_tx}


def _detector_con_historial():
    det = BlockAnomalyDetector()
    for i in range(19):
        det.record_block(_bloque(1000.0 + i * 10 + (i % 2), 5))
    return det


def test_bloque_con_tx_infladas_las_senala_primero():
    rep = _detector_con_historial().peek_block(_bloque(1191.0, 500))
    assert rep.explicacion[0]["caracteristica"] == "n_transactions"
    assert rep.explicacion[0]["contribucion"] == 0.3 and rep.explicacion[0]["valor"] == 500
    assert "n_transactions" in rep.resumen and rep.to_dict()["explicacion"]


def test_bloque_con_intervalo_inflado_senala_el_intervalo():
    rep = _detector_con_historial().peek_block(_bloque(1600.0, 5))
    assert rep.explicacion[0]["caracteristica"] == "desvio_intervalo"
    assert rep.explicacion[0]["contribucion"] == 0.5


def test_bloque_normal_sin_contribuciones():
    rep = _detector_con_historial().peek_block(_bloque(1191.0, 5))
    assert all(e["contribucion"] == 0 for e in rep.explicacion)
    assert rep.resumen.startswith("Sin ")


def _tasa(m):
    for _ in range(101):
        m.on_transaction({"sender": "A" * 20})


def _dificultad(m):
    for d in (4, 4, 10):
        m.on_block({"header": {"difficulty": d}})


CASOS = [
    ("TX_RATE_LIMIT", _tasa),
    ("TX_RATE_LIMIT", lambda m: m.on_tx_rate_limited("A" * 20, 120, 100)),
    ("DIFFICULTY_SPIKE", _dificultad),
    ("CHAIN_REORG", lambda m: m.on_chain_reorg(4)),
    ("INVALID_BLOCK", lambda m: m.on_invalid_block("PoW inválido", "nodo_x")),
    ("UNKNOWN_PEER", lambda m: m.on_unknown_peer("10.0.0.9:8001")),
    ("PBFT_EQUIVOCATION", lambda m: m.on_pbft_equivocation("r1", 0, 5, "PREPARE", ["aa" * 8, "bb" * 8])),
    ("PBFT_CONFLICT", lambda m: m.on_certified_conflict(7, "a" * 64, "b" * 64)),
    ("ORPHAN_BLOCK", lambda m: m.on_orphan_block("c" * 64, "parent not found")),
    ("HIGH_FEE", lambda m: m.on_high_fee_transaction({"sender": "A" * 20, "fee": 50}, 5.0)),
]


@pytest.mark.parametrize("tipo,disparar", CASOS, ids=[f"{t}-{i}" for i, (t, _) in enumerate(CASOS)])
def test_cada_alerta_lleva_explicacion_bien_formada(tipo, disparar):
    m = SecurityMonitor()
    disparar(m)
    a = [x for x in m.get_alerts() if x["event_type"] == tipo][-1]
    meta = a["metadata"]
    assert isinstance(meta["resumen"], str) and meta["resumen"]
    assert meta["explicacion"]
    for e in meta["explicacion"]:
        assert {"regla", "valor", "umbral", "operador", "cumple"} <= set(e)
    assert any(e["cumple"] for e in meta["explicacion"])
    assert a["message"]      # el mensaje original se conserva


@pytest_asyncio.fixture
async def client(tmp_path):
    app = make_app(tmp_path)
    app.state.node.security_monitor.on_chain_reorg(5)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_alertas_por_api_traen_explicacion_de_regla(client):
    alertas = (await client.get("/security/alerts")).json()["alerts"]
    meta = [a for a in alertas if a["event_type"] == "CHAIN_REORG"][-1]["metadata"]
    assert meta["depth"] == 5 and meta["total_reorgs"] >= 1
    assert meta["explicacion"][0]["regla"] == "profundidad_reorg" and meta["explicacion"][0]["cumple"]
    assert "5" in meta["resumen"]
