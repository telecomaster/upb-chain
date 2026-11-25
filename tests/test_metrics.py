"""P2-10: /metrics en formato Prometheus, registros independientes y control de acceso."""
import re
import time

import pytest
from fastapi.testclient import TestClient

from blockchain.core.transaction import Transaction, TransactionType
from blockchain.core.wallet import Wallet
from tests.helpers import make_app

REMOTO = ("10.0.0.5", 1234)

NOMBRES = [
    "upb_node_info", "upb_chain_height", "upb_chain_work", "upb_difficulty_bits",
    "upb_mempool_size", "upb_peers_total", "upb_peers_active", "upb_mining_in_progress",
    "upb_last_block_age_seconds", "upb_blocks_mined_total", "upb_tx_total", "upb_alerts",
]


def _valor(texto: str, serie: str) -> float:
    """Valor de la línea ``serie`` (nombre con etiquetas) del texto de exposición."""
    m = re.search(r"^" + re.escape(serie) + r" (\S+)$", texto, re.M)
    assert m, f"serie {serie} no encontrada en:\n{texto}"
    return float(m.group(1))


def _tx_firmada(ana: Wallet, nonce: int) -> dict:
    tx = Transaction(TransactionType.DATA_RECORD, ana.address, "DEST",
                     {"d": time.time_ns()}, nonce=nonce)
    tx.sign(ana.private_key_hex)
    return {"type": tx.type.value, "sender": tx.sender, "recipient": tx.recipient,
            "payload": tx.payload, "fee": tx.fee, "nonce": tx.nonce,
            "timestamp": tx.timestamp, "signature": tx.signature, "public_key": tx.public_key}


def test_formato_y_nombres(tmp_path):
    c = TestClient(make_app(tmp_path, "nodo_a"))
    r = c.get("/metrics")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    for nombre in NOMBRES:
        assert f"# TYPE {nombre.removesuffix('_total')}" in r.text or f"# TYPE {nombre}" in r.text, nombre
    assert 'upb_node_info{node_id="nodo_a"} 1.0' in r.text
    assert _valor(r.text, "upb_chain_height") == 0
    assert _valor(r.text, "upb_chain_work") > 0
    assert _valor(r.text, 'upb_alerts{severity="CRITICAL"}') == 0


def test_valores_cambian_al_minar_y_admitir_tx(tmp_path):
    c = TestClient(make_app(tmp_path))
    ana = Wallet.generate()
    assert c.post("/transactions", json=_tx_firmada(ana, 1)).status_code == 200
    assert c.post("/transactions", json=_tx_firmada(ana, 9)).status_code == 400   # nonce erróneo
    t = c.get("/metrics").text
    assert _valor(t, "upb_mempool_size") == 1
    assert _valor(t, 'upb_tx_total{result="admitted"}') == 1
    assert _valor(t, 'upb_tx_total{result="rejected"}') == 1
    trabajo = _valor(t, "upb_chain_work")

    assert c.post("/blocks/mine", json={}).status_code == 200
    t = c.get("/metrics").text
    assert _valor(t, "upb_chain_height") == 1
    assert _valor(t, "upb_mempool_size") == 0
    assert _valor(t, "upb_blocks_mined_total") == 1
    assert _valor(t, "upb_chain_work") > trabajo
    assert _valor(t, "upb_mining_in_progress") == 0


def test_dos_apps_registros_independientes(tmp_path):
    a = make_app(tmp_path, "nodo_a")
    b = make_app(tmp_path, "nodo_b")
    ca, cb = TestClient(a), TestClient(b)
    assert ca.post("/blocks/mine", json={}).status_code == 200
    ta, tb = ca.get("/metrics").text, cb.get("/metrics").text
    assert _valor(ta, "upb_chain_height") == 1 and _valor(tb, "upb_chain_height") == 0
    assert _valor(ta, "upb_blocks_mined_total") == 1 and _valor(tb, "upb_blocks_mined_total") == 0
    assert 'node_id="nodo_a"' in ta and 'node_id="nodo_b"' in tb
    assert a.state.metrics_registry is not b.state.metrics_registry


def test_acceso_sin_llave_loopback_si_remoto_no(tmp_path):
    app = make_app(tmp_path)
    assert TestClient(app).get("/metrics").status_code == 200
    assert TestClient(app, client=REMOTO).get("/metrics").status_code == 403


def test_acceso_con_llave(tmp_path):
    app = make_app(tmp_path, admin_api_key="secreta")
    c = TestClient(app, client=REMOTO)
    assert c.get("/metrics").status_code == 401
    assert c.get("/metrics", headers={"X-API-Key": "mala"}).status_code == 401
    assert c.get("/metrics", headers={"X-API-Key": "secreta"}).status_code == 200


def test_metrics_public_abre_el_endpoint(tmp_path):
    app = make_app(tmp_path, metrics_public=True, admin_api_key="secreta")
    assert TestClient(app, client=REMOTO).get("/metrics").status_code == 200
    # Los endpoints de administración siguen protegidos.
    assert TestClient(app, client=REMOTO).post("/mempool/prune", json={}).status_code == 401


def test_tx_limitada_se_cuenta(tmp_path):
    app = make_app(tmp_path, tx_rate_limit=1)
    c = TestClient(app)
    ana = Wallet.generate()
    assert c.post("/transactions", json=_tx_firmada(ana, 1)).status_code == 200
    assert c.post("/transactions", json=_tx_firmada(ana, 2)).status_code == 429
    t = c.get("/metrics").text
    assert _valor(t, 'upb_tx_total{result="rate_limited"}') == 1
    assert _valor(t, 'upb_alerts{severity="WARNING"}') >= 1
