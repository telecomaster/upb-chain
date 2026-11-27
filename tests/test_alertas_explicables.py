"""Tests de la Idea 7: alertas explicables con contribución por característica."""
import os

os.environ.setdefault("NODE_PORT", "0")

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from ai.anomaly.dataset import extraer_matriz, generar_dataset
from ai.anomaly.detector import TransactionAnomalyDetector
from blockchain.core.transaction import Transaction, TransactionType
from blockchain.core.wallet import Wallet
from tests.helpers import make_app

PEQUENO = dict(dias=6, tx_normales_por_dia=120, episodios_por_ataque=2)


@pytest.fixture
def fastapi(tmp_path):
    return make_app(tmp_path)


@pytest.fixture
def node(fastapi):
    return fastapi.state.node


@pytest_asyncio.fixture
async def client(fastapi):
    async with AsyncClient(transport=ASGITransport(app=fastapi), base_url="http://127.0.0.1") as ac:
        yield ac


def test_caracteristica_inflada_queda_primera_en_la_explicacion():
    regs = generar_dataset(7, **PEQUENO)
    X = extraer_matriz(regs)
    det = TransactionAnomalyDetector()
    det.fit_features(X, seed=7)
    x = list([x for r, x in zip(regs, X) if r.label == 0][len(X) // 2])
    x[1] = 5000          # fee gigante
    exp = det.explain_contributions(x)
    assert exp[0]["caracteristica"] == "fee" and exp[0]["contribucion"] > 0
    assert exp[0]["valor"] == 5000
    assert set(exp[0]) >= {"caracteristica", "valor", "referencia", "contribucion"}
    assert exp == det.explain_contributions(x)      # determinista


def test_heuristica_sin_modelo_explica_reglas():
    det = TransactionAnomalyDetector()
    rep = det.predict({"tx_id": "t", "sender": "a", "type": "DATA_RECORD", "fee": 500,
                       "payload": {"b": "x" * 20000}, "timestamp": 1767632400.0})
    assert rep.explicacion[0]["caracteristica"] == "payload_size"
    assert rep.explicacion[0]["contribucion"] == 0.4
    assert "payload_size" in rep.resumen and rep.to_dict()["explicacion"]


@pytest.mark.asyncio
async def test_alerta_anomaly_incluye_explicacion_por_api(client, node):
    node.tx_anomaly_detector = TransactionAnomalyDetector(threshold=0.3)
    w = Wallet.generate()
    tx = Transaction(type=TransactionType.DATA_RECORD, sender=w.address, recipient="DEST",
                     payload={"blob": "x" * 20000}, nonce=1)
    tx.sign(w.private_key_hex)
    body = {"type": tx.type.value, "sender": tx.sender, "recipient": tx.recipient, "payload": tx.payload,
            "fee": tx.fee, "timestamp": tx.timestamp, "signature": tx.signature,
            "public_key": tx.public_key, "nonce": tx.nonce}
    r = await client.post("/transactions", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["anomaly"]["explicacion"][0]["caracteristica"] == "payload_size"
    alertas = (await client.get("/security/alerts")).json()["alerts"]
    meta = [a for a in alertas if a["event_type"] == "ANOMALY"][-1]["metadata"]
    assert meta["explicacion"][0]["caracteristica"] == "payload_size" and meta["resumen"]
