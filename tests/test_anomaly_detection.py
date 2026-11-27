"""Tests de P1-6: dataset etiquetado, evaluación, modelo persistido y alertas ANOMALY."""
import os

os.environ.setdefault("NODE_PORT", "0")

import copy
import sys
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from ai.anomaly.dataset import extraer_matriz, generar_dataset
from ai.anomaly.detector import BlockAnomalyDetector, TransactionAnomalyDetector
from blockchain.core.transaction import Transaction, TransactionType
from blockchain.core.wallet import Wallet
from tests.helpers import make_app

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from evaluar_anomalias import evaluar  # noqa: E402

PEQUENO = dict(dias=6, tx_normales_por_dia=120, episodios_por_ataque=2)


@pytest.fixture
def fastapi(tmp_path):
    """App propia (create_app) con datos en tmp_path."""
    return make_app(tmp_path)


@pytest.fixture
def node(fastapi):
    return fastapi.state.node


@pytest_asyncio.fixture
async def client(fastapi):
    async with AsyncClient(transport=ASGITransport(app=fastapi), base_url="http://127.0.0.1") as ac:
        yield ac


def test_generador_determinista_por_semilla():
    a = generar_dataset(3, **PEQUENO)
    b = generar_dataset(3, **PEQUENO)
    c = generar_dataset(4, **PEQUENO)
    assert [(r.tx, r.label, r.attack) for r in a] == [(r.tx, r.label, r.attack) for r in b]
    assert [r.tx for r in a] != [r.tx for r in c]
    assert {r.attack for r in a} >= {"spam_burst", "replay", "new_address_flood", "huge_payload"}


def test_evaluacion_devuelve_metricas_en_rango():
    res = evaluar(seed=3, **PEQUENO)
    for b in [res["global"], *res["por_ataque"].values()]:
        for modelo in ("iforest", "heuristica"):
            for k, v in b[modelo].items():
                assert 0.0 <= v <= 1.0, (modelo, k, v)


def test_regla_hora_nocturna_corregida():
    # 02:00 hora de Bolivia (UTC-4) = 06:00 UTC del 2026-01-06
    ts_noche = 1767585600.0 + 86400 + 2 * 3600
    ts_dia = ts_noche + 10 * 3600
    det = TransactionAnomalyDetector()
    fn = lambda ts: det._heuristic_score(det.base_features({"payload": {}, "fee": 1, "timestamp": ts}))
    assert fn(ts_noche) == pytest.approx(0.1)
    assert fn(ts_dia) == 0.0
    assert det.base_features({"payload": {}, "fee": 3, "timestamp": ts_noche})[2] == 2   # fee int, hora de La Paz


def test_modelo_guardar_cargar_mismas_predicciones(tmp_path):
    regs = generar_dataset(5, **PEQUENO)
    det = TransactionAnomalyDetector()
    assert det.train([r.tx for r in regs])["trained"]
    ruta = tmp_path / "models" / "tx_iforest.joblib"
    det.save(ruta)
    otro = TransactionAnomalyDetector()
    assert otro.load(ruta)
    for r in regs[::17]:
        a, b = det.predict(r.tx), otro.predict(r.tx)
        assert (a.score, a.is_anomaly) == (b.score, b.is_anomaly)
    assert not TransactionAnomalyDetector().load(tmp_path / "no_existe.joblib")


def test_predict_no_muta_el_contexto():
    det = TransactionAnomalyDetector()
    tx = generar_dataset(1, **PEQUENO)[0].tx
    antes = det.extract_features(tx)
    det.predict(tx)
    det.predict(tx)
    assert det.extract_features(tx) == antes


def test_get_block_no_muta_detector(tmp_path):
    det = BlockAnomalyDetector()
    bloque = {"hash": "ab" * 32, "header": {"timestamp": 100.0, "difficulty": 1}, "transactions": []}
    det.record_block(bloque)
    snap = (list(det._block_times), list(det._block_sizes))
    det.peek_block(bloque)
    assert (det._block_times, det._block_sizes) == snap


@pytest.mark.asyncio
async def test_get_blocks_dos_veces_no_cambia_estado(client, node):
    det = node.block_anomaly_detector
    antes = (list(det._block_times), list(det._block_sizes))
    for _ in range(2):
        r = await client.get("/blocks/0")
        assert r.status_code == 200 and "anomaly" in r.json()
    assert (det._block_times, det._block_sizes) == antes


@pytest.mark.asyncio
async def test_tx_marcada_genera_alerta_anomaly_por_api(client, node):
    # Umbral bajo: un payload gigante (0,4 en la heurística) basta para marcarla.
    node.tx_anomaly_detector = TransactionAnomalyDetector(threshold=0.3)
    w = Wallet.generate()
    antes = len([a for a in node.security_monitor.get_alerts(limit=100000) if a["event_type"] == "ANOMALY"])
    tx = Transaction(type=TransactionType.DATA_RECORD, sender=w.address, recipient="DEST",
                     payload={"blob": "x" * 20000}, nonce=1)
    tx.sign(w.private_key_hex)
    body = {"type": tx.type.value, "sender": tx.sender, "recipient": tx.recipient, "payload": tx.payload,
            "fee": tx.fee, "timestamp": tx.timestamp, "signature": tx.signature,
            "public_key": tx.public_key, "nonce": tx.nonce}
    r = await client.post("/transactions", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["anomaly"]["is_anomaly"] is True
    alertas = [a for a in node.security_monitor.get_alerts(limit=100000) if a["event_type"] == "ANOMALY"]
    assert len(alertas) == antes + 1
    assert alertas[-1]["metadata"]["tx_id"] == tx.tx_id
    # y se ve en el endpoint público
    r2 = await client.get("/security/alerts")
    assert any(a["event_type"] == "ANOMALY" for a in r2.json()["alerts"])


@pytest.mark.asyncio
async def test_ai_train_guarda_modelo_y_se_carga(client, node, tmp_path):
    from types import SimpleNamespace
    regs = generar_dataset(2, **PEQUENO)
    falsa = SimpleNamespace(chain=[SimpleNamespace(transactions=[r.tx for r in regs])])
    ruta = tmp_path / "models" / "tx_iforest.joblib"
    node.blockchain = falsa
    node.anomaly_model_path = ruta
    node.tx_anomaly_detector = TransactionAnomalyDetector()
    r = await client.post("/ai/train", headers=_admin_headers(node))
    assert r.status_code == 200, r.text
    assert r.json()["trained"] and ruta.exists()
    assert TransactionAnomalyDetector().load(ruta)


def _admin_headers(node):
    key = node.settings.admin_api_key
    return {"X-API-Key": key} if key else {}
