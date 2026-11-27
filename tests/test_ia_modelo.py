"""Codificación de tipos, compatibilidad del modelo guardado y estado visible del detector."""
import os

os.environ.setdefault("NODE_PORT", "0")

import logging

import joblib
from httpx import ASGITransport, AsyncClient

from ai.anomaly.detector import TYPE_MAP, TransactionAnomalyDetector
from blockchain.core.transaction import TransactionType
from tests.helpers import make_app


def test_type_map_cubre_todos_los_tipos():
    assert set(TYPE_MAP) == {t.value for t in TransactionType}
    assert len(set(TYPE_MAP.values())) == len(TYPE_MAP)
    a = TransactionAnomalyDetector.base_features({"type": "BADGE_AWARD", "payload": {}, "timestamp": 1.0})
    b = TransactionAnomalyDetector.base_features({"type": "DATA_RECORD", "payload": {}, "timestamp": 1.0})
    assert a[4] != b[4]


def _entrenado(n=120):
    det = TransactionAnomalyDetector()
    txs = [{"type": "DATA_RECORD", "sender": f"s{i % 7}", "payload": {"i": i}, "fee": 1,
            "timestamp": 1_700_000_000.0 + i * 30} for i in range(n)]
    assert det.train(txs)["trained"]
    return det


def test_modelo_con_codificacion_vieja_se_ignora(tmp_path, caplog):
    det = _entrenado()
    ruta = tmp_path / "m.joblib"
    det.save(ruta)
    datos = joblib.load(ruta)
    datos["type_map"] = {"DATA_RECORD": 4}          # codificación anterior
    joblib.dump(datos, ruta)
    nuevo = TransactionAnomalyDetector()
    with caplog.at_level(logging.WARNING, logger="upb_chain.ai.anomaly"):
        assert nuevo.load(ruta) is False
    assert "incompatible" in caplog.text
    assert nuevo.get_stats()["mode"] == "heuristic"
    det.save(ruta)
    assert TransactionAnomalyDetector().load(ruta) is True


def test_min_samples_y_estado_del_modelo():
    det = TransactionAnomalyDetector()
    assert TransactionAnomalyDetector.MIN_SAMPLES >= 100
    res = det.train([{"type": "DATA_RECORD", "payload": {}, "timestamp": 1.0}] * 50)
    assert res["trained"] is False and res["min_samples"] == det.MIN_SAMPLES
    assert det.get_stats()["label"] == "heurística (sin entrenar)"
    assert _entrenado(120).get_stats()["label"] == "Isolation Forest entrenado (120 muestras)"


async def test_stats_endpoint_nodo_nuevo(tmp_path):
    app = make_app(tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://127.0.0.1") as c:
        r = (await c.get("/ai/anomaly/stats")).json()
    assert r["mode"] == "heuristic" and r["label"] == "heurística (sin entrenar)"
