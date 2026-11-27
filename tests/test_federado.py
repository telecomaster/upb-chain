"""Idea 6: detección federada de anomalías (resúmenes, puntaje, alerta k-de-n, límites)."""
import math
import time

import pytest
from fastapi.testclient import TestClient

from ai.anomaly import federated as fed
from ai.anomaly.dataset import generar_dataset
from ai.anomaly.detector import TYPE_MAP, TransactionAnomalyDetector
from blockchain.network.node import MSG_AI_FLAG, P2PNode
from tests.helpers import make_app, make_settings

MV = TransactionAnomalyDetector.MODEL_VERSION


def _resumen(n, med, mad):
    return {"v": 1, "model_version": MV, "features": fed.FED_NAMES, "type_map_hash": fed.hash_tipos(TYPE_MAP),
            "n": n, "mediana": med, "mad": mad}


def _esperar(cond, timeout=10.0):
    limite = time.time() + timeout
    while time.time() < limite:
        if cond():
            return True
        time.sleep(0.05)
    return cond()


# ── Matemática ───────────────────────────────────────────────────────────────

def test_agregar_pondera_por_muestras_y_agrupa_varianza():
    a = _resumen(100, [1, 2, 0, 0, 0], [0, 0, 0, 0, 0])
    b = _resumen(300, [3, 2, 0, 0, 0], [0, 1, 0, 0, 0])
    ref = fed.agregar([a, b])
    assert ref["n"] == 400 and ref["nodos"] == 2
    assert ref["mediana"][0] == pytest.approx(2.5)           # (100*1 + 300*3) / 400
    # varianza agrupada: 0.25*(0+1.5^2) + 0.75*(0+0.5^2) = 0.75
    assert ref["escala"][0] == pytest.approx(math.sqrt(0.75), abs=1e-5)
    assert ref["escala"][1] == pytest.approx(math.sqrt(0.75), abs=1e-5)   # sólo b aporta mad=1 (peso 0,75)
    assert fed.agregar([None]) is None


def test_puntaje_es_el_maximo_z_robusto_y_respeta_escala_minima():
    ref = {"mediana": [5.0, 0, 0, 0, 0], "escala": [1.0, 0, 0, 0, 0]}
    x = [0] * 9
    x[0] = 5 + 3 * 1.4826          # z = 3 en payload_size
    x[5] = 2.0                     # escala 0 -> piso 0.5 -> z = 4 en sender_rate
    z, det = fed.puntaje(x, ref)
    assert z == pytest.approx(4.0) and det[0]["caracteristica"] == "sender_rate"
    assert [d["caracteristica"] for d in det][:2] == ["sender_rate", "payload_size"]


def test_resumen_del_detector_es_compacto_y_sin_datos():
    det = TransactionAnomalyDetector()
    assert det.federated_summary() is None
    txs = [r.tx for r in generar_dataset(7, 3, 120)]
    assert det.train(txs)["trained"]
    r = det.federated_summary()
    assert r["n"] == len(txs) and len(r["mediana"]) == len(fed.FED_IDX)
    assert fed.validar_resumen(r, fed.hash_tipos(TYPE_MAP), MV) is None
    assert len(str(r)) < fed.MAX_RESUMEN_BYTES and "tx_id" not in str(r)


def test_validar_resumen_rechaza_malformados():
    h = fed.hash_tipos(TYPE_MAP)
    ok = _resumen(10, [0] * 5, [0] * 5)
    assert fed.validar_resumen(ok, h, MV) is None
    for malo in [{**ok, "n": 0}, {**ok, "n": True}, {**ok, "mediana": [0] * 4}, {**ok, "mad": [-1, 0, 0, 0, 0]},
                 {**ok, "mediana": [float("nan")] * 5}, {**ok, "type_map_hash": "x"}, {**ok, "v": 9},
                 {**ok, "extra": "x" * 5000}, "no", None]:
        assert fed.validar_resumen(malo, h, MV), malo


# ── k-de-n y límites ─────────────────────────────────────────────────────────

class Reloj:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def _f(k=2, reloj=None):
    return fed.FederadoIA("A", k=k, ventana=100, type_map=TYPE_MAP, model_version=MV, reloj=reloj or Reloj())


FLAG = {"tx_id": "t1", "sender": "s1", "score": 0.9, "z": 7.0, "top": ["fee"]}


def test_alerta_con_k_nodos_distintos_una_sola_vez():
    f = _f(k=2)
    assert f.recibir_flag("B", FLAG) == []                    # 1 nodo
    assert f.recibir_flag("B", FLAG) == []                    # el mismo nodo no cuenta dos veces
    alertas = f.recibir_flag("C", FLAG)
    assert [a["clave"] for a in alertas] == ["tx:t1"]
    assert alertas[0]["nodos"] == ["B", "C"]
    assert f.recibir_flag("D", FLAG) == []                    # ya alertada: dedupe


def test_marca_propia_cuenta_como_un_nodo_y_k3_exige_tres():
    f = _f(k=3)
    f.marcar_local("t1", "s1", 0.9, 7, ["fee"])
    assert f.recibir_flag("B", FLAG) == []
    assert f.recibir_flag("C", FLAG)


def test_ventana_expira_y_emisor_agrupa_txs_distintas():
    r = Reloj()
    f = _f(reloj=r)
    f.recibir_flag("B", FLAG)
    r.t += 101
    assert f.recibir_flag("C", FLAG) == []                    # B ya salió de la ventana
    f2 = _f()
    f2.recibir_flag("B", {**FLAG, "tx_id": "x1"})
    alertas = f2.recibir_flag("C", {**FLAG, "tx_id": "x2"})   # distinto tx, mismo emisor
    assert [a["clave"] for a in alertas] == ["sender:s1"]


def test_banderas_invalidas_propias_y_tope_de_tasa():
    f = _f()
    for malo in [None, {}, {**FLAG, "score": "alto"}, {**FLAG, "tx_id": 5}, {**FLAG, "top": "x"},
                 {**FLAG, "x": "y" * 3000}, {**FLAG, "z": float("inf")}]:
        assert f.recibir_flag("B", malo) == []
    assert f.recibir_flag("A", FLAG) == []                    # eco de sí mismo
    assert f.rechazos >= 6
    for i in range(fed.MAX_FLAGS_POR_MIN + 20):
        f.recibir_flag("Z", {**FLAG, "tx_id": f"u{i}", "sender": f"u{i}"})
    assert len(f._tasa["Z"]) == fed.MAX_FLAGS_POR_MIN         # lo demás se descartó


def test_tope_de_pares_y_de_claves():
    f = _f()
    for i in range(fed.MAX_PARES + 10):
        f.recibir_resumen(f"P{i}", _resumen(5, [0] * 5, [0] * 5))
    assert len(f._peers) == fed.MAX_PARES
    g = _f()
    for i in range(fed.MAX_CLAVES + 50):
        g._registrar(f"k{i}", "B", 1.0)
    assert len(g._flags) == fed.MAX_CLAVES


# ── Apagado por defecto y costura P2P ────────────────────────────────────────

def test_apagado_por_defecto(tmp_path):
    app = make_app(tmp_path, "off")
    assert app.state.node.federated is None
    c = TestClient(app, base_url="http://127.0.0.1")
    assert c.get("/ai/federated").json() == {"enabled": False}
    assert c.post("/ai/federated/sync").status_code == 409
    app.state.node.on_ai_message(MSG_AI_FLAG, "B", FLAG)      # ignorado sin error


def _nodo(tmp_path, nombre, k=2):
    from api.app import build_node
    node = build_node(make_settings(tmp_path, nombre, federated_ai="on", federated_k=k), None)
    node.p2p.start()
    return node


def _txs(seed, n):
    return [r.tx for r in generar_dataset(seed, 4, 150) if not r.label][:n]


@pytest.fixture
def tres(tmp_path):
    nodos = [_nodo(tmp_path, n) for n in ("a", "b", "c")]
    for i, n in enumerate(nodos):
        for m in nodos:
            if m is not n:
                n.p2p.add_peer("127.0.0.1", m.p2p.port)
        assert n.tx_anomaly_detector.train(_txs(7 + i, 400))["trained"]
    assert _esperar(lambda: all(len(n.p2p.active_peers()) == 2 for n in nodos))
    yield nodos
    for n in nodos:
        n.p2p.stop()


GRANDE = {"tx_id": "tx-gran", "sender": "UPBsospechoso", "type": "DATA_RECORD", "fee": 90000,
          "payload": {"x": "z" * 40000}, "timestamp": 1_700_000_000.0}


def _alertas(n):
    return [x for x in n.security_monitor.get_alerts() if x["event_type"] == "FEDERATED_ANOMALY"]


def test_sync_reparte_resumenes_y_la_referencia_agrega_los_tres(tres):
    a, b, c = tres
    for n in tres:
        assert n.federated_sync()["enviados"] == 2
    assert _esperar(lambda: all(len(n.federated.estado()["pares"]) == 2 for n in tres))
    ref = a.federated.referencia()
    assert ref["nodos"] == 3 and ref["n"] == 1200
    assert "tx_id" not in str(a.federated.estado()["pares"])


def test_tres_nodos_alertan_cuando_k_marcan_la_misma_tx(tres):
    a, b, c = tres
    for n in tres:
        n.federated_sync()
    assert _esperar(lambda: all(len(n.federated.estado()["pares"]) == 2 for n in tres))
    a.federated_peer_tx(dict(GRANDE))          # A marca y difunde; con k=2 todavía no hay alerta en C
    assert _esperar(lambda: len(c.federated.estado()["banderas_recientes"]) == 1)
    assert not _alertas(c)
    b.federated_peer_tx(dict(GRANDE))          # B también: C ve 2 nodos distintos
    assert _esperar(lambda: _alertas(c))
    meta = _alertas(c)[0]["metadata"]
    assert meta["nodos"] == ["a", "b"] and meta["tx_id"] == "tx-gran"


def test_tx_normal_no_dispara_el_puntaje_federado(tres):
    a, _, _ = tres
    for n in tres:
        n.federated_sync()
    for tx in _txs(7, 30):
        a.federated_peer_tx(dict(tx))
    time.sleep(0.3)
    # el IF local puede marcar alguna (contamination = 5 %), pero el puntaje federado no se pasa del umbral
    assert all(b["z"] < fed.Z_UMBRAL for b in a.federated.estado()["banderas_recientes"])


def test_sin_tls_la_lista_blanca_filtra_ids_desconocidos():
    recibidos = []
    r = P2PNode("r", "127.0.0.1", 0, allowlist=["ok"], on_ai_message=lambda *a: recibidos.append(a))
    ok = P2PNode("ok", "127.0.0.1", 0)
    mal = P2PNode("mal", "127.0.0.1", 0)
    for n in (r, ok, mal):
        n.start()
    try:
        for n in (ok, mal):
            n.add_peer("127.0.0.1", r.port)
            assert _esperar(lambda n=n: n.active_peers())
        ok.broadcast_ai(MSG_AI_FLAG, {"node_id": "ok", **FLAG})
        mal.broadcast_ai(MSG_AI_FLAG, {"node_id": "mal", **FLAG})
        assert _esperar(lambda: recibidos)
        time.sleep(0.3)
        assert [x[1] for x in recibidos] == ["ok"]
    finally:
        for n in (r, ok, mal):
            n.stop()
