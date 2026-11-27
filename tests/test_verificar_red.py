"""Pruebas de scripts/verificar_red.py (P1-10) contra apps reales de ``make_app`` y datos sintéticos."""
import copy
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import verificar_red as vr  # noqa: E402
from tests.helpers import make_app  # noqa: E402


def _fetch_de(clientes, alterar=None):
    """Fetch que atiende ``http://nodo_x`` con el TestClient de cada app (sin red real)."""
    def fetch(base, ruta, cab, timeout):
        if base not in clientes:
            raise OSError("conexión rechazada")
        r = clientes[base].get(ruta)
        cuerpo = r.json() if r.status_code == 200 else None
        if alterar and cuerpo is not None:
            cuerpo = alterar(base, ruta, copy.deepcopy(cuerpo))
        return r.status_code, cuerpo
    return fetch


@pytest.fixture
def red(tmp_path):
    apps = {f"http://nodo_{c}": make_app(tmp_path, f"nodo_{c}") for c in "abc"}
    clientes = {u: TestClient(a) for u, a in apps.items()}
    for c in clientes.values():
        c.__enter__()
    yield clientes
    for c in clientes.values():
        c.__exit__(None, None, None)


def _estado(chequeos):
    return {c.nombre: c.estado for c in chequeos}


def test_red_pow_coherente_pasa(red):
    res = vr.verificar(list(red), fetch=_fetch_de(red), pares_min=0, reintentos_altura=1)
    e = _estado(res)
    assert all(v != vr.FAIL for v in e.values()), vr.tabla(res)
    assert e["génesis"] == vr.OK and e["consenso"] == vr.OK and e["P2P TLS"] == vr.OK
    assert "PBFT" in e and e["reloj"] == vr.OK


def test_nodo_caido_es_fallo(red):
    urls = list(red) + ["http://nodo_caido"]
    res = vr.verificar(urls, fetch=_fetch_de(red), pares_min=0, reintentos_altura=1)
    e = _estado(res)
    assert e["salud http://nodo_caido"] == vr.FAIL and e["salud (/health)"] == vr.FAIL


def test_genesis_distinto_es_fallo(red):
    def alterar(base, ruta, cuerpo):
        if base.endswith("_b") and ruta == "/health":
            cuerpo["genesis_hash"] = "ab" * 32
        return cuerpo
    res = vr.verificar(list(red), fetch=_fetch_de(red, alterar), pares_min=0, reintentos_altura=1)
    assert _estado(res)["génesis"] == vr.FAIL


def test_consenso_y_tls_distintos_son_fallo(red):
    def alterar(base, ruta, cuerpo):
        if base.endswith("_c"):
            if ruta == "/consensus":
                cuerpo["mode"] = "pbft"
            if ruta == "/health":
                cuerpo["p2p_tls"] = "on"
        return cuerpo
    e = _estado(vr.verificar(list(red), fetch=_fetch_de(red, alterar), pares_min=0,
                             reintentos_altura=1))
    assert e["consenso"] == vr.FAIL and e["P2P TLS"] == vr.FAIL


def test_desfase_de_reloj_es_fallo(red):
    def alterar(base, ruta, cuerpo):
        if base.endswith("_a") and ruta == "/health":
            cuerpo["timestamp"] += 60
        return cuerpo
    res = vr.verificar(list(red), fetch=_fetch_de(red, alterar), pares_min=0, reintentos_altura=1)
    assert _estado(res)["reloj"] == vr.FAIL


def test_pares_insuficientes_es_fallo(red):
    # Por defecto se exige N-1 pares activos y las apps aisladas no tienen ninguno.
    res = vr.verificar(list(red), fetch=_fetch_de(red), reintentos_altura=1)
    assert _estado(res)["pares P2P"] == vr.FAIL


def test_alturas_divergentes_se_reintentan_y_fallan():
    def fetch(base, ruta, cab, timeout):
        h = {"http://a": 5, "http://b": 9}[base]
        if ruta == "/health":
            return 200, {"status": "ok", "height": h, "timestamp": vr.time.time(),
                         "genesis_hash": "g", "consensus": "pow", "p2p_tls": "off"}
        if ruta == "/consensus":
            return 200, {"mode": "pow"}
        return 200, {"active_peers": 1}
    pausas = []
    res = vr.verificar(["http://a", "http://b"], fetch=fetch, reintentos_altura=3,
                       dormir=pausas.append)
    assert _estado(res)["alturas"] == vr.FAIL and len(pausas) == 3


def _muestra_pbft(url, rid, replicas, **kw):
    cons = {"mode": "pbft", "is_replica": True, "replica_id": rid, "view": 0, "primary": "n1",
            "n": 4, "f": 1, "quorum": 3, "replicas": replicas}
    cons.update(kw)
    return vr.Muestra(url, health={"height": 3, "timestamp": 1000.0, "genesis_hash": "g",
                                   "p2p_tls": "on", "consensus": "pbft"},
                      consenso=cons, red={"active_peers": 3}, genesis="g", reloj_s=0.0)


def _replicas(claves=("k1", "k2", "k3", "k4"), activas=4):
    return [{"id": f"n{i + 1}", "address": f"10.0.0.{i + 1}:8001", "public_key": k,
             "active": i < activas} for i, k in enumerate(claves)]


def test_pbft_coherente_pasa():
    ms = [_muestra_pbft(f"http://n{i}", f"n{i}", _replicas()) for i in range(1, 5)]
    res = vr.evaluar(ms)
    assert all(c.estado != vr.FAIL for c in res), vr.tabla(res)


def test_pbft_lista_de_replicas_distinta_es_fallo():
    ms = [_muestra_pbft(f"http://n{i}", f"n{i}", _replicas()) for i in range(1, 4)]
    ms.append(_muestra_pbft("http://n4", "n4", _replicas(claves=("k1", "k2", "k3", "otra"))))
    assert _estado(vr.evaluar(ms))["PBFT: conjunto de réplicas"] == vr.FAIL


def test_pbft_red_ociosa_sin_trafico_es_aviso_no_fallo():
    ms = [_muestra_pbft(f"http://n{i}", f"n{i}", _replicas(activas=2)) for i in range(1, 5)]
    assert _estado(vr.evaluar(ms))["PBFT: quórum alcanzable"] == vr.WARN


def test_pbft_nodo_que_no_es_replica_es_fallo():
    ms = [_muestra_pbft(f"http://n{i}", f"n{i}", _replicas()) for i in range(1, 5)]
    ms[2].consenso["is_replica"] = False
    assert _estado(vr.evaluar(ms))["PBFT: réplica propia"] == vr.FAIL


def test_cli_codigo_de_salida(red, monkeypatch, capsys):
    monkeypatch.setattr(vr, "fetch_http", _fetch_de(red))
    monkeypatch.setattr(vr, "verificar", lambda urls, **kw: vr.evaluar(
        [vr.leer_nodo(u, _fetch_de(red)) for u in urls], pares_min=0))
    assert vr.main(list(red)) == 0
    assert "RED LISTA" in capsys.readouterr().out
    assert vr.main(list(red) + ["http://nodo_caido"]) == 1


def test_health_expone_genesis_consenso_y_tls(red):
    from blockchain.core.block import GENESIS_HASH
    h = next(iter(red.values())).get("/health").json()
    assert h["genesis_hash"] == GENESIS_HASH and h["consensus"] == "pow" and h["p2p_tls"] == "off"
