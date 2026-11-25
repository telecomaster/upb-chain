"""P1-9: endpoints de administración protegidos y CORS restringido."""
import dataclasses

import pytest
from fastapi.testclient import TestClient

from api import app as api_app

REMOTO = ("10.0.0.5", 1234)


def _con_llave(monkeypatch, llave):
    monkeypatch.setattr(api_app, "settings",
                        dataclasses.replace(api_app.settings, admin_api_key=llave))


def _remoto():
    return TestClient(api_app.app, client=REMOTO)


def test_llave_ausente_o_incorrecta_401(monkeypatch):
    _con_llave(monkeypatch, "secreta")
    c = _remoto()
    assert c.post("/mempool/prune", json={}).status_code == 401
    r = c.post("/mempool/prune", json={}, headers={"X-API-Key": "mala"})
    assert r.status_code == 401


def test_llave_correcta_200(monkeypatch):
    _con_llave(monkeypatch, "secreta")
    r = _remoto().post("/mempool/prune", json={}, headers={"X-API-Key": "secreta"})
    assert r.status_code == 200


def test_llave_exigida_incluso_en_loopback(monkeypatch):
    _con_llave(monkeypatch, "secreta")
    assert TestClient(api_app.app).post("/mempool/prune", json={}).status_code == 401


def test_sin_llave_remoto_403(monkeypatch):
    _con_llave(monkeypatch, "")
    c = _remoto()
    for ruta in ["/mempool/prune", "/blocks/mine", "/credentials/issuers",
                 "/network/sync", "/network/peers", "/ai/train"]:
        assert c.post(ruta, json={}).status_code == 403, ruta


def test_sin_llave_loopback_permitido(monkeypatch):
    _con_llave(monkeypatch, "")
    assert TestClient(api_app.app).post("/mempool/prune", json={}).status_code == 200
    assert TestClient(api_app.app, client=("127.0.0.1", 1)).post(
        "/mempool/prune", json={}).status_code == 200


def test_endpoints_publicos_no_afectados(monkeypatch):
    _con_llave(monkeypatch, "secreta")
    c = _remoto()
    assert c.get("/health").status_code == 200
    assert c.get("/blocks").status_code == 200
    assert c.post("/wallet/generate").status_code == 200
    assert c.get("/credentials/verify/no_existe").status_code != 401
    assert c.get("/verify/no_existe").status_code != 401


def test_cors_solo_origenes_permitidos():
    c = TestClient(api_app.app)
    propio = f"http://localhost:{api_app.API_PORT}"
    ok = c.get("/health", headers={"Origin": propio})
    assert ok.headers.get("access-control-allow-origin") == propio
    mal = c.get("/health", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in mal.headers
