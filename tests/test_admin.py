"""P1-9: endpoints de administración protegidos y CORS restringido."""
import pytest
from fastapi.testclient import TestClient

from tests.helpers import make_app

REMOTO = ("10.0.0.5", 1234)


@pytest.fixture
def api_app(tmp_path):
    """App propia (create_app); cada test fija su ``admin_api_key``."""
    return make_app(tmp_path)


def _con_llave(app, llave):
    app.state.node.settings = app.state.node.settings.model_copy(update={"admin_api_key": llave})


def _remoto(app):
    return TestClient(app, client=REMOTO)


def test_llave_ausente_o_incorrecta_401(api_app):
    _con_llave(api_app, "secreta")
    c = _remoto(api_app)
    assert c.post("/mempool/prune", json={}).status_code == 401
    r = c.post("/mempool/prune", json={}, headers={"X-API-Key": "mala"})
    assert r.status_code == 401


def test_llave_correcta_200(api_app):
    _con_llave(api_app, "secreta")
    r = _remoto(api_app).post("/mempool/prune", json={}, headers={"X-API-Key": "secreta"})
    assert r.status_code == 200


def test_llave_exigida_incluso_en_loopback(api_app):
    _con_llave(api_app, "secreta")
    assert TestClient(api_app).post("/mempool/prune", json={}).status_code == 401


def test_sin_llave_remoto_403(api_app):
    _con_llave(api_app, "")
    c = _remoto(api_app)
    for ruta in ["/mempool/prune", "/blocks/mine", "/credentials/issuers",
                 "/network/sync", "/network/peers", "/ai/train"]:
        assert c.post(ruta, json={}).status_code == 403, ruta


def test_sin_llave_loopback_permitido(api_app):
    _con_llave(api_app, "")
    assert TestClient(api_app).post("/mempool/prune", json={}).status_code == 200
    assert TestClient(api_app, client=("127.0.0.1", 1)).post(
        "/mempool/prune", json={}).status_code == 200


def test_endpoints_publicos_no_afectados(api_app):
    _con_llave(api_app, "secreta")
    c = _remoto(api_app)
    assert c.get("/health").status_code == 200
    assert c.get("/blocks").status_code == 200
    assert c.post("/wallet/generate").status_code == 200
    assert c.get("/credentials/verify/no_existe").status_code != 401
    assert c.get("/verify/no_existe").status_code != 401


def test_cors_solo_origenes_permitidos(api_app):
    c = TestClient(api_app)
    propio = f"http://localhost:{api_app.state.node.settings.api_port}"
    ok = c.get("/health", headers={"Origin": propio})
    assert ok.headers.get("access-control-allow-origin") == propio
    mal = c.get("/health", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in mal.headers
