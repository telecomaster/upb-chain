"""P1-9: tope del cuerpo HTTP (Content-Length y cuerpo chunked) y NET-005 con la config del nodo."""
import httpx
import pytest

from api.app import MAX_BODY_BYTES
from security.hardening import HardeningAuditor
from tests.helpers import make_app, make_settings


def _cliente(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1")


@pytest.mark.asyncio
async def test_content_length_excesivo_da_413(tmp_path):
    async with _cliente(make_app(tmp_path)) as c:
        r = await c.post("/transactions", content=b"x" * (MAX_BODY_BYTES + 1),
                         headers={"content-type": "application/json"})
        assert r.status_code == 413


@pytest.mark.asyncio
async def test_cuerpo_chunked_sin_content_length_da_413(tmp_path):
    async def trozos():
        for _ in range(MAX_BODY_BYTES // 65536 + 2):
            yield b"x" * 65536

    async with _cliente(make_app(tmp_path)) as c:
        r = await c.post("/transactions", content=trozos(),
                         headers={"content-type": "application/json"})
        assert r.status_code == 413


@pytest.mark.asyncio
async def test_cuerpo_normal_pasa(tmp_path):
    async with _cliente(make_app(tmp_path)) as c:
        r = await c.post("/transactions", json={})
        assert r.status_code != 413


def _net005(res):
    return next(i for i in res["items"] if i["id"] == "NET-005")["status"]


@pytest.mark.asyncio
async def test_net005_usa_la_config_del_nodo(tmp_path, monkeypatch):
    monkeypatch.delenv("P2P_ALLOWLIST", raising=False)
    monkeypatch.delenv("P2P_TLS", raising=False)
    s_ok = make_settings(tmp_path, "a", p2p_allowlist=["nodo_1"], p2p_tls="on")
    s_no = make_settings(tmp_path, "b")
    assert _net005(HardeningAuditor(settings=s_ok).run_audit()) == "PASS"
    assert _net005(HardeningAuditor(settings=s_no).run_audit()) == "FAIL"
    async with _cliente(make_app(tmp_path, "c")) as c:
        assert _net005((await c.get("/security/hardening")).json()) == "FAIL"
