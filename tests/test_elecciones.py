"""Idea 8: elecciones estudiantiles (título, elegibilidad por credencial, estado y certificación)."""
from types import SimpleNamespace

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from blockchain.core.transaction import (
    create_credential_transaction, create_election_transaction, create_issuer_register_transaction,
    create_vote_transaction)
from blockchain.core.wallet import Wallet
from tests.helpers import make_app
from tests.test_canjes import _cadena, _datos, _ok


@pytest.fixture
def mundo(tmp_path):
    a, e, ana, beto = (Wallet.generate() for _ in range(4))
    bc = _cadena(tmp_path / "a", a)
    k = a.private_key_hex
    _ok(bc, [create_issuer_register_transaction(a.address, e.address, "UPB", k, nonce=1)])
    _ok(bc, [create_credential_transaction(e.address, ana.address, _datos("DEGREE"),
                                           e.private_key_hex, nonce=1)])
    return SimpleNamespace(bc=bc, a=a, e=e, ana=ana, beto=beto)


def _crear(m, nonce, inicio, fin, **extra):
    return create_election_transaction(m.a.address, "dir", ["x", "y"], "one_per_address", inicio, fin,
                                       m.a.private_key_hex, nonce=nonce, **extra)


def _voto(w, opcion, nonce):
    return create_vote_transaction(w.address, "dir", opcion, w.private_key_hex, nonce=nonce)


@pytest.mark.integration
def test_elegibilidad_por_credencial(mundo):
    m = mundo
    h = m.bc.contracts.height
    _ok(m.bc, [_crear(m, 2, h, h + 20, title="Centro", eligible_credential_type="DEGREE",
                      eligible_program="IA")])
    assert m.bc.contract_state("voting").configs["dir"]["title"] == "Centro"
    ok, why = m.bc.add_transaction(_voto(m.beto, "x", 1))
    assert not ok and "elegibilidad" in why
    ok, why = m.bc.add_transaction(_voto(m.ana, "x", 1))
    assert ok, why


@pytest.mark.integration
def test_elegibilidad_programa_distinto_y_titulo_invalido(mundo):
    m = mundo
    h = m.bc.contracts.height
    _ok(m.bc, [_crear(m, 2, h, h + 20, eligible_program="Derecho")])
    assert not m.bc.add_transaction(_voto(m.ana, "x", 1))[0]
    tx = create_election_transaction(m.a.address, "otra", ["x", "y"], "one_per_address", 0, 5,
                                     m.a.private_key_hex, nonce=3, title="")
    ok, why = m.bc.add_transaction(tx)
    assert not ok and "title" in why


@pytest_asyncio.fixture
async def api(tmp_path):
    a, ana = Wallet.generate(), Wallet.generate()
    app = make_app(tmp_path, autoridad=a, mining_difficulty=1, tx_rate_limit=1000)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield SimpleNamespace(c=c, a=a, ana=ana, bc=app.state.node.blockchain)


@pytest.mark.integration
async def test_api_estado_resultado_parcial_y_certificacion(api):
    c, bc = api.c, api.bc
    h = bc.contracts.height
    r = await c.post("/elections", json={
        "creator_address": api.a.address, "private_key_hex": api.a.private_key_hex,
        "election_id": "cd", "title": "Centro de estudiantes", "options": ["A", "B"],
        "weight_rule": "one_per_address", "start_height": h + 3, "end_height": h + 4})
    assert r.status_code == 200, r.text
    assert (await c.post("/blocks/mine", json={})).status_code == 200      # h+1: creada
    info = (await c.get("/elections/cd")).json()
    assert info["status"] == "pending" and info["title"] == "Centro de estudiantes"
    assert (await c.get("/elections/nada")).status_code == 404
    await c.post("/blocks/mine", json={})                                   # h+2: abre en h+3
    assert (await c.get("/elections/cd")).json()["status"] == "open"
    ok, why = bc.add_transaction(create_vote_transaction(
        api.a.address, "cd", "A", api.a.private_key_hex, nonce=bc.next_nonce(api.a.address)))
    assert ok, why
    await c.post("/blocks/mine", json={})                                   # h+3: voto
    parcial = (await c.get("/elections/cd")).json()
    assert parcial["status"] == "open" and parcial["tally"] is None
    assert parcial["turnout"]["voters"] == 1 and parcial["certification"] is None
    await c.post("/blocks/mine", json={})                                   # h+4: cierre
    final = (await c.get("/elections/cd")).json()
    assert final["status"] == "closed" and final["tally"] == {"A": 1, "B": 0}
    cert = final["certification"]
    assert cert["close_block_hash"] == bc.chain[h + 4].hash and len(cert["digest"]) == 64
    assert (await c.get("/elections")).json()["elections"][0]["status"] == "closed"
