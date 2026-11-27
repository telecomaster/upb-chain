"""Tests de P1-12: recompensas del laboratorio de ataques.

Camino completo por la API: correr el laboratorio con --direccion -> recibo -> POST
/laboratorio/recompensas (el servidor repite el escenario) -> minar -> saldo e insignia.
"""
import os
from types import SimpleNamespace

os.environ.setdefault("NODE_PORT", "0")

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from blockchain.core.wallet import Wallet
from scripts import laboratorio_ataques as cli
from security.attacks import recompensas
from tests.helpers import make_app

pytestmark = [pytest.mark.integration, pytest.mark.security]


@pytest.fixture
def nodo(tmp_path):
    autoridad = Wallet.generate()
    fastapi = make_app(tmp_path, autoridad=autoridad, mining_difficulty=1, tx_rate_limit=1000)
    return SimpleNamespace(fastapi=fastapi, emisor=Wallet.generate(), ana=Wallet.generate())


@pytest_asyncio.fixture
async def client(nodo):
    async with AsyncClient(transport=ASGITransport(app=nodo.fastapi), base_url="http://127.0.0.1") as ac:
        yield ac


async def _ok(r):
    assert r.status_code == 200, r.text
    return r.json()


async def _minar(client):
    await _ok(await client.post("/blocks/mine", json={}))


async def _preparar_emisor(client, nodo, presupuesto=100):
    await _ok(await client.post("/credentials/issuers", json={
        "issuer_address": nodo.emisor.address, "institution_code": "UPB"}))
    await _minar(client)
    await _ok(await client.post("/tokens/budget", json={
        "issuer_address": nodo.emisor.address, "amount": presupuesto}))
    await _minar(client)


def _cuerpo(nodo, recibo):
    return {"issuer_address": nodo.emisor.address, "private_key_hex": nodo.emisor.private_key_hex,
            "recibo": recibo}


@pytest.fixture(scope="module")
def recibo_ana():
    """Recibo real: corre el laboratorio (equivocación PBFT, ~4 s) con la CLI."""
    ana = Wallet.generate()
    resultado = cli.main(["--escenario", "equivocacion", "--consenso", "pbft", "--json",
                          "--direccion", ana.address])
    assert resultado["recibo"] is not None
    return ana, resultado["recibo"]


@pytest.mark.asyncio
async def test_recibo_real_da_puntos_e_insignia_una_sola_vez(client, nodo, recibo_ana):
    ana, recibo = recibo_ana
    await _preparar_emisor(client, nodo)
    cuerpo = _cuerpo(nodo, recibo)
    r = await _ok(await client.post("/laboratorio/recompensas", json=cuerpo))
    assert r["badge_id"] == "lab-equivocacion" and r["amount"] == recompensas.PUNTOS_POR_ESCENARIO
    # Mientras está pendiente tampoco se puede repetir (ni cobrar dos veces).
    assert (await client.post("/laboratorio/recompensas", json=cuerpo)).status_code in (400, 409)
    await _minar(client)
    saldo = await _ok(await client.get(f"/tokens/{ana.address}"))
    assert saldo["balance"] == recompensas.PUNTOS_POR_ESCENARIO
    insignias = (await _ok(await client.get(f"/badges/{ana.address}")))["badges"]
    assert [b["badge_id"] for b in insignias] == ["lab-equivocacion"]
    assert insignias[0]["reason"] == "laboratorio:equivocacion"
    # Repetir tras confirmar: 409 y el saldo no cambia.
    assert (await client.post("/laboratorio/recompensas", json=cuerpo)).status_code == 409
    await _minar(client)
    assert (await _ok(await client.get(f"/tokens/{ana.address}")))["balance"] == recompensas.PUNTOS_POR_ESCENARIO


@pytest.mark.asyncio
async def test_recibo_alterado_o_falsificado_se_rechaza(client, nodo, recibo_ana):
    ana, recibo = recibo_ana
    await _preparar_emisor(client, nodo)
    otra = Wallet.generate()
    # Cambiar la dirección sin recalcular el digest.
    alterado = {**recibo, "direccion": otra.address}
    r = await client.post("/laboratorio/recompensas", json=_cuerpo(nodo, alterado))
    assert r.status_code == 400 and "alterado" in r.json()["detail"]
    # Escenario sin recompensa (aunque el digest sea coherente).
    falso = {"version": 1, "escenario": "reorg", "consenso": "pow", "semilla": 1,
             "direccion": otra.address, "resumen": {}}
    falso["digest"] = recompensas._digest(falso)
    r = await client.post("/laboratorio/recompensas", json=_cuerpo(nodo, falso))
    assert r.status_code == 400 and "sin recompensa" in r.json()["detail"]
    # Sin digest.
    sin = {k: v for k, v in recibo.items() if k != "digest"}
    assert (await client.post("/laboratorio/recompensas", json=_cuerpo(nodo, sin))).status_code == 400
    await _minar(client)
    assert (await _ok(await client.get(f"/tokens/{otra.address}")))["balance"] == 0


@pytest.mark.asyncio
async def test_si_la_repeticion_no_cumple_el_logro_no_se_premia(client, nodo, recibo_ana, monkeypatch):
    ana, recibo = recibo_ana
    await _preparar_emisor(client, nodo)
    monkeypatch.setattr(recompensas, "verificar_repitiendo", lambda r: False)
    import api.app as app_mod
    monkeypatch.setattr(app_mod, "verificar_repitiendo", lambda r: False)
    r = await client.post("/laboratorio/recompensas", json=_cuerpo(nodo, recibo))
    assert r.status_code == 400 and "no se cumplió" in r.json()["detail"]
    await _minar(client)
    assert (await _ok(await client.get(f"/tokens/{ana.address}")))["balance"] == 0


@pytest.mark.asyncio
async def test_solo_un_emisor_con_presupuesto_puede_recompensar(client, nodo, recibo_ana):
    _, recibo = recibo_ana
    # Sin emisor registrado ni presupuesto.
    r = await client.post("/laboratorio/recompensas", json=_cuerpo(nodo, recibo))
    assert r.status_code == 400 and "presupuesto" in r.json()["detail"]
    # Emisor registrado pero sin presupuesto suficiente.
    await _preparar_emisor(client, nodo, presupuesto=recompensas.PUNTOS_POR_ESCENARIO - 1)
    r = await client.post("/laboratorio/recompensas", json=_cuerpo(nodo, recibo))
    assert r.status_code == 400 and "presupuesto" in r.json()["detail"]


def test_la_cli_no_da_recibo_si_el_escenario_no_es_premiable():
    assert recompensas.construir_recibo({"escenario": "reorg", "consenso": "pow"}, "UPBX") is None
    assert recompensas.construir_recibo(
        {"escenario": "sybil", "consenso": "pbft", "exito_ataque": True}, "UPBX") is None
