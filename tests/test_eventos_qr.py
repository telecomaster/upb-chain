"""Tests de P1-12: códigos QR de evento de un solo uso.

- Camino completo por la API: crear código → minar → reclamar firmado por el estudiante → minar → saldo.
- Un reclamo por dirección, cupo máximo, vencimiento por altura y presupuesto del emisor.
- Contra el front-running: la firma del evento liga la dirección; una TX copiada por otra
  dirección (o con la firma de otra) es inválida.
- Solo emisores registrados crean códigos.
- Determinismo: replace_chain, recarga desde disco y reorg.
"""
import base64
import os
from types import SimpleNamespace

os.environ.setdefault("NODE_PORT", "0")

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from httpx import ASGITransport, AsyncClient

from blockchain.contracts.tokens import claim_message
from blockchain.core.transaction import create_event_claim_transaction
from blockchain.core.wallet import Wallet
from security.crypto_utils import sign_data
from tests.helpers import make_app, mine_and_add, mine_candidate
from tests.test_tokens import _cadena, _foto

DIFICULTAD = 1


def _der(raw_hex: str) -> str:
    """Llave privada DER (como las de Wallet) a partir del escalar de 64 hex que lleva el QR."""
    key = ec.derive_private_key(int(raw_hex, 16), ec.SECP256K1())
    return key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption()).hex()


@pytest.fixture
def nodo(tmp_path):
    autoridad = Wallet.generate()
    fastapi = make_app(tmp_path, autoridad=autoridad, mining_difficulty=DIFICULTAD, tx_rate_limit=1000)
    return SimpleNamespace(fastapi=fastapi, node=fastapi.state.node, bc=fastapi.state.node.blockchain,
                           autoridad=autoridad, emisor=Wallet.generate(), ana=Wallet.generate(),
                           beto=Wallet.generate(), carla=Wallet.generate())


@pytest_asyncio.fixture
async def client(nodo):
    async with AsyncClient(transport=ASGITransport(app=nodo.fastapi), base_url="http://test") as ac:
        yield ac


async def _ok(r):
    assert r.status_code == 200, r.text
    return r.json()


async def _minar(client, n=1):
    for _ in range(n):
        await _ok(await client.post("/blocks/mine", json={}))


async def _emisor(client, nodo, presupuesto=100):
    await _ok(await client.post("/credentials/issuers", json={
        "issuer_address": nodo.emisor.address, "institution_code": "UPB"}))
    await _minar(client)
    await _ok(await client.post("/tokens/budget", json={
        "issuer_address": nodo.emisor.address, "amount": presupuesto}))
    await _minar(client)


async def _crear(client, nodo, monto=5, max_claims=2, expires_height=None, quien=None, **extra):
    quien = quien or nodo.emisor
    cuerpo = {"issuer_address": quien.address, "private_key_hex": quien.private_key_hex,
              "amount": monto, "max_claims": max_claims, "reason": "Feria de ciencias", **extra}
    if expires_height is not None:
        cuerpo["expires_height"] = expires_height
    return await client.post("/tokens/event-codes", json=cuerpo)


def _reclamo(nodo, codigo, estudiante, nonce=1, firmar_para=None):
    """TX EVENT_CODE_CLAIM; ``firmar_para``: dirección que liga la firma del evento (por defecto, la propia)."""
    sig = sign_data(claim_message(codigo["code_id"], firmar_para or estudiante.address),
                    _der(codigo["event_private_key"]))
    return create_event_claim_transaction(estudiante.address, codigo["code_id"], sig,
                                          estudiante.private_key_hex, nonce=nonce)


async def _enviar(client, tx):
    d = tx.to_dict()
    return await client.post("/transactions", json={k: d[k] for k in (
        "type", "sender", "recipient", "payload", "fee", "nonce", "timestamp", "signature", "public_key")})


@pytest.mark.integration
@pytest.mark.asyncio
async def test_api_crear_reclamar_minar_y_ver_saldo(client, nodo):
    await _emisor(client, nodo)
    codigo = await _ok(await _crear(client, nodo, monto=7, max_claims=3))
    assert codigo["claim_url"].endswith(f"evento={codigo['code_id']}&k={codigo['event_private_key']}")
    assert base64.b64decode(codigo["qr_png_base64"]).startswith(b"\x89PNG")
    assert (await client.get(f"/tokens/event-codes/{codigo['code_id']}")).status_code == 404  # sin confirmar
    await _minar(client)
    estado = await _ok(await client.get(f"/tokens/event-codes/{codigo['code_id']}"))
    assert (estado["status"], estado["claims_used"], estado["claims_left"], estado["amount"]) == ("OPEN", 0, 3, 7)
    assert "event_private_key" not in estado and "event_pubkey" not in estado

    await _ok(await _enviar(client, _reclamo(nodo, codigo, nodo.ana)))
    await _minar(client)
    assert (await _ok(await client.get(f"/tokens/{nodo.ana.address}")))["balance"] == 7
    estado = await _ok(await client.get(f"/tokens/event-codes/{codigo['code_id']}"))
    assert estado["claims_used"] == 1
    premio = (await _ok(await client.get(f"/tokens/{nodo.ana.address}")))["awards"][0]
    assert premio["reason"] == "Feria de ciencias" and premio["code_id"] == codigo["code_id"]
    presupuesto = await _ok(await client.get(f"/issuers/{nodo.emisor.address}/budget"))
    assert presupuesto["minted"] == 7 and presupuesto["remaining"] == 93
    assert nodo.bc.contract_state("accounts").total_supply == 7


@pytest.mark.integration
@pytest.mark.asyncio
async def test_reclamo_doble_se_rechaza(client, nodo):
    await _emisor(client, nodo)
    codigo = await _ok(await _crear(client, nodo, max_claims=5))
    await _minar(client)
    await _ok(await _enviar(client, _reclamo(nodo, codigo, nodo.ana, nonce=1)))
    await _minar(client)
    r = await _enviar(client, _reclamo(nodo, codigo, nodo.ana, nonce=2))
    assert r.status_code == 400 and "ya reclamó" in r.text
    # En el mismo bloque: la segunda TX de la misma dirección tampoco entra.
    codigo2 = await _ok(await _crear(client, nodo, max_claims=5))
    await _minar(client)
    await _ok(await _enviar(client, _reclamo(nodo, codigo2, nodo.beto, nonce=1)))
    r = await _enviar(client, _reclamo(nodo, codigo2, nodo.beto, nonce=2))
    assert r.status_code == 400 and "ya reclamó" in r.text


@pytest.mark.integration
@pytest.mark.asyncio
async def test_cupo_agotado(client, nodo):
    await _emisor(client, nodo)
    codigo = await _ok(await _crear(client, nodo, max_claims=1))
    await _minar(client)
    await _ok(await _enviar(client, _reclamo(nodo, codigo, nodo.ana)))
    await _minar(client)
    assert (await _ok(await client.get(f"/tokens/event-codes/{codigo['code_id']}")))["status"] == "EXHAUSTED"
    r = await _enviar(client, _reclamo(nodo, codigo, nodo.beto))
    assert r.status_code == 400 and "agotó" in r.text
    assert (await _ok(await client.get(f"/tokens/{nodo.beto.address}")))["balance"] == 0


@pytest.mark.integration
@pytest.mark.asyncio
async def test_reclamo_vencido_se_rechaza_en_api_y_en_bloque(client, nodo):
    await _emisor(client, nodo)
    altura = nodo.bc.contracts.height
    # El código se confirma en altura+1 y vence en altura+3: el reclamo cabe en el bloque altura+2 y altura+3.
    codigo = await _ok(await _crear(client, nodo, expires_height=altura + 3))
    await _minar(client)
    tx = _reclamo(nodo, codigo, nodo.ana)
    await _minar(client, 2)          # la cadena llega a altura+3: el próximo bloque (altura+4) ya venció
    assert (await _ok(await client.get(f"/tokens/event-codes/{codigo['code_id']}")))["status"] == "EXPIRED"
    r = await _enviar(client, tx)
    assert r.status_code == 400 and "venció" in r.text
    ok, motivo = mine_and_add(nodo.bc, [tx])      # minado a mano: el bloque entero es inválido
    assert not ok and "venció" in motivo
    # Dentro de plazo sí entra.
    codigo2 = await _ok(await _crear(client, nodo, expires_height=nodo.bc.contracts.height + 3))
    await _minar(client)
    await _ok(await _enviar(client, _reclamo(nodo, codigo2, nodo.beto)))


@pytest.mark.integration
@pytest.mark.asyncio
async def test_front_running_la_firma_liga_la_direccion(client, nodo):
    await _emisor(client, nodo)
    codigo = await _ok(await _crear(client, nodo, max_claims=5))
    await _minar(client)
    ana_tx = _reclamo(nodo, codigo, nodo.ana)
    # Beto ve la TX de Ana en el mempool y reenvía su claim_sig desde SU dirección.
    copia = create_event_claim_transaction(nodo.beto.address, codigo["code_id"],
                                           ana_tx.payload["claim_sig"], nodo.beto.private_key_hex, nonce=1)
    r = await _enviar(client, copia)
    assert r.status_code == 400 and "claim_sig" in r.text
    # Firmar con la dirección ajena tampoco sirve, y una firma con otra llave menos.
    assert (await _enviar(client, _reclamo(nodo, codigo, nodo.beto, firmar_para=nodo.ana.address))).status_code == 400
    ajena = create_event_claim_transaction(
        nodo.beto.address, codigo["code_id"],
        sign_data(claim_message(codigo["code_id"], nodo.beto.address), nodo.beto.private_key_hex),
        nodo.beto.private_key_hex, nonce=1)
    assert (await _enviar(client, ajena)).status_code == 400
    # La TX original de Ana sigue valiendo y la copia no le quitó el cupo.
    await _ok(await _enviar(client, ana_tx))
    await _minar(client)
    assert (await _ok(await client.get(f"/tokens/{nodo.ana.address}")))["balance"] == 5
    assert (await _ok(await client.get(f"/tokens/{nodo.beto.address}")))["balance"] == 0


@pytest.mark.integration
@pytest.mark.asyncio
async def test_solo_emisores_registrados_crean_codigos(client, nodo):
    await _emisor(client, nodo)
    r = await _crear(client, nodo, quien=nodo.ana)
    assert r.status_code == 400 and "emisor registrado" in r.text
    r = await _crear(client, nodo, monto=1, max_claims=1, code_id="con|barra")
    assert r.status_code == 400
    ok = await _ok(await _crear(client, nodo, code_id="EV-fijo"))
    await _minar(client)
    r = await _crear(client, nodo, code_id=ok["code_id"])
    assert r.status_code == 400 and "ya existe" in r.text


@pytest.mark.integration
@pytest.mark.asyncio
async def test_presupuesto_del_emisor_limita_los_reclamos(client, nodo):
    await _emisor(client, nodo, presupuesto=8)
    codigo = await _ok(await _crear(client, nodo, monto=5, max_claims=3))
    await _minar(client)
    await _ok(await _enviar(client, _reclamo(nodo, codigo, nodo.ana)))
    await _minar(client)
    r = await _enviar(client, _reclamo(nodo, codigo, nodo.beto))
    assert r.status_code == 400 and "Presupuesto" in r.text
    # Con más presupuesto el mismo reclamo pasa (el código sigue vigente).
    await _ok(await client.post("/tokens/budget", json={
        "issuer_address": nodo.emisor.address, "amount": 20}))
    await _minar(client)
    await _ok(await _enviar(client, _reclamo(nodo, codigo, nodo.beto)))


@pytest.mark.integration
@pytest.mark.asyncio
async def test_determinismo_replace_chain_recarga_y_reorg(client, nodo, tmp_path):
    await _emisor(client, nodo)
    codigo = await _ok(await _crear(client, nodo, monto=4, max_claims=2))
    await _minar(client)
    await _ok(await _enviar(client, _reclamo(nodo, codigo, nodo.ana)))
    await _ok(await _enviar(client, _reclamo(nodo, codigo, nodo.beto)))
    await _minar(client)
    assert nodo.bc.get_balance(nodo.ana.address) == 4

    b = _cadena(tmp_path / "otro", nodo.autoridad)
    ok, why = b.replace_chain([blk.to_dict() for blk in nodo.bc.chain])
    assert ok, why
    assert _foto(b) == _foto(nodo.bc)
    assert b.contract_state("tokens").event_codes == nodo.bc.contract_state("tokens").event_codes
    assert b.contract_state("tokens").event_codes[codigo["code_id"]]["claimed_by"] == [
        nodo.ana.address, nodo.beto.address]
    assert _foto(_cadena(tmp_path / "otro", nodo.autoridad)) == _foto(b)     # recarga desde disco

    # Reorg a una cadena más larga sin esa actividad: el código y los saldos desaparecen.
    d = _cadena(tmp_path / "d", nodo.autoridad)
    for _ in range(len(b.chain) + 1):
        ok, why = d.add_block(mine_candidate(d, None))
        assert ok, why
    ok, why = b.replace_chain([blk.to_dict() for blk in d.chain])
    assert ok, why
    assert b.contract_state("tokens").event_codes == {} and b.get_balance(nodo.ana.address) == 0
