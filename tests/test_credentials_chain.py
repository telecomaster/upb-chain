"""Tests de P0-6: credenciales derivadas de la cadena.

El estado del contrato debe ser la reproducción de las TXs confirmadas:
emitir deja la credencial PENDING, minar la confirma, un reinicio la conserva,
una revocación firmada la deja REVOCADA y dos nodos con la misma cadena derivan
el mismo estado. Los tests pasan por la API (httpx + ASGI) sobre una cadena en
tmp_path; nunca tocan data/.
"""
import os
import time
from types import SimpleNamespace

os.environ.setdefault("NODE_PORT", "0")

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from blockchain.contracts.credential import CredentialContract
from blockchain.core.block import GENESIS_AUTHORITY_ADDRESS, Block, BlockHeader
from blockchain.core.chain import Blockchain
from blockchain.core.transaction import (
    Transaction,
    TransactionType,
    create_credential_transaction,
    create_issuer_register_transaction,
    create_revoke_transaction,
)
from blockchain.core.wallet import Wallet
from tests.helpers import mine_and_add

pytestmark = pytest.mark.integration


def _datos(**extra) -> dict:
    base = {
        "student_name": "Carla Rojas",
        "program": "Ingeniería en Inteligencia Artificial",
        "degree": f"Licenciatura en IA {time.time_ns()}",
        "issue_date": "2026-06-10",
        "credential_type": "DEGREE",
        "grade": 90,
    }
    base.update(extra)
    return base


# Dificultad inicial baja (parámetro de la cadena) para que minar sea instantáneo.
DIFICULTAD = 1


def _cadena(directorio) -> Blockchain:
    return Blockchain(f"nodo_{directorio.name}", str(directorio), initial_difficulty=DIFICULTAD)


def _minar(bc: Blockchain) -> None:
    ok, reason = mine_and_add(bc)
    assert ok, reason


# ── Nodo de prueba: app real con cadena en tmp_path y autoridad de test ──────

@pytest.fixture
def nodo(tmp_path, monkeypatch):
    """Sustituye el estado global de api.app por una cadena en tmp_path.

    La autoridad es una wallet del test (el génesis de producción fija otra
    dirección, cuya llave privada no está en el repo). ``reiniciar()`` simula
    un reinicio del proceso: cadena y contrato nuevos desde el mismo directorio.
    """
    import api.app as app_mod
    autoridad = Wallet.generate()
    data_dir = str(tmp_path / "nodo")

    def reiniciar():
        bc, contrato = app_mod.build_node_state(data_dir, "nodo_test", autoridad.address,
                                                initial_difficulty=DIFICULTAD)
        monkeypatch.setattr(app_mod, "blockchain", bc)
        monkeypatch.setattr(app_mod, "credential_contract", contrato)
        return bc, contrato

    monkeypatch.setattr(app_mod, "authority_wallet", autoridad)
    reiniciar()
    return SimpleNamespace(app=app_mod, autoridad=autoridad, reiniciar=reiniciar)


@pytest_asyncio.fixture
async def client(nodo):
    async with AsyncClient(transport=ASGITransport(app=nodo.app.app),
                           base_url="http://test") as ac:
        yield ac


async def _emitir(client, emisor, estudiante, datos=None):
    return await client.post("/credentials/issue", json={
        "issuer_address": emisor.address,
        "student_address": estudiante.address,
        "private_key_hex": emisor.private_key_hex,
        "credential_data": datos or _datos(),
    })


async def _revocar(client, quien, credential_id, motivo="Error administrativo"):
    return await client.post("/credentials/revoke", json={
        "credential_id": credential_id,
        "revoker_address": quien.address,
        "private_key_hex": quien.private_key_hex,
        "reason": motivo,
    })


async def _minar_api(client):
    r = await client.post("/blocks/mine", json={})
    assert r.status_code == 200, r.text
    return r.json()["block"]["header"]["index"]


async def _registrar(client, emisor):
    r = await client.post("/credentials/issuers",
                          json={"issuer_address": emisor.address, "institution_code": "UPB"})
    assert r.status_code == 200, r.text
    return r


# ── Flujo completo por la API ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_flujo_emitir_minar_reiniciar_revocar(client, nodo):
    emisor, estudiante = Wallet.generate(), Wallet.generate()

    r = await _registrar(client, emisor)
    assert r.json()["status"] == "PENDING"

    # Emitir con el registro aún pendiente: se valida contra el estado especulativo.
    r = await _emitir(client, emisor, estudiante)
    assert r.status_code == 200, r.text
    cid = r.json()["credential_id"]
    assert r.json()["status"] == "PENDING"

    v = (await client.get(f"/credentials/verify/{cid}")).json()
    assert v["status"] == "PENDING" and v["valid"] is False
    # La API no mutó el estado confirmado.
    assert nodo.app.credential_contract.get_stats()["total_credentials"] == 0

    bloque = await _minar_api(client)
    v = (await client.get(f"/credentials/verify/{cid}")).json()
    assert v["status"] == "CONFIRMED" and v["verdict"] == "VÁLIDA" and v["valid"] is True
    assert v["block_index"] == bloque
    assert v["confirmations"] == 1
    assert v["credential"]["student_address"] == estudiante.address

    await _minar_api(client)
    v = (await client.get(f"/credentials/verify/{cid}")).json()
    assert v["confirmations"] == 2

    # Reinicio: cadena y contrato nuevos desde el mismo directorio.
    nodo.reiniciar()
    v = (await client.get(f"/credentials/verify/{cid}")).json()
    assert v["status"] == "CONFIRMED" and v["valid"] is True
    assert v["block_index"] == bloque and v["confirmations"] == 2

    r = await _revocar(client, emisor, cid)
    assert r.status_code == 200, r.text
    v = (await client.get(f"/credentials/verify/{cid}")).json()
    assert v["status"] == "CONFIRMED" and v["pending_revocation"] is True

    bloque_rev = await _minar_api(client)
    v = (await client.get(f"/credentials/verify/{cid}")).json()
    assert v["status"] == "REVOKED" and v["verdict"] == "REVOCADA" and v["valid"] is False
    assert v["credential"]["revocation_block"] == bloque_rev

    nodo.reiniciar()
    v = (await client.get(f"/credentials/verify/{cid}")).json()
    assert v["status"] == "REVOKED"


@pytest.mark.asyncio
async def test_registro_de_emisor_no_autorizado_rechazado(client, nodo):
    intruso, emisor = Wallet.generate(), Wallet.generate()

    # TX ISSUER_REGISTER firmada por alguien que no es la autoridad.
    tx = create_issuer_register_transaction(intruso.address, emisor.address, "UPB",
                                            intruso.private_key_hex)
    r = await client.post("/transactions", json={
        "type": tx.type.value, "sender": tx.sender, "recipient": tx.recipient,
        "payload": tx.payload, "fee": tx.fee, "timestamp": tx.timestamp,
        "signature": tx.signature, "public_key": tx.public_key,
    })
    assert r.status_code == 400
    assert "autoridad" in r.json()["detail"]

    # Sin registro, el emisor no puede emitir.
    r = await _emitir(client, emisor, Wallet.generate())
    assert r.status_code == 400
    assert "no registrado" in r.json()["detail"]

    # Un nodo sin la llave de autoridad no registra emisores.
    nodo.app.authority_wallet = None
    r = await client.post("/credentials/issuers",
                          json={"issuer_address": emisor.address, "institution_code": "UPB"})
    assert r.status_code == 503


@pytest.mark.asyncio
async def test_revocacion_por_tercero_rechazada_y_por_autoridad_aceptada(client, nodo):
    emisor, estudiante, tercero = Wallet.generate(), Wallet.generate(), Wallet.generate()
    await _registrar(client, emisor)
    cid = (await _emitir(client, emisor, estudiante)).json()["credential_id"]
    await _minar_api(client)

    r = await _revocar(client, tercero, cid)
    assert r.status_code == 400
    # El estudiante tampoco puede revocar su credencial.
    r = await _revocar(client, estudiante, cid)
    assert r.status_code == 400

    r = await _revocar(client, nodo.autoridad, cid, "Fraude comprobado")
    assert r.status_code == 200, r.text
    await _minar_api(client)
    v = (await client.get(f"/credentials/verify/{cid}")).json()
    assert v["status"] == "REVOKED"
    assert v["credential"]["revocation_reason"] == "Fraude comprobado"


@pytest.mark.asyncio
async def test_credencial_duplicada_rechazada(client):
    emisor, estudiante = Wallet.generate(), Wallet.generate()
    await _registrar(client, emisor)
    datos = _datos()
    assert (await _emitir(client, emisor, estudiante, datos)).status_code == 200
    # Duplicada contra el mempool…
    assert (await _emitir(client, emisor, estudiante, datos)).status_code == 400
    await _minar_api(client)
    # …y contra el estado confirmado.
    assert (await _emitir(client, emisor, estudiante, datos)).status_code == 400


@pytest.mark.asyncio
async def test_verificar_inexistente(client):
    v = (await client.get("/credentials/verify/no_existe_abc")).json()
    assert v["status"] == "NOT_FOUND" and v["valid"] is False


# ── Dos nodos: misma cadena ⇒ mismo estado ───────────────────────────────────

def _estado(contrato: CredentialContract) -> dict:
    return {
        "emisores": dict(contrato._issuer_registry),
        "credenciales": sorted((c["credential_id"], c["status"], c["block_number"])
                               for c in contrato.get_all_credentials()),
        "altura": contrato.height,
    }


def test_dos_nodos_derivan_el_mismo_estado(tmp_path):
    autoridad, emisor = Wallet.generate(), Wallet.generate()
    a = _cadena(tmp_path / "a")
    ca = CredentialContract(authority_address=autoridad.address)
    a.register_state_listener(ca)

    ok, why = a.add_transaction(create_issuer_register_transaction(
        autoridad.address, emisor.address, "UPB", autoridad.private_key_hex))
    assert ok, why
    txs = [create_credential_transaction(emisor.address, Wallet.generate().address,
                                         _datos(), emisor.private_key_hex) for _ in range(3)]
    for tx in txs:
        assert a.add_transaction(tx)[0]
    _minar(a)
    cid = ca.credential_id_of_tx(txs[0].to_dict())
    assert a.add_transaction(create_revoke_transaction(emisor.address, cid, "x",
                                                       emisor.private_key_hex))[0]
    _minar(a)
    assert ca.get_stats()["total_credentials"] == 3 and ca.get_stats()["revoked"] == 1

    # Nodo B recibe la cadena por replace_chain.
    b = _cadena(tmp_path / "b")
    cb = CredentialContract(authority_address=autoridad.address)
    b.register_state_listener(cb)
    ok, why = b.replace_chain([blk.to_dict() for blk in a.chain])
    assert ok, why
    assert _estado(cb) == _estado(ca)

    # Nodo C arranca desde el chain.json de A.
    c = _cadena(tmp_path / "a")
    cc = CredentialContract(authority_address=autoridad.address)
    c.register_state_listener(cc)
    assert _estado(cc) == _estado(ca)


# ── Reproducción: TXs inválidas dentro de un bloque se ignoran ───────────────

def _bloque(index, prev, txs):
    h = BlockHeader(index=index, timestamp=1767225600.0 + index * 10, previous_hash=prev.hash,
                    merkle_root=Block.compute_merkle_root(txs), node_id="x")
    return Block(header=h, transactions=txs)


def test_reproduccion_ignora_txs_invalidas_de_forma_determinista():
    autoridad, emisor, intruso = Wallet.generate(), Wallet.generate(), Wallet.generate()
    alumno = Wallet.generate().address

    registro_falso = create_issuer_register_transaction(
        intruso.address, intruso.address, "UPB", intruso.private_key_hex).to_dict()
    # Sin firma pero declarando ser la autoridad: debe ignorarse aunque llegue en un bloque.
    sin_firma = Transaction(TransactionType.ISSUER_REGISTER, autoridad.address, intruso.address,
                            {"issuer_address": intruso.address, "institution_code": "UPB"}).to_dict()
    registro = create_issuer_register_transaction(
        autoridad.address, emisor.address, "UPB", autoridad.private_key_hex).to_dict()
    datos = _datos()
    emision = create_credential_transaction(emisor.address, alumno, datos,
                                            emisor.private_key_hex).to_dict()
    duplicada = create_credential_transaction(emisor.address, alumno, datos,
                                              emisor.private_key_hex).to_dict()
    emision_intruso = create_credential_transaction(intruso.address, alumno, _datos(),
                                                    intruso.private_key_hex).to_dict()

    g = Block.create_genesis()
    b1 = _bloque(1, g, [registro_falso, sin_firma, registro, emision, duplicada, emision_intruso])
    cid = CredentialContract().credential_id_of_tx(emision)
    revoca_intruso = create_revoke_transaction(intruso.address, cid, "x",
                                               intruso.private_key_hex).to_dict()
    b2 = _bloque(2, b1, [revoca_intruso])

    estados = []
    for _ in range(2):
        contrato = CredentialContract(authority_address=autoridad.address)
        contrato.rebuild([g, b1, b2])
        estados.append(_estado(contrato))
        assert list(contrato._issuer_registry) == [emisor.address]
        assert contrato.get_stats()["total_credentials"] == 1
        assert contrato.credential_status(cid)["status"] == "CONFIRMED"
        assert contrato.credential_status(cid)["confirmations"] == 2
    assert estados[0] == estados[1]


def test_contrato_por_defecto_usa_la_autoridad_del_genesis():
    assert GENESIS_AUTHORITY_ADDRESS.startswith("UPB")
    assert CredentialContract().authority_address == GENESIS_AUTHORITY_ADDRESS
    assert Block.create_genesis().transactions[0]["authority_address"] == GENESIS_AUTHORITY_ADDRESS


def test_load_authority_wallet_rechaza_llave_ajena(tmp_path):
    import api.app as app_mod
    w = Wallet.generate()
    ruta = tmp_path / "authority.json"
    w.export(str(ruta))
    assert app_mod.load_authority_wallet(str(ruta), w.address).address == w.address
    assert app_mod.load_authority_wallet(str(ruta), GENESIS_AUTHORITY_ADDRESS) is None
    assert app_mod.load_authority_wallet(str(tmp_path / "no_existe.json"), w.address) is None
