"""Tests de P0-9: estado de cuentas (saldo, nonce, montos enteros).

El estado de cuentas es la reproducción de la cadena (como el contrato de
credenciales, P0-6) pero es regla de CONSENSO: una TX repetida, sin saldo o con
nonce incorrecto se rechaza en la API (400) y un bloque que la contenga se
rechaza entero. Los tests pasan por la API (httpx + ASGI) y por dos cadenas.
"""
import os
import time
from types import SimpleNamespace

os.environ.setdefault("NODE_PORT", "0")

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from blockchain.core.chain import Blockchain
from blockchain.contracts.accounts import AccountContract
from blockchain.contracts.registry import ContractRegistry
from blockchain.core.transaction import (
    Transaction,
    TransactionType,
    create_mint_transaction,
    create_transfer_transaction,
)
from blockchain.core.wallet import Wallet
from tests.helpers import make_app, mine_and_add, mine_candidate, reiniciar_nodo

pytestmark = pytest.mark.integration

DIFICULTAD = 1


# ── Nodo de prueba por la API ────────────────────────────────────────────────

@pytest.fixture
def nodo(tmp_path):
    """App propia (create_app) sobre tmp_path, con una autoridad de test."""
    autoridad = Wallet.generate()
    fastapi = make_app(tmp_path, autoridad=autoridad, mining_difficulty=DIFICULTAD)
    return SimpleNamespace(
        fastapi=fastapi, node=fastapi.state.node, autoridad=autoridad,
        reiniciar=lambda: reiniciar_nodo(fastapi, autoridad))


@pytest_asyncio.fixture
async def client(nodo):
    async with AsyncClient(transport=ASGITransport(app=nodo.fastapi),
                           base_url="http://127.0.0.1") as ac:
        yield ac


def _cuerpo(tx: Transaction) -> dict:
    """Cuerpo de POST /transactions para una TX firmada por el cliente."""
    return {
        "type": tx.type.value, "sender": tx.sender, "recipient": tx.recipient,
        "payload": tx.payload, "fee": tx.fee, "nonce": tx.nonce,
        "timestamp": tx.timestamp, "signature": tx.signature, "public_key": tx.public_key,
    }


async def _cuenta(client, address) -> dict:
    r = await client.get(f"/accounts/{address}")
    assert r.status_code == 200, r.text
    return r.json()


async def _minar(client):
    r = await client.post("/blocks/mine", json={})
    assert r.status_code == 200, r.text


async def _emitir_tokens(client, destino, monto):
    r = await client.post("/tokens/mint", json={"recipient": destino, "amount": monto})
    assert r.status_code == 200, r.text
    return r.json()


# ── Flujo completo: mint → minar → transferir → minar → reiniciar ────────────

@pytest.mark.asyncio
async def test_mint_transferencia_saldos_y_reinicio(client, nodo):
    ana, beto = Wallet.generate(), Wallet.generate()
    await _emitir_tokens(client, ana.address, 1000)
    # Pendiente: el saldo confirmado no cambia, pero el próximo nonce sí.
    cuenta = await _cuenta(client, nodo.autoridad.address)
    assert cuenta["nonce"] == 0 and cuenta["next_nonce"] == 2
    assert (await _cuenta(client, ana.address))["balance"] == 0
    await _minar(client)
    assert (await _cuenta(client, ana.address))["balance"] == 1000

    r = await client.post("/tokens/transfer", json={
        "sender": ana.address, "recipient": beto.address, "amount": 300,
        "fee": 5, "private_key_hex": ana.private_key_hex,
    })
    assert r.status_code == 200, r.text
    assert r.json()["nonce"] == 1
    await _minar(client)

    cuenta_ana = await _cuenta(client, ana.address)
    assert cuenta_ana["balance"] == 695 and cuenta_ana["nonce"] == 1
    assert cuenta_ana["next_nonce"] == 2
    assert (await _cuenta(client, beto.address))["balance"] == 300
    bc = nodo.fastapi.state.node.blockchain
    assert bc.accounts.total_supply == 995 and bc.accounts.burned_fees == 5

    # Reinicio: el estado se recupera desde chain.db (foto + bloques posteriores, P2-4).
    nodo.reiniciar()
    assert (await _cuenta(client, ana.address))["balance"] == 695
    assert (await _cuenta(client, beto.address))["balance"] == 300
    assert (await _cuenta(client, nodo.autoridad.address))["nonce"] == 1


# ── Rechazos en la API (400) ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_tx_repetida_rechazada(client, nodo):
    ana = Wallet.generate()
    tx = Transaction(TransactionType.DATA_RECORD, ana.address, "DEST",
                     {"d": time.time_ns()}, nonce=1)
    tx.sign(ana.private_key_hex)
    assert (await client.post("/transactions", json=_cuerpo(tx))).status_code == 200
    r = await client.post("/transactions", json=_cuerpo(tx))     # repetida en mempool
    assert r.status_code == 400
    await _minar(client)
    r = await client.post("/transactions", json=_cuerpo(tx))     # repetida ya confirmada
    assert r.status_code == 400
    # Misma operación con otro timestamp (otro tx_id) pero el mismo nonce: replay.
    copia = Transaction(TransactionType.DATA_RECORD, ana.address, "DEST", tx.payload, nonce=1)
    copia.sign(ana.private_key_hex)
    r = await client.post("/transactions", json=_cuerpo(copia))
    assert r.status_code == 400 and "Nonce" in r.json()["detail"]


@pytest.mark.asyncio
async def test_transferencia_sin_saldo_rechazada(client, nodo):
    ana, beto = Wallet.generate(), Wallet.generate()
    r = await client.post("/tokens/transfer", json={
        "sender": ana.address, "recipient": beto.address, "amount": 1,
        "private_key_hex": ana.private_key_hex,
    })
    assert r.status_code == 400 and "Saldo insuficiente" in r.json()["detail"]

    # Con saldo 10: transferir 8 con fee 3 (=11) no alcanza.
    await _emitir_tokens(client, ana.address, 10)
    await _minar(client)
    r = await client.post("/tokens/transfer", json={
        "sender": ana.address, "recipient": beto.address, "amount": 8, "fee": 3,
        "private_key_hex": ana.private_key_hex,
    })
    assert r.status_code == 400 and "Saldo insuficiente" in r.json()["detail"]
    # El gasto pendiente cuenta: dos transferencias de 6 no caben en 10.
    cuerpo = {"sender": ana.address, "recipient": beto.address, "amount": 6,
              "private_key_hex": ana.private_key_hex}
    assert (await client.post("/tokens/transfer", json=cuerpo)).status_code == 200
    assert (await client.post("/tokens/transfer", json=cuerpo)).status_code == 400
    # Una fee > 0 sin saldo tampoco entra (DATA_RECORD).
    pobre = Wallet.generate()
    tx = Transaction(TransactionType.DATA_RECORD, pobre.address, "DEST", {"d": 1},
                     fee=1, nonce=1)
    tx.sign(pobre.private_key_hex)
    assert (await client.post("/transactions", json=_cuerpo(tx))).status_code == 400


@pytest.mark.asyncio
async def test_nonce_incorrecto_rechazado(client, nodo):
    ana = Wallet.generate()
    for nonce in (0, 2, 5):
        tx = Transaction(TransactionType.DATA_RECORD, ana.address, "DEST",
                         {"d": time.time_ns()}, nonce=nonce)
        tx.sign(ana.private_key_hex)
        r = await client.post("/transactions", json=_cuerpo(tx))
        assert r.status_code == 400 and "Nonce" in r.json()["detail"], r.text
    # Firmada por el cliente sin nonce: 400 explícito.
    cuerpo = _cuerpo(tx)
    del cuerpo["nonce"]
    assert (await client.post("/transactions", json=cuerpo)).status_code == 400
    # El servidor que firma rellena el nonce correcto.
    r = await client.post("/transactions", json={
        "type": "DATA_RECORD", "sender": ana.address, "recipient": "DEST",
        "payload": {"d": 1}, "private_key_hex": ana.private_key_hex,
    })
    assert r.status_code == 200, r.text
    assert (await _cuenta(client, ana.address))["next_nonce"] == 2


@pytest.mark.asyncio
async def test_mint_de_quien_no_es_autoridad_rechazado(client, nodo):
    intruso = Wallet.generate()
    tx = create_mint_transaction(intruso.address, intruso.address, 10**6,
                                 intruso.private_key_hex, nonce=1)
    r = await client.post("/transactions", json=_cuerpo(tx))
    assert r.status_code == 400 and "autoridad" in r.json()["detail"]
    # Sin llave de autoridad el nodo no puede emitir.
    nodo.fastapi.state.node.authority_wallet = None
    r = await client.post("/tokens/mint", json={"recipient": intruso.address, "amount": 1})
    assert r.status_code == 503


@pytest.mark.asyncio
async def test_montos_no_enteros_rechazados(client, nodo):
    ana, beto = Wallet.generate(), Wallet.generate()
    await _emitir_tokens(client, ana.address, 100)
    await _minar(client)
    for monto in (1.5, 0, -3, "10", True):
        tx = Transaction(TransactionType.TOKEN_TRANSFER, ana.address, beto.address,
                         {"amount": monto}, nonce=1)
        tx.sign(ana.private_key_hex)
        assert (await client.post("/transactions", json=_cuerpo(tx))).status_code == 400
    # fee float en el modelo de la API: 422 (Pydantic) o 400, nunca aceptada.
    r = await client.post("/tokens/transfer", json={
        "sender": ana.address, "recipient": beto.address, "amount": 1, "fee": 0.5,
        "private_key_hex": ana.private_key_hex,
    })
    assert r.status_code in (400, 422)


@pytest.mark.asyncio
async def test_credenciales_consumen_nonce_del_firmante(client, nodo):
    """El nonce aplica a TODO tipo de TX: registrar un emisor gasta el nonce 1
    de la autoridad y el mint siguiente usa el 2, ambos en el mismo bloque."""
    emisor = Wallet.generate()
    r = await client.post("/credentials/issuers",
                          json={"issuer_address": emisor.address, "institution_code": "UPB"})
    assert r.status_code == 200, r.text
    assert (await _emitir_tokens(client, emisor.address, 7))["nonce"] == 2
    await _minar(client)
    assert (await _cuenta(client, nodo.autoridad.address))["nonce"] == 2
    assert (await _cuenta(client, emisor.address))["balance"] == 7
    assert nodo.fastapi.state.node.blockchain.contract_state("credentials").is_registered_issuer(emisor.address)


# ── Consenso: bloques con TXs inválidas para las cuentas ─────────────────────

def _cadena(directorio, autoridad) -> Blockchain:
    return Blockchain(f"nodo_{directorio.name}", str(directorio),
                      initial_difficulty=DIFICULTAD, authority_address=autoridad.address)


def test_bloque_con_tx_sin_saldo_o_nonce_repetido_se_rechaza(tmp_path):
    autoridad, ana, beto = Wallet.generate(), Wallet.generate(), Wallet.generate()
    bc = _cadena(tmp_path / "a", autoridad)

    sin_saldo = create_transfer_transaction(ana.address, beto.address, 5,
                                            ana.private_key_hex, nonce=1)
    ok, motivo = bc.add_block(mine_candidate(bc, [sin_saldo]))
    assert not ok and "Saldo insuficiente" in motivo and bc.height == 0

    mint = create_mint_transaction(autoridad.address, ana.address, 10,
                                   autoridad.private_key_hex, nonce=1)
    t1 = create_transfer_transaction(ana.address, beto.address, 4, ana.private_key_hex, nonce=1)
    # Doble gasto dentro del mismo bloque: dos TXs distintas con el mismo nonce.
    t1_bis = create_transfer_transaction(ana.address, autoridad.address, 4,
                                         ana.private_key_hex, nonce=1)
    ok, motivo = bc.add_block(mine_candidate(bc, [mint, t1, t1_bis]))
    assert not ok and "Nonce" in motivo and bc.height == 0

    ok, motivo = mine_and_add(bc, [mint, t1])
    assert ok, motivo
    assert bc.get_balance(ana.address) == 6 and bc.get_balance(beto.address) == 4

    # Bloque siguiente con la otra TX del nonce 1 (replay del nonce): rechazado.
    ok, motivo = bc.add_block(mine_candidate(bc, [t1_bis]))
    assert not ok and "Nonce" in motivo

    # Otro nodo no acepta por replace_chain una cadena con ese bloque inválido.
    otra = _cadena(tmp_path / "b", autoridad)
    falsa = [b.to_dict() for b in bc.chain] + [mine_candidate(bc, [t1_bis]).to_dict()]
    ok, motivo = otra.replace_chain(falsa)
    assert not ok and "Nonce" in motivo


def test_mint_en_bloque_de_quien_no_es_autoridad_rechazado(tmp_path):
    autoridad, intruso = Wallet.generate(), Wallet.generate()
    bc = _cadena(tmp_path / "a", autoridad)
    mint = create_mint_transaction(intruso.address, intruso.address, 100,
                                   intruso.private_key_hex, nonce=1)
    ok, motivo = bc.add_block(mine_candidate(bc, [mint]))
    assert not ok and "autoridad" in motivo


def test_tx_caducada_del_mempool_no_invalida_el_bloque_del_minero(tmp_path):
    """Dos TXs con el mismo nonce llegan a nodos distintos; cuando el bloque de A
    confirma una, B descarta la otra de su mempool y puede seguir minando."""
    autoridad, ana = Wallet.generate(), Wallet.generate()
    a, b = _cadena(tmp_path / "a", autoridad), _cadena(tmp_path / "b", autoridad)
    tx_a = Transaction(TransactionType.DATA_RECORD, ana.address, "X", {"v": "a"}, nonce=1)
    tx_b = Transaction(TransactionType.DATA_RECORD, ana.address, "X", {"v": "b"}, nonce=1)
    tx_a.sign(ana.private_key_hex)
    tx_b.sign(ana.private_key_hex)
    assert a.add_transaction(tx_a)[0] and b.add_transaction(tx_b)[0]
    assert mine_and_add(a)[0]
    ok, motivo = b.add_block(a.last_block)
    assert ok, motivo
    assert b.mempool == []
    assert b.next_nonce(ana.address) == 2
    ok, motivo = mine_and_add(b)
    assert ok, motivo


def test_reorg_reconstruye_saldos(tmp_path):
    autoridad, ana = Wallet.generate(), Wallet.generate()
    a, b = _cadena(tmp_path / "a", autoridad), _cadena(tmp_path / "b", autoridad)
    mint = create_mint_transaction(autoridad.address, ana.address, 50,
                                   autoridad.private_key_hex, nonce=1)
    assert a.add_transaction(mint)[0]
    assert mine_and_add(a)[0]
    assert a.get_balance(ana.address) == 50

    # B mina más trabajo sin el mint; A se reorganiza a la cadena de B.
    for _ in range(2):
        assert mine_and_add(b)[0]
    ok, motivo = a.replace_chain([blk.to_dict() for blk in b.chain])
    assert ok, motivo
    assert a.get_balance(ana.address) == 0
    assert a.accounts.nonce_of(autoridad.address) == 0
    # El mint huérfano vuelve al mempool y al minarse restaura el saldo.
    assert [t.tx_id for t in a.mempool] == [mint.tx_id]
    assert mine_and_add(a)[0]
    assert a.get_balance(ana.address) == 50

    # Reiniciar desde disco reproduce el mismo estado.
    recargada = _cadena(tmp_path / "a", autoridad)
    assert recargada.accounts.balances == a.accounts.balances
    assert recargada.accounts.nonces == a.accounts.nonces


def test_estado_de_cuentas_es_determinista():
    """Mismo bloque ⇒ mismo estado; los montos son siempre int."""
    autoridad, ana = Wallet.generate(), Wallet.generate()
    from blockchain.core.block import Block, BlockHeader
    g = Block.create_genesis()
    txs = [create_mint_transaction(autoridad.address, ana.address, 9,
                                   autoridad.private_key_hex, nonce=1).to_dict(),
           create_transfer_transaction(ana.address, autoridad.address, 4,
                                       ana.private_key_hex, nonce=1, fee=2).to_dict()]
    h = BlockHeader(index=1, timestamp=g.header.timestamp + 10, previous_hash=g.hash,
                    merkle_root=Block.compute_merkle_root(txs), node_id="x")
    b1 = Block(header=h, transactions=txs)
    estados = []
    for _ in range(2):
        registro = ContractRegistry([AccountContract(autoridad.address)])
        registro.rebuild([g, b1])
        s = registro.state("accounts")
        estados.append((s.balances, s.nonces, s.total_supply, s.burned_fees))
    assert estados[0] == estados[1]
    assert estados[0][0] == {ana.address: 3, autoridad.address: 4}
    assert all(type(v) is int for v in estados[0][0].values())
    assert estados[0][2] == 7 and estados[0][3] == 2
