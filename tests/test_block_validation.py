"""Tests de P0-3: validación completa de bloques (PoW, dificultad, TXs, duplicados)."""
import copy
import json
import os

os.environ.setdefault("NODE_PORT", "0")

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from blockchain.core.block import Block, hash_meets_bits
from blockchain.core.chain import Blockchain
from blockchain.core.transaction import Transaction, TransactionType
from blockchain.core.wallet import Wallet
from tests.helpers import make_app, mine_and_add, mine_candidate


def _tx(wallet, n=0, timestamp=None, nonce=1):
    tx = Transaction(
        type=TransactionType.DATA_RECORD,
        sender=wallet.address,
        recipient="DEST",
        payload={"n": n},
        nonce=nonce,
    )
    if timestamp is not None:
        tx.timestamp = timestamp
        tx.tx_id = tx._compute_id()
    tx.sign(wallet.private_key_hex)
    return tx


def _nuevo(tmp_path, nombre="c"):
    return Blockchain("n", str(tmp_path / nombre), initial_difficulty=1)


def _rehash(block):
    """Recalcula merkle+hash tras manipular un bloque (sin rehacer PoW)."""
    block.header.merkle_root = Block.compute_merkle_root(block.transactions)
    block.hash = block.compute_hash()
    return block


@pytest.fixture
def w():
    return Wallet.generate()


def test_bloque_con_dificultad_0_rechazado(tmp_path, w):
    bc = _nuevo(tmp_path)
    bc.add_transaction(_tx(w))
    cand = bc.create_candidate_block()
    cand.header.difficulty = 0
    cand.hash = cand.compute_hash()
    ok, motivo = bc.add_block(cand)
    assert not ok and "Dificultad" in motivo
    assert bc.height == 0


def test_hash_que_no_cumple_objetivo_rechazado(tmp_path, w):
    bc = _nuevo(tmp_path)
    bc.add_transaction(_tx(w))
    cand = bc.create_candidate_block()
    n = 0
    while True:  # buscar un nonce que NO cumpla el objetivo
        cand.header.nonce = n
        cand.hash = cand.compute_hash()
        if not hash_meets_bits(cand.hash, cand.header.difficulty):
            break
        n += 1
    ok, motivo = bc.add_block(cand)
    assert not ok and "Proof of Work" in motivo


def test_replace_chain_rechaza_dificultad_0(tmp_path, w):
    a, b = _nuevo(tmp_path, "a"), _nuevo(tmp_path, "b")
    for i in range(2):
        a.add_transaction(_tx(w, i, nonce=i + 1))
        assert mine_and_add(a)[0]
    falsa = [x.to_dict() for x in a.chain]
    falsa[1]["header"]["difficulty"] = 0
    blk = _rehash(Block.from_dict(falsa[1]))
    falsa[1] = blk.to_dict()
    ok, motivo = b.replace_chain(falsa)
    assert not ok
    assert b.height == 0


def test_tx_sin_firma_o_falsificada_rechazada(tmp_path, w):
    bc = _nuevo(tmp_path)
    tx = _tx(w)
    d = tx.to_dict()
    d["payload"] = {"n": 999}  # contenido alterado tras firmar
    cand = mine_candidate(bc, [tx])
    cand.transactions = [d]
    cand.header.merkle_root = Block.compute_merkle_root(cand.transactions)
    # re-minar con el contenido falso para que sólo falle la TX
    from blockchain.consensus.proof_of_work import ProofOfWork
    res = ProofOfWork(1).mine(cand, difficulty=1)
    ok, motivo = bc.add_block(res.block)
    assert not ok and "inválida" in motivo

    # sin firma
    d2 = {**tx.to_dict(), "signature": ""}
    cand2 = bc.create_candidate_block([tx])
    cand2.transactions = [d2]
    cand2.header.merkle_root = Block.compute_merkle_root(cand2.transactions)
    res2 = ProofOfWork(1).mine(cand2, difficulty=1)
    ok, motivo = bc.add_block(res2.block)
    assert not ok and "sin firma" in motivo


def test_tx_duplicada_entre_bloques_rechazada(tmp_path, w):
    bc = _nuevo(tmp_path)
    tx = _tx(w)
    assert mine_and_add(bc, [tx])[0]
    cand = mine_candidate(bc, [tx])  # misma TX otra vez
    ok, motivo = bc.add_block(cand)
    assert not ok and "duplicada" in motivo


def test_tx_duplicada_dentro_del_bloque_rechazada(tmp_path, w):
    bc = _nuevo(tmp_path)
    tx = _tx(w)
    ok, motivo = bc.add_block(mine_candidate(bc, [tx, tx]))
    assert not ok and "duplicada" in motivo


def test_mempool_rechaza_tx_ya_confirmada(tmp_path, w):
    bc = _nuevo(tmp_path)
    tx = _tx(w)
    assert mine_and_add(bc, [tx])[0]
    ok, motivo = bc.add_transaction(tx)
    assert not ok and "confirmada" in motivo


def test_archivo_manipulado_se_rechaza_al_cargar(tmp_path, w):
    bc = _nuevo(tmp_path)
    assert mine_and_add(bc, [_tx(w)])[0]
    f = tmp_path / "c" / "chain.json"
    data = json.loads(f.read_text(encoding="utf-8"))
    data[1]["transactions"][0]["payload"] = {"n": 666}
    f.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError):
        Blockchain("n", str(tmp_path / "c"), initial_difficulty=1)


def test_archivo_con_bloque_sin_pow_se_rechaza_al_cargar(tmp_path, w):
    bc = _nuevo(tmp_path)
    assert mine_and_add(bc, [_tx(w)])[0]
    f = tmp_path / "c" / "chain.json"
    data = json.loads(f.read_text(encoding="utf-8"))
    data[1]["header"]["difficulty"] = 0
    blk = _rehash(Block.from_dict(data[1]))
    data[1] = blk.to_dict()
    f.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError):
        Blockchain("n", str(tmp_path / "c"), initial_difficulty=1)


def test_cadena_vieja_con_txs_de_mas_de_1h_sigue_valida(tmp_path, w):
    """Consenso != mempool: las TX viejas dentro de bloques no expiran."""
    bc = _nuevo(tmp_path)
    vieja = _tx(w, timestamp=1_700_000_000.0)
    assert vieja.is_valid()[0] is False          # el mempool la rechaza (expirada)
    assert vieja.is_consensus_valid()[0] is True  # el consenso no
    assert mine_and_add(bc, [vieja])[0]
    ok, motivo = bc.validate_chain()
    assert ok, motivo
    # y recargar desde disco la acepta
    assert Blockchain("n", str(tmp_path / "c"), initial_difficulty=1).height == 1


def test_timestamp_en_el_futuro_rechazado(tmp_path, w):
    bc = _nuevo(tmp_path)
    cand = bc.create_candidate_block([_tx(w)])
    cand.header.timestamp += 3 * 3600
    from blockchain.consensus.proof_of_work import ProofOfWork
    res = ProofOfWork(1).mine(cand, difficulty=1)
    ok, motivo = bc.add_block(res.block)
    assert not ok and "futuro" in motivo


def test_timestamp_anterior_a_la_mediana_rechazado(tmp_path, w):
    bc = _nuevo(tmp_path)
    cand = bc.create_candidate_block([_tx(w)])
    cand.header.timestamp = bc.last_block.header.timestamp - 1
    from blockchain.consensus.proof_of_work import ProofOfWork
    res = ProofOfWork(1).mine(cand, difficulty=1)
    ok, motivo = bc.add_block(res.block)
    assert not ok and "Timestamp" in motivo


def test_dificultad_esperada_es_funcion_pura_y_acotada(tmp_path, w):
    bc = Blockchain("n", str(tmp_path / "d"), initial_difficulty=1, max_difficulty=3,
                    difficulty_window=3, target_block_time=10.0)
    assert bc.expected_difficulty(bc.chain[:1]) == 1
    # bloques sintéticos muy rápidos (1 s entre sí): la dificultad sube hasta el máximo
    from blockchain.core.block import BlockHeader
    prev = bc.chain[0]
    chain = [prev]
    base = prev.header.timestamp
    for i in range(1, 8):
        d = bc.expected_difficulty(chain)
        hdr = BlockHeader(index=i, timestamp=base + i, previous_hash=chain[-1].hash,
                          merkle_root="x", difficulty=d, node_id="n")
        chain.append(Block(header=hdr, transactions=[]))
    assert chain[-1].header.difficulty == 3
    assert bc.expected_difficulty(chain) == 3  # acotada por max_difficulty


@pytest_asyncio.fixture
async def client(tmp_path):
    app = make_app(tmp_path, "api")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        ac.node = app.state.node
        yield ac


@pytest.mark.asyncio
async def test_api_minar_y_no_aceptar_tx_ya_confirmada(client):
    bc = client.node.blockchain
    w = Wallet.generate()
    tx = _tx(w, 7)
    body = {
        "type": tx.type.value, "sender": tx.sender, "recipient": tx.recipient,
        "payload": tx.payload, "fee": tx.fee, "nonce": tx.nonce, "timestamp": tx.timestamp,
        "signature": tx.signature, "public_key": tx.public_key,
    }
    r = await client.post("/transactions", json=body)
    assert r.status_code == 200, r.text
    r = await client.post("/blocks/mine", json={"miner_address": w.address})
    assert r.status_code == 200, r.text
    assert r.json()["block"]["header"]["difficulty"] == 1
    assert bc.height == 1
    assert bc.validate_chain()[0]
    # la misma TX ya está confirmada: el mempool la rechaza
    r = await client.post("/transactions", json=body)
    assert r.status_code == 400, r.text
