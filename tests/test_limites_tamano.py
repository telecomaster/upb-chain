"""Límites de tamaño de TX y de bloque (P0-3, auditoría: DATA_RECORD de 3 MB admitido).

Son reglas de consenso (``blockchain/core/limits.py``): se aplican en la API (413),
en la admisión al mempool (API y P2P) y en la validación de bloques (recibidos por
P2P o al sincronizar). La TX legítima más grande (CONTRACT_DEPLOY al máximo de la
VM) debe seguir cabiendo.
"""
from fastapi.testclient import TestClient

from blockchain.core.block import GENESIS_HASH
from blockchain.core.chain import Blockchain
from blockchain.core.limits import (MAX_BLOCK_BYTES, MAX_TX_BYTES, check_tx_size,
                                    serialized_size)
from blockchain.core.transaction import Transaction, TransactionType
from blockchain.core.wallet import Wallet
from tests.helpers import make_app, mine_candidate

WORD = (1 << 256) - 1


def _dato(w, n_bytes, nonce=1):
    t = Transaction(type=TransactionType.DATA_RECORD, sender=w.address, recipient="DEST",
                    payload={"data": "x" * n_bytes}, nonce=nonce)
    t.sign(w.private_key_hex)
    return t


def _cadena(tmp_path, nombre="c"):
    return Blockchain(node_id=nombre, data_dir=str(tmp_path / nombre), initial_difficulty=1)


def test_la_tx_legitima_mas_grande_cabe_con_margen():
    """CONTRACT_DEPLOY con 4096 B de código y 256 casillas de 256 bits (~50 KB)."""
    w = Wallet.generate()
    t = Transaction(type=TransactionType.CONTRACT_DEPLOY, sender=w.address,
                    recipient="UPC" + "A" * 32,
                    payload={"code": "00" * 4096,
                             "storage": [[WORD - i, WORD - i] for i in range(256)],
                             "gas_limit": 200_000, "gas_price": 10 ** 18},
                    fee=10 ** 18, nonce=10 ** 9)
    t.sign(w.private_key_hex)
    size = serialized_size(t.to_dict())
    assert 40_000 < size < MAX_TX_BYTES * 0.8
    assert check_tx_size(t.to_dict())[0]
    assert t.is_consensus_valid() == (True, "OK")


def test_api_rechaza_data_record_enorme_con_413(tmp_path):
    """Regresión de la auditoría: POST /transactions aceptaba un payload de 3 MB."""
    app = make_app(tmp_path)
    w = Wallet.generate()
    t = _dato(w, MAX_TX_BYTES + 1)
    cuerpo = {"type": "DATA_RECORD", "sender": w.address, "recipient": "DEST",
              "payload": t.payload, "nonce": 1, "timestamp": t.timestamp,
              "signature": t.signature, "public_key": t.public_key}
    with TestClient(app, base_url="http://127.0.0.1") as c:
        r = c.post("/transactions", json=cuerpo)
        assert r.status_code == 413, r.text
        assert "demasiado grande" in r.json()["detail"]
        assert app.state.node.blockchain.mempool == []
        # Una TX normal del mismo remitente sí entra.
        ok = _dato(w, 100)
        r = c.post("/transactions", json={
            "type": "DATA_RECORD", "sender": w.address, "recipient": "DEST",
            "payload": ok.payload, "nonce": 1, "timestamp": ok.timestamp,
            "signature": ok.signature, "public_key": ok.public_key})
        assert r.status_code == 200, r.text


def test_mempool_y_p2p_rechazan_tx_enorme(tmp_path):
    app = make_app(tmp_path)
    with TestClient(app, base_url="http://127.0.0.1"):
        node = app.state.node
        grande = _dato(Wallet.generate(), MAX_TX_BYTES)
        ok, motivo = node.blockchain.add_transaction(grande)
        assert not ok and "demasiado grande" in motivo
        node.p2p._handle_tx({"type": "NEW_TX", "data": grande.to_dict()})
        assert node.blockchain.mempool == []


def test_bloque_con_tx_enorme_es_invalido_por_p2p_y_al_sincronizar(tmp_path):
    """Un minero que mete una TX enorme (sin pasar por el mempool) hace inválido su bloque."""
    minero = _cadena(tmp_path, "minero")
    bloque = mine_candidate(minero, [_dato(Wallet.generate(), MAX_TX_BYTES)])
    ok, motivo = minero.add_block(bloque)
    assert not ok and "demasiado grande" in motivo

    app = make_app(tmp_path)
    invalidos = []
    with TestClient(app, base_url="http://127.0.0.1"):
        node = app.state.node
        node.p2p.on_invalid_block = lambda motivo, origen: invalidos.append(motivo)
        node.p2p._handle_block({"type": "NEW_BLOCK", "data": bloque.to_dict()}, None)
        assert node.blockchain.height == 0
        assert invalidos and "demasiado grande" in invalidos[0]
        cadena = [minero.chain[0].to_dict(), bloque.to_dict()]
        ok, motivo = node.blockchain.replace_chain(cadena)
        assert not ok and "demasiado grande" in motivo


def test_bloque_que_supera_el_tope_es_invalido_aunque_cada_tx_quepa(tmp_path):
    bc = _cadena(tmp_path)
    por_tx = MAX_TX_BYTES - 2_000
    txs = [_dato(Wallet.generate(), por_tx) for _ in range(MAX_BLOCK_BYTES // por_tx + 1)]
    assert all(t.is_consensus_valid()[0] for t in txs)
    bloque = mine_candidate(bc, txs)
    assert serialized_size(bloque.to_dict()) > MAX_BLOCK_BYTES
    ok, motivo = bc.add_block(bloque)
    assert not ok and "Bloque demasiado grande" in motivo


def test_el_minero_corta_el_bloque_para_no_pasarse(tmp_path):
    """Con el mempool lleno de TXs grandes, el candidato cabe en el tope y es válido."""
    bc = _cadena(tmp_path)
    por_tx = MAX_TX_BYTES - 2_000
    for _ in range(MAX_BLOCK_BYTES // por_tx + 3):
        assert bc.add_transaction(_dato(Wallet.generate(), por_tx))[0]
    bloque = mine_candidate(bc)
    assert serialized_size(bloque.to_dict()) <= MAX_BLOCK_BYTES
    assert bc.add_block(bloque) == (True, "OK")
    assert len(bc.mempool) > 0            # lo que no cupo queda para el siguiente bloque
    assert bc.add_block(mine_candidate(bc)) == (True, "OK")
    assert bc.mempool == []


def test_genesis_no_cambia(tmp_path):
    bc = _cadena(tmp_path)
    assert bc.chain[0].hash == GENESIS_HASH
    assert bc.validate_chain()[0]
