"""El mempool sobrevive a un reinicio (chain.db, tabla ``mempool``).

Las TX pendientes se recargan por la misma puerta que las nuevas
(``add_transaction``): las inválidas, confirmadas o fuera de tope se descartan.
"""
import json

from blockchain.core.chain import Blockchain
from blockchain.core.transaction import Transaction, TransactionType
from blockchain.core.wallet import Wallet
from tests.helpers import mine_and_add


def _tx(w, nonce, dato="x"):
    t = Transaction(type=TransactionType.DATA_RECORD, sender=w.address, recipient="DEST",
                    payload={"data": dato}, nonce=nonce)
    t.sign(w.private_key_hex)
    return t


def _abrir(tmp_path, nombre="c", **kw):
    return Blockchain(node_id="n", data_dir=str(tmp_path / nombre), **kw)


def test_las_pendientes_sobreviven_al_reinicio_en_orden(tmp_path):
    bc = _abrir(tmp_path)
    w = Wallet.generate()
    txs = [_tx(w, n) for n in (1, 2, 3)]
    for t in txs:
        assert bc.add_transaction(t)[0]
    bc.close()
    bc2 = _abrir(tmp_path)
    assert [t.tx_id for t in bc2.mempool] == [t.tx_id for t in txs]
    assert bc2.add_transaction(txs[0]) == (False, "Transacción duplicada")


def test_confirmadas_no_reaparecen_tras_reiniciar(tmp_path):
    bc = _abrir(tmp_path)
    assert bc.add_transaction(_tx(Wallet.generate(), 1))[0]
    mine_and_add(bc)
    assert bc.mempool == []
    bc.close()
    assert _abrir(tmp_path).mempool == []


def test_las_ya_no_validas_se_descartan_y_se_borran_de_disco(tmp_path):
    bc = _abrir(tmp_path)
    w = Wallet.generate()
    assert bc.add_transaction(_tx(w, 1))[0]
    # Fila escrita directo en disco con una TX que el mempool no admitiría (nonce 5).
    mala = _tx(w, 5)
    bc.store.mempool_add(mala.tx_id, json.dumps(mala.to_dict(), sort_keys=True))
    bc.close()
    bc2 = _abrir(tmp_path)
    assert len(bc2.mempool) == 1
    assert bc2.store.mempool_ids() == [bc2.mempool[0].tx_id]


def test_los_topes_se_aplican_al_recargar(tmp_path):
    bc = _abrir(tmp_path)
    for _ in range(6):
        assert bc.add_transaction(_tx(Wallet.generate(), 1))[0]
    bc.close()
    bc2 = _abrir(tmp_path, mempool_max=4)
    assert len(bc2.mempool) == 4
    assert len(bc2.store.mempool_ids()) == 4


def test_podar_borra_de_disco(tmp_path):
    bc = _abrir(tmp_path)
    assert bc.add_transaction(_tx(Wallet.generate(), 1))[0]
    assert bc.prune_mempool(max_age_seconds=-1) == 1
    bc.close()
    assert _abrir(tmp_path).mempool == []


def test_huerfanas_de_una_reorg_tambien_quedan_persistidas(tmp_path):
    a = _abrir(tmp_path, "a")
    b = _abrir(tmp_path, "b")
    t = _tx(Wallet.generate(), 1)
    assert a.add_transaction(t)[0]
    mine_and_add(a)                      # a: 1 bloque con t
    for _ in range(2):
        mine_and_add(b)                  # b: cadena más larga, sin t
    ok, _ = a.replace_chain([blk.to_dict() for blk in b.chain])
    assert ok
    assert [x.tx_id for x in a.mempool] == [t.tx_id]
    assert a.store.mempool_ids() == [t.tx_id]
    a.close()
    assert [x.tx_id for x in _abrir(tmp_path, "a").mempool] == [t.tx_id]
