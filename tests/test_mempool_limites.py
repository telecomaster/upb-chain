"""Tope del mempool y de TX pendientes por remitente (P1-5, auditoría de seguridad).

Política local, no consenso: con el mempool lleno se rechaza la TX nueva y un
remitente no puede ocupar más de ``MEMPOOL_MAX_PER_SENDER`` plazas, ni por la
API ni por P2P. La admisión incremental debe aceptar exactamente lo mismo que
la reproducción completa de las pendientes.
"""
from fastapi.testclient import TestClient

from blockchain.core.chain import Blockchain
from blockchain.core.transaction import Transaction, TransactionType
from blockchain.core.wallet import Wallet
from tests.helpers import make_app, mine_and_add


def _tx(w, nonce, dato="x"):
    t = Transaction(type=TransactionType.DATA_RECORD, sender=w.address, recipient="DEST",
                    payload={"data": dato}, nonce=nonce)
    t.sign(w.private_key_hex)
    return t


def _cadena(tmp_path, **kw):
    return Blockchain(node_id="n", data_dir=str(tmp_path / "c"), **kw)


def test_billeteras_nuevas_sin_saldo_llenan_el_mempool_hasta_el_tope(tmp_path):
    bc = _cadena(tmp_path, mempool_max=10)
    resultados = [bc.add_transaction(_tx(Wallet.generate(), 1)) for _ in range(15)]
    assert sum(ok for ok, _ in resultados) == 10
    assert len(bc.mempool) == 10
    assert "Mempool lleno" in resultados[-1][1]


def test_un_remitente_no_pasa_de_su_tope(tmp_path):
    bc = _cadena(tmp_path, mempool_max_per_sender=3)
    w = Wallet.generate()
    res = [bc.add_transaction(_tx(w, n)) for n in range(1, 6)]
    assert [ok for ok, _ in res] == [True, True, True, False, False]
    assert "remitente" in res[3][1]
    # otro remitente sigue pudiendo entrar
    assert bc.add_transaction(_tx(Wallet.generate(), 1))[0]


def test_el_tope_por_remitente_se_libera_al_minar(tmp_path):
    bc = _cadena(tmp_path, mempool_max_per_sender=2)
    w = Wallet.generate()
    assert bc.add_transaction(_tx(w, 1))[0] and bc.add_transaction(_tx(w, 2))[0]
    assert not bc.add_transaction(_tx(w, 3))[0]
    mine_and_add(bc)
    assert bc.mempool == []
    assert bc.add_transaction(_tx(w, 3))[0]


def test_p2p_respeta_el_tope_por_remitente(tmp_path):
    app = make_app(tmp_path, mempool_max_per_sender=2)
    with TestClient(app, base_url="http://127.0.0.1"):
        node = app.state.node
        w = Wallet.generate()
        for n in range(1, 6):
            node.p2p._handle_tx({"type": "TX", "data": _tx(w, n).to_dict()})
        assert len(node.blockchain.mempool) == 2


def test_ajustes_exponen_los_topes(tmp_path):
    app = make_app(tmp_path, mempool_max=7, mempool_max_per_sender=3)
    with TestClient(app, base_url="http://127.0.0.1"):
        bc = app.state.node.blockchain
        assert (bc.mempool_max, bc.mempool_max_per_sender) == (7, 3)


def test_admision_incremental_equivale_a_reproducir_las_pendientes(tmp_path):
    """Mismo veredicto que ``check_transaction`` (reproducción completa) en una mezcla."""
    bc = _cadena(tmp_path)
    a, b = Wallet.generate(), Wallet.generate()
    secuencia = [_tx(a, 1), _tx(a, 3), _tx(a, 2), _tx(a, 2), _tx(b, 1), _tx(b, 2), _tx(a, 3)]
    for t in secuencia:
        esperado = bc.contracts.check_transaction(
            t.to_dict(), [p.to_dict() for p in bc.mempool], bc._next_block_timestamp())
        dup = any(p.tx_id == t.tx_id for p in bc.mempool)
        ok, _ = bc.add_transaction(t)
        assert ok == (esperado[0] and not dup)


def test_reorg_devuelve_huerfanas_y_el_estado_especulativo_se_reconstruye(tmp_path):
    a = _cadena(tmp_path / "a")
    b = _cadena(tmp_path / "b")
    w = Wallet.generate()
    assert a.add_transaction(_tx(w, 1))[0]
    mine_and_add(a)                      # a: bloque 1 con la TX nonce 1
    for _ in range(2):
        mine_and_add(b)                  # b: cadena más larga sin esa TX
    ok, _ = a.replace_chain([blk.to_dict() for blk in b.chain])
    assert ok
    assert [t.nonce for t in a.mempool] == [1]      # huérfana readmitida
    assert a.add_transaction(_tx(w, 2))[0]          # el nonce especulativo es 2
    assert not a.add_transaction(_tx(w, 2, "otra"))[0]
