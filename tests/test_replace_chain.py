"""Tests de P0-5: replace_chain por trabajo acumulado, TXs huérfanas y on_chain_reorg."""
import time

import pytest

from blockchain.consensus.proof_of_work import ProofOfWork
from blockchain.core.block import Block
from blockchain.core.chain import Blockchain
from blockchain.core.state import ReplayState
from blockchain.core.transaction import Transaction, TransactionType
from blockchain.core.wallet import Wallet
from tests.helpers import mine_and_add, mine_candidate

pytestmark = pytest.mark.unit


def _tx(wallet, n=0, nonce=1):
    tx = Transaction(
        type=TransactionType.DATA_RECORD,
        sender=wallet.address,
        recipient="DEST",
        payload={"n": n},
        nonce=nonce,
    )
    tx.sign(wallet.private_key_hex)
    return tx


def _nuevo(tmp_path, nombre, **kw):
    params = dict(initial_difficulty=1, max_difficulty=2)
    params.update(kw)
    return Blockchain(nombre, str(tmp_path / nombre), **params)


def _dicts(bc):
    return [b.to_dict() for b in bc.chain]


# Parámetros con ventana corta para que la dificultad cambie rápido:
# h <= 2 → 2; después, intervalo < 5 s → +1, > 20 s → -1, acotado a [1, 3].
_AJUSTE = dict(initial_difficulty=2, min_difficulty=1, max_difficulty=3,
               target_block_time=10.0, difficulty_window=2)


def _minar_con_espaciado(bc, n, espaciado):
    """Mina n bloques con timestamps separados `espaciado` segundos."""
    base = time.time() - 1000 if espaciado < 1 else time.time()
    for i in range(n):
        cand = bc.create_candidate_block([])
        cand.header.timestamp = max(base + (i + 1) * espaciado,
                                    bc.last_block.header.timestamp + 0.001)
        res = ProofOfWork(cand.header.difficulty).mine(
            cand, timeout=60.0, difficulty=cand.header.difficulty)
        ok, motivo = bc.add_block(res.block)
        assert ok, motivo


def test_mas_larga_pero_con_menos_trabajo_se_rechaza(tmp_path):
    rapida = Blockchain("r", str(tmp_path / "r"), **_AJUSTE)
    lenta = Blockchain("l", str(tmp_path / "l"), **_AJUSTE)
    _minar_con_espaciado(rapida, 4, 0.01)    # dificultades 2,2,3,3
    _minar_con_espaciado(lenta, 6, 100.0)    # dificultades 2,2,1,1,1,1
    assert len(lenta.chain) > len(rapida.chain)
    assert lenta.total_work < rapida.total_work

    ok, motivo = rapida.replace_chain(_dicts(lenta))
    assert not ok and "trabajo" in motivo
    assert rapida.height == 4

    # Al revés: la más corta con más trabajo SÍ se adopta.
    ok, motivo = lenta.replace_chain(_dicts(rapida))
    assert ok, motivo
    assert lenta.last_block.hash == rapida.last_block.hash


def test_empate_de_trabajo_conserva_la_propia(tmp_path):
    a, b = _nuevo(tmp_path, "a"), _nuevo(tmp_path, "b")
    mine_and_add(a)
    mine_and_add(b)
    assert a.total_work == b.total_work
    propia = a.last_block.hash
    ok, motivo = a.replace_chain(_dicts(b))
    assert not ok and "trabajo" in motivo
    assert a.last_block.hash == propia


def test_mas_trabajo_se_acepta_y_persiste(tmp_path):
    a, b = _nuevo(tmp_path, "a"), _nuevo(tmp_path, "b")
    for _ in range(3):
        mine_and_add(a)
    mine_and_add(b)
    ok, motivo = b.replace_chain(_dicts(a))
    assert ok, motivo
    assert b.last_block.hash == a.last_block.hash
    recargada = _nuevo(tmp_path, "b")
    assert recargada.last_block.hash == a.last_block.hash


def test_cadena_invalida_se_rechaza(tmp_path):
    a, b = _nuevo(tmp_path, "a"), _nuevo(tmp_path, "b")
    for _ in range(3):
        mine_and_add(a)
    falsa = _dicts(a)
    falsa[2]["header"]["nonce"] += 1
    ok, motivo = b.replace_chain(falsa)
    assert not ok and "inválida" in motivo
    assert b.height == 0


def test_cadena_malformada_se_rechaza(tmp_path):
    b = _nuevo(tmp_path, "b")
    ok, motivo = b.replace_chain([{"basura": 1}])
    assert not ok


def test_txs_huerfanas_vuelven_al_mempool_y_hook(tmp_path):
    # Remitentes distintos: cada uno con su propia secuencia de nonce (P0-9).
    t_comun, t_huerfana = _tx(Wallet.generate(), 1), _tx(Wallet.generate(), 2)
    a, b = _nuevo(tmp_path, "a"), _nuevo(tmp_path, "b")

    # B mina un bloque propio con la TX huérfana; t_comun queda en su mempool.
    assert b.add_transaction(t_huerfana)[0]
    mine_and_add(b)
    assert b.add_transaction(t_comun)[0]
    bloque_b = b.last_block.hash

    # A (más trabajo) confirma t_comun pero no t_huerfana.
    assert a.add_transaction(t_comun)[0]
    mine_and_add(a)
    mine_and_add(a)

    eventos = []
    b.add_reorg_listener(lambda fork, dropped, added: eventos.append((fork, dropped, added)))
    ok, motivo = b.replace_chain(_dicts(a))
    assert ok, motivo

    ids_mempool = {t.tx_id for t in b.mempool}
    assert ids_mempool == {t_huerfana.tx_id}
    assert t_comun.tx_id in b._confirmed_ids
    assert t_huerfana.tx_id not in b._confirmed_ids

    assert len(eventos) == 1
    fork, dropped, added = eventos[0]
    assert fork == 0
    assert [blk.hash for blk in dropped] == [bloque_b]
    assert [blk.hash for blk in added] == [blk.hash for blk in a.chain[1:]]

    # La huérfana puede minarse de nuevo en la cadena adoptada.
    ok, motivo = mine_and_add(b)
    assert ok, motivo
    assert t_huerfana.tx_id in b._confirmed_ids


def test_listener_que_falla_no_deshace_el_reemplazo(tmp_path):
    a, b = _nuevo(tmp_path, "a"), _nuevo(tmp_path, "b")
    mine_and_add(a)

    def roto(*_):
        raise RuntimeError("fallo del listener")

    b.add_reorg_listener(roto)
    ok, _ = b.replace_chain(_dicts(a))
    assert ok and b.height == 1


class _EstadoDePrueba(ReplayState):
    """Estado derivado mínimo (P0-6): cuenta reconstrucciones y veta payload {"n": 99}."""
    HANDLED_TYPES = frozenset({TransactionType.DATA_RECORD.value})

    def reset(self):
        self.aplicadas = []
        self.rebuilds = getattr(self, "rebuilds", 0) + 1

    def validate_tx(self, tx):
        if tx.get("payload", {}).get("n") == 99:
            return False, "vetada por el estado"
        return True, "OK"

    def _apply_valid_tx(self, tx, block_index, block_timestamp):
        self.aplicadas.append(tx["tx_id"])


def test_reorg_reconstruye_estados_y_readmite_por_check_transaction(tmp_path):
    w = Wallet.generate()
    a, b = _nuevo(tmp_path, "a"), _nuevo(tmp_path, "b")
    t_ok, t_vetada = _tx(w, 1, nonce=1), _tx(w, 99, nonce=2)
    assert b.add_transaction(t_ok)[0]
    assert b.add_transaction(t_vetada)[0]     # aún sin estado registrado
    mine_and_add(b)
    for _ in range(2):
        mine_and_add(a)

    estado = _EstadoDePrueba()
    b.register_state_listener(estado)
    assert estado.aplicadas == [t_ok.tx_id]   # la vetada se ignora al reproducir
    antes = estado.rebuilds

    ok, motivo = b.replace_chain(_dicts(a))
    assert ok, motivo
    assert estado.rebuilds == antes + 1       # rebuild sobre la cadena nueva
    assert estado.aplicadas == []             # t_ok ya no está confirmada
    # Re-admisión vía add_transaction: pasa t_ok, check_transaction veta t_vetada.
    assert [t.tx_id for t in b.mempool] == [t_ok.tx_id]


def test_trabajo_acumulado_es_suma_de_16_a_la_dificultad(tmp_path):
    a = _nuevo(tmp_path, "a")
    mine_and_add(a)
    mine_and_add(a)
    assert a.total_work == 16 ** 0 + 16 ** 1 + 16 ** 1
    assert isinstance(a.total_work, int)
