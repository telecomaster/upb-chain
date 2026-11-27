"""P0-4: el minado serializa el bloque una vez; el hash debe ser idéntico al canónico."""
import random

import pytest

from blockchain.consensus.proof_of_work import ProofOfWork
from blockchain.core.block import Block, BlockHeader

pytestmark = pytest.mark.unit


def _bloque_aleatorio(rng: random.Random, n_tx: int) -> Block:
    txs = [
        {
            "id": f"tx{i}",
            "monto": rng.random() * 1000,
            "nota": rng.choice(["ñandú", "日本語", "emoji 🚀", "plain", 'q"uote\\']),
            "lista": [rng.randint(-5, 5), 1.5e-7, None, True],
            "nonce": rng.randint(0, 9),
        }
        for i in range(n_tx)
    ]
    header = BlockHeader(
        index=rng.randint(1, 99), timestamp=1_700_000_000.123,
        previous_hash="ab" * 32, merkle_root=Block.compute_merkle_root(txs),
        difficulty=8, node_id="nodo-ñ",
    )
    return Block(header=header, transactions=txs)


def test_hash_rapido_igual_al_canonico():
    rng = random.Random(7)
    for _ in range(20):
        b = _bloque_aleatorio(rng, rng.randint(0, 12))
        f = b.hasher_por_nonce()
        nonces = [0, 1, 9, 10, 255, 10**6, 2**32 - 1] + [rng.randint(0, 2**40) for _ in range(20)]
        for nonce in nonces:
            b.header.nonce = nonce
            assert f(nonce) == b.compute_hash()


def test_hash_rapido_con_centinela_en_contenido():
    """Si el texto del centinela aparece en las TXs se usa el camino lento, igual de correcto."""
    b = _bloque_aleatorio(random.Random(1), 2)
    b.transactions[0]["nota"] = "987654321098765432109876543210"
    f = b.hasher_por_nonce()
    for nonce in (0, 5, 123456):
        b.header.nonce = nonce
        assert f(nonce) == b.compute_hash()


def test_bloque_minado_valida_y_conserva_nonce():
    b = _bloque_aleatorio(random.Random(3), 5)
    r = ProofOfWork(difficulty=10).mine(b)
    assert r is not None
    assert b.hash == b.compute_hash()
    assert b.header.nonce == r.nonce
