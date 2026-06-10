"""
Tests de rendimiento para UPB-Chain.

Verifican que las operaciones core sean viables en hardware embebido (Raspberry Pi 5).
Todos los tests están marcados con @pytest.mark.slow para poder excluirlos en CI rápido.

Ejecutar: pytest tests/test_performance.py -v
Excluir:  pytest -m "not slow"
"""
import time
import pytest

from blockchain.core.block import Block, BlockHeader
from blockchain.core.chain import Blockchain
from blockchain.core.transaction import Transaction, TransactionType
from blockchain.core.wallet import Wallet
from blockchain.consensus.proof_of_work import ProofOfWork
from security.crypto_utils import benchmark_crypto


# ---------------------------------------------------------------------------
# Constantes de límite de tiempo
# ---------------------------------------------------------------------------

LIMIT_100_TX_S      = 1.0    # Crear 100 TXs < 1 segundo
LIMIT_VALIDATE_S    = 2.0    # Validar cadena 50 bloques < 2 segundos
LIMIT_MERKLE_MS     = 100.0  # Merkle root 200 TXs < 100 ms
LIMIT_BENCHMARK_S   = 30.0   # benchmark_crypto(1000) < 30 segundos
LIMIT_MINING_S      = 30.0   # Minado dificultad 2 < 30 segundos


# ---------------------------------------------------------------------------
# Fixtures locales (evitan cargar cadena ya minada en fixtures globales)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def _shared_wallet():
    return Wallet.generate()


# ---------------------------------------------------------------------------
# 1. Creación de transacciones
# ---------------------------------------------------------------------------

@pytest.mark.slow
def test_create_100_transactions_under_1_second(_shared_wallet):
    """Crear 100 objetos Transaction (incluye cálculo de tx_id SHA-256) < 1 s."""
    wallet = _shared_wallet
    start = time.perf_counter()
    for i in range(100):
        Transaction(
            type=TransactionType.DATA_RECORD,
            sender=wallet.address,
            recipient="UPB_PERF_DEST",
            payload={"data": f"perf_tx_{i}", "index": i},
        )
    elapsed = time.perf_counter() - start
    assert elapsed < LIMIT_100_TX_S, (
        f"Crear 100 TXs tardó {elapsed:.3f}s (límite {LIMIT_100_TX_S}s)"
    )


# ---------------------------------------------------------------------------
# 2. Validación de cadena
# ---------------------------------------------------------------------------

@pytest.mark.slow
def test_validate_chain_50_blocks_under_2_seconds(tmp_path, _shared_wallet):
    """validate_chain() sobre una cadena de 50 bloques debe completar < 2 s."""
    bc = Blockchain(
        node_id="perf_validate",
        data_dir=str(tmp_path / "perf_validate"),
    )
    wallet = _shared_wallet

    # Construir 50 bloques sin PoW (sólo valida integridad de hash)
    for i in range(50):
        tx = Transaction(
            type=TransactionType.DATA_RECORD,
            sender=wallet.address,
            recipient="DEST",
            payload={"i": i, "data": "perf_block"},
        )
        bc.add_transaction(tx)
        candidate = bc.create_candidate_block()
        bc.add_block(candidate)

    assert bc.height == 50, f"Altura esperada 50, obtenida {bc.height}"

    # Medir sólo la validación
    start = time.perf_counter()
    valid, reason = bc.validate_chain()
    elapsed = time.perf_counter() - start

    assert valid, f"Cadena inválida: {reason}"
    assert elapsed < LIMIT_VALIDATE_S, (
        f"validate_chain de 50 bloques tardó {elapsed:.3f}s (límite {LIMIT_VALIDATE_S}s)"
    )


# ---------------------------------------------------------------------------
# 3. Cálculo de Merkle root
# ---------------------------------------------------------------------------

@pytest.mark.slow
def test_merkle_root_200_txs_under_100ms():
    """compute_merkle_root() con 200 transacciones debe completar < 100 ms."""
    txs = [
        {"tx_id": str(i), "type": "DATA_RECORD", "data": f"tx_{i}", "value": i}
        for i in range(200)
    ]

    start = time.perf_counter()
    root = Block.compute_merkle_root(txs)
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert root, "Merkle root no debe ser vacío"
    assert len(root) == 64, "Merkle root debe ser SHA-256 (64 hex chars)"
    assert elapsed_ms < LIMIT_MERKLE_MS, (
        f"Merkle root de 200 TXs tardó {elapsed_ms:.2f}ms (límite {LIMIT_MERKLE_MS}ms)"
    )


# ---------------------------------------------------------------------------
# 4. Benchmark criptográfico
# ---------------------------------------------------------------------------

@pytest.mark.slow
def test_benchmark_crypto_1000_under_30_seconds():
    """benchmark_crypto(1000) debe completar en < 30 segundos.

    Incluye: 1000 ops de SHA-256/SHA3/BLAKE2b + 100 pares ECDSA sign/verify.
    """
    start = time.perf_counter()
    result = benchmark_crypto(iterations=1000)
    elapsed = time.perf_counter() - start

    assert "sha256" in result
    assert "ecdsa_sign_verify" in result
    assert result["sha256"]["ops_per_sec"] > 0
    assert elapsed < LIMIT_BENCHMARK_S, (
        f"benchmark_crypto(1000) tardó {elapsed:.2f}s (límite {LIMIT_BENCHMARK_S}s)"
    )


# ---------------------------------------------------------------------------
# 5. Minado con dificultad 2
# ---------------------------------------------------------------------------

@pytest.mark.slow
def test_mining_difficulty_2_under_30_seconds():
    """Minar un bloque con dificultad 2 (hash inicia con '00') debe tardar < 30 s.

    Con ~500 000 H/s estimados para RPi5, se esperan ~0.5 ms en promedio.
    El límite de 30 s proporciona margen para hardware lento o VMs.
    """
    pow_engine = ProofOfWork(difficulty=2)
    genesis = Block.create_genesis("perf_miner")

    candidate = Block(
        header=BlockHeader(
            index=1,
            timestamp=genesis.header.timestamp + 1.0,
            previous_hash=genesis.hash,
            merkle_root=Block.compute_merkle_root([]),
            difficulty=2,
        ),
        transactions=[],
    )

    start = time.perf_counter()
    result = pow_engine.mine(candidate, timeout=LIMIT_MINING_S)
    elapsed = time.perf_counter() - start

    assert result is not None, "Minado fallido o timeout alcanzado"
    assert result.hash.startswith("00"), (
        f"Hash no cumple dificultad 2: {result.hash[:8]}"
    )
    assert pow_engine.validate_proof(result.block)
    assert elapsed < LIMIT_MINING_S, (
        f"Minado dificultad 2 tardó {elapsed:.2f}s (límite {LIMIT_MINING_S}s)"
    )
