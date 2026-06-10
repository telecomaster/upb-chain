"""
Fixtures compartidas para todos los tests de UPB-Chain.

Alcances (scope):
- function  → fixture se recrea para cada función de test (aislamiento total)
- module    → fixture se comparte dentro de un módulo (ahorra tiempo de setup caro)
"""
import pytest

from blockchain.core.chain import Blockchain
from blockchain.core.transaction import Transaction, TransactionType
from blockchain.core.wallet import Wallet
from blockchain.contracts.credential import CredentialContract


# ── Blockchain y Wallet ────────────────────────────────────────────────────────

@pytest.fixture
def chain(tmp_path):
    """Blockchain limpia con bloque génesis (datos en directorio temporal)."""
    return Blockchain(node_id="test_node", data_dir=str(tmp_path / "chain"))


@pytest.fixture
def wallet():
    """Wallet ECDSA nueva y única por cada test."""
    return Wallet.generate()


@pytest.fixture
def funded_chain(tmp_path):
    """Blockchain con 5 bloques y 10 transacciones ya incluidas (sin PoW).

    _validate_block sólo verifica integridad de hash y Merkle, no el prefijo
    de dificultad, por lo que los bloques se pueden añadir directamente.
    """
    bc = Blockchain(
        node_id="funded_node",
        data_dir=str(tmp_path / "funded_chain"),
    )
    w = Wallet.generate()
    for block_idx in range(5):
        for tx_idx in range(2):  # 2 TXs por bloque = 10 TXs en total
            tx = Transaction(
                type=TransactionType.DATA_RECORD,
                sender=w.address,
                recipient="UPB_DEST_ADDRESS",
                payload={
                    "data": f"block_{block_idx}_tx_{tx_idx}",
                    "value": block_idx * 10 + tx_idx,
                },
            )
            bc.add_transaction(tx)
        candidate = bc.create_candidate_block()
        bc.add_block(candidate)
    return bc


# ── Credenciales ───────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def issuer_wallet():
    """Wallet de universidad emisora; compartida en todo el módulo para ahorrar ECDSA."""
    return Wallet.generate()


@pytest.fixture
def student_wallet():
    """Wallet de estudiante; nueva por cada test para evitar IDs duplicados."""
    return Wallet.generate()


@pytest.fixture
def credential_contract(issuer_wallet):
    """CredentialContract fresco con emisor UPB ya registrado."""
    contract = CredentialContract()
    ok, reason = contract.register_issuer(issuer_wallet.address, "UPB")
    assert ok, f"Registro de emisor falló inesperadamente: {reason}"
    return contract


@pytest.fixture
def sample_credential_data():
    """Dict con todos los campos requeridos para emitir una credencial válida."""
    return {
        "student_name": "Ana García López",
        "program": "Ingeniería en Inteligencia Artificial",
        "degree": "Licenciatura en IA",
        "issue_date": "2025-06-10",
        "credential_type": "DEGREE",
        "grade": 87.5,
        "metadata": {"semester": "II-2025", "honors": False},
    }
