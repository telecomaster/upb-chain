"""Tests de la cadena de bloques y lógica core."""
import time
import pytest

from blockchain.core.block import Block, BlockHeader
from blockchain.core.chain import Blockchain
from blockchain.core.transaction import Transaction, TransactionType
from blockchain.core.wallet import Wallet
from tests.helpers import mine_and_add


@pytest.fixture
def chain(tmp_path):
    return Blockchain(node_id="test_node", data_dir=str(tmp_path / "chain"), initial_difficulty=1)


@pytest.fixture
def wallet():
    return Wallet.generate()


class TestBlock:
    def test_genesis_creation(self):
        genesis = Block.create_genesis("test")
        assert genesis.header.index == 0
        assert genesis.header.previous_hash == "0" * 64
        assert genesis.hash == genesis.compute_hash()

    def test_hash_changes_with_nonce(self):
        genesis = Block.create_genesis("test")
        h1 = genesis.compute_hash()
        genesis.header.nonce = 1
        h2 = genesis.compute_hash()
        assert h1 != h2

    def test_merkle_root_deterministic(self):
        txs = [{"id": "1", "data": "a"}, {"id": "2", "data": "b"}]
        r1 = Block.compute_merkle_root(txs)
        r2 = Block.compute_merkle_root(txs)
        assert r1 == r2

    def test_merkle_root_changes_with_data(self):
        txs1 = [{"id": "1", "data": "a"}]
        txs2 = [{"id": "1", "data": "b"}]
        assert Block.compute_merkle_root(txs1) != Block.compute_merkle_root(txs2)

    def test_block_serialization(self):
        genesis = Block.create_genesis("test")
        data = genesis.to_dict()
        restored = Block.from_dict(data)
        assert restored.hash == genesis.hash
        assert restored.header.index == genesis.header.index


class TestBlockchain:
    def test_init_creates_genesis(self, chain):
        assert len(chain.chain) == 1
        assert chain.chain[0].header.index == 0

    def test_add_valid_transaction(self, chain, wallet):
        tx = Transaction(
            type=TransactionType.DATA_RECORD,
            sender=wallet.address,
            recipient="DEST",
            payload={"data": "test"},
            nonce=1,
        )
        tx.sign(wallet.private_key_hex)
        ok, reason = chain.add_transaction(tx)
        assert ok, reason
        assert len(chain.mempool) == 1

    def test_reject_duplicate_transaction(self, chain, wallet):
        tx = Transaction(
            type=TransactionType.DATA_RECORD,
            sender=wallet.address,
            recipient="DEST",
            payload={"data": "test"},
            nonce=1,
        )
        tx.sign(wallet.private_key_hex)
        chain.add_transaction(tx)
        ok, reason = chain.add_transaction(tx)
        assert not ok
        assert "duplicada" in reason.lower()

    def test_create_candidate_block(self, chain, wallet):
        tx = Transaction(
            type=TransactionType.DATA_RECORD,
            sender=wallet.address,
            recipient="DEST",
            payload={"data": "test"},
            nonce=1,
        )
        tx.sign(wallet.private_key_hex)
        chain.add_transaction(tx)
        candidate = chain.create_candidate_block()
        assert candidate.header.index == 1
        assert candidate.header.previous_hash == chain.last_block.hash
        assert len(candidate.transactions) == 1

    def test_validate_chain_integrity(self, chain):
        valid, reason = chain.validate_chain()
        assert valid, reason

    def test_detect_tampered_chain(self, chain, wallet):
        tx = Transaction(
            type=TransactionType.DATA_RECORD,
            sender=wallet.address,
            recipient="DEST",
            payload={"data": "test"},
            nonce=1,
        )
        tx.sign(wallet.private_key_hex)
        chain.add_transaction(tx)
        ok, reason = mine_and_add(chain)
        assert ok, reason

        # Tamper
        chain.chain[1].transactions[0]["data"] = "tampered"
        valid, reason = chain.validate_chain()
        assert not valid

    def test_chain_stats(self, chain):
        stats = chain.get_stats()
        assert stats["height"] == 0
        assert stats["total_blocks"] == 1

    @pytest.mark.xfail(
        strict=False,
        reason="Fee-based mempool ordering no está implementado; mempool usa FIFO",
    )
    def test_mempool_sorted_by_fee(self, tmp_path):
        """TXs con mayor fee deben procesarse primero en el bloque candidato.

        La implementación actual usa orden FIFO (sin prioridad por fee).
        Este test documenta el comportamiento esperado y estará marcado como
        XFAIL hasta que se implemente la priorización por fee en el mempool.
        Fees enteras (P0-9): cada remitente recibe saldo con TOKEN_MINT para pagarlas.
        """
        from blockchain.core.transaction import create_mint_transaction
        autoridad = Wallet.generate()
        bc = Blockchain("fee_node", str(tmp_path / "fees"), initial_difficulty=1,
                        authority_address=autoridad.address)
        remitentes = [Wallet.generate() for _ in range(3)]
        for i, w in enumerate(remitentes, start=1):
            ok, why = bc.add_transaction(create_mint_transaction(
                autoridad.address, w.address, 100, autoridad.private_key_hex, nonce=i))
            assert ok, why
        assert mine_and_add(bc)[0]
        # Insertamos en orden: bajo → alto → medio
        for w, fee in zip(remitentes, (1, 10, 5)):
            tx = Transaction(type=TransactionType.DATA_RECORD, sender=w.address,
                             recipient="DEST", payload={"data": f"fee_{fee}"},
                             fee=fee, nonce=1)
            tx.sign(w.private_key_hex)
            ok, why = bc.add_transaction(tx)
            assert ok, why

        candidate = bc.create_candidate_block()
        fees = [tx.get("fee", 0) for tx in candidate.transactions]
        assert len(fees) == 3

        # Las fees en el bloque deben estar ordenadas de mayor a menor
        assert fees == sorted(fees, reverse=True), (
            f"Se esperaba orden descendente por fee, obtenido: {fees}"
        )

    def test_blockchain_persistence(self, tmp_path):
        """Guarda la cadena en disco, recarga desde disco y la altura debe ser igual."""
        data_dir = str(tmp_path / "persist_chain")

        # Crear cadena con un bloque adicional
        bc1 = Blockchain(node_id="persist_test", data_dir=data_dir, initial_difficulty=1)
        w = Wallet.generate()
        tx = Transaction(
            type=TransactionType.DATA_RECORD,
            sender=w.address,
            recipient="DEST",
            payload={"data": "persistence_test"},
            nonce=1,
        )
        tx.sign(w.private_key_hex)
        bc1.add_transaction(tx)
        ok, reason = mine_and_add(bc1)
        assert ok, reason
        height_before = bc1.height
        last_hash_before = bc1.last_block.hash

        # Recargar desde disco con una nueva instancia
        bc2 = Blockchain(node_id="persist_test", data_dir=data_dir, initial_difficulty=1)
        assert bc2.height == height_before, (
            f"Altura tras recarga: {bc2.height}, esperada: {height_before}"
        )
        assert bc2.last_block.hash == last_hash_before, (
            "Hash del último bloque no coincide tras recarga"
        )
        # La cadena recargada debe ser válida
        valid, validation_reason = bc2.validate_chain()
        assert valid, validation_reason

    def test_validate_genesis_block(self, tmp_path):
        """El bloque génesis siempre debe ser válido y tener hash previo de ceros."""
        bc = Blockchain(
            node_id="genesis_val_test",
            data_dir=str(tmp_path / "genesis_val"),
        )
        genesis = bc.chain[0]

        assert genesis.header.index == 0
        assert genesis.header.previous_hash == "0" * 64
        assert genesis.hash == genesis.compute_hash(), (
            "El hash del génesis no coincide con su cálculo"
        )

        valid, reason = bc.validate_chain()
        assert valid, f"Cadena con sólo génesis no válida: {reason}"


class TestWallet:
    def test_generate_unique_addresses(self):
        w1 = Wallet.generate()
        w2 = Wallet.generate()
        assert w1.address != w2.address
        assert w1.private_key_hex != w2.private_key_hex

    def test_address_starts_with_upb(self):
        w = Wallet.generate()
        assert w.address.startswith("UPB")

    def test_export_and_load(self, tmp_path):
        w = Wallet.generate()
        path = str(tmp_path / "wallet.json")
        w.export(path)
        loaded = Wallet.load(path)
        assert loaded.address == w.address
        assert loaded.private_key_hex == w.private_key_hex
