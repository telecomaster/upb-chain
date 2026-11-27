"""Tests del mecanismo de consenso PoW y PBFT."""
import pytest

from blockchain.core.block import Block
from blockchain.consensus.proof_of_work import ProofOfWork, estimate_rpi5_performance
from blockchain.consensus.pbft import ReplicaSet
from blockchain.core.wallet import Wallet


class TestProofOfWork:
    def test_mine_difficulty_1(self):
        pow_engine = ProofOfWork(difficulty=1)
        genesis = Block.create_genesis("test")
        candidate = Block(
            header=genesis.header.__class__(
                index=1,
                timestamp=genesis.header.timestamp + 1,
                previous_hash=genesis.hash,
                merkle_root=Block.compute_merkle_root([]),
                difficulty=1,
            ),
            transactions=[],
        )
        result = pow_engine.mine(candidate, timeout=30.0)
        assert result is not None
        assert int(result.hash, 16) < 2 ** 255  # 1 bit inicial en cero (P2-5)
        assert result.block.hash == result.hash

    def test_mining_stats_empty(self):
        pow_engine = ProofOfWork(difficulty=4)
        stats = pow_engine.get_mining_stats()
        assert stats == {}

    def test_rpi5_benchmark(self):
        result = estimate_rpi5_performance()
        assert result["hash_rate_per_second"] > 0
        assert "expected_time_16_bits_s" in result


class TestPBFT:
    """La clase ``PBFTNode`` anterior (sin firmas ni cambio de vista real) se reemplazó
    por ``PBFTReplica`` en P1-1; sus pruebas están en test_pbft.py y test_pbft_red.py."""

    def test_quorum_textual_4_replicas(self):
        rs = ReplicaSet.from_list([{"id": f"n{i}", "address": f"h:{i + 1}",
                                    "public_key": Wallet.generate().public_key_hex}
                                   for i in range(4)])
        # n = 3f + 1: con 4 réplicas f = 1, COMMIT necesita 2f+1 = 3 y PREPARE 2f = 2
        # (más el PRE-PREPARE del primario, que cuenta como su voto).
        assert (rs.f, rs.quorum, rs.prepare_quorum) == (1, 3, 2)
