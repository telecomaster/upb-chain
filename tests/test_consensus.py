"""Tests del mecanismo de consenso PoW y PBFT."""
import pytest

from blockchain.core.block import Block
from blockchain.consensus.proof_of_work import ProofOfWork, estimate_rpi5_performance
from blockchain.consensus.pbft import PBFTNode, PBFTPhase


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
        assert result.hash.startswith("0")
        assert result.block.hash == result.hash

    def test_validate_proof(self):
        pow_engine = ProofOfWork(difficulty=1)
        genesis = Block.create_genesis("test")
        from blockchain.core.block import BlockHeader
        candidate = Block(
            header=BlockHeader(
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
        assert pow_engine.validate_proof(result.block)

    def test_invalid_hash_fails_validation(self):
        pow_engine = ProofOfWork(difficulty=4)
        genesis = Block.create_genesis("test")
        genesis.hash = "0" * 64  # hash inválido
        assert not pow_engine.validate_proof(genesis)

    def test_mining_stats_empty(self):
        pow_engine = ProofOfWork(difficulty=4)
        stats = pow_engine.get_mining_stats()
        assert stats == {}

    def test_rpi5_benchmark(self):
        result = estimate_rpi5_performance()
        assert result["hash_rate_per_second"] > 0
        assert "expected_time_difficulty_4_s" in result


class TestPBFT:
    def _make_network(self, n_nodes: int = 4):
        nodes = []
        peer_ids = [f"node_{i}" for i in range(n_nodes)]
        for i, node_id in enumerate(peer_ids):
            node = PBFTNode(node_id=node_id, peers=peer_ids, is_primary=(i == 0))
            nodes.append(node)
        return nodes

    def test_pbft_consensus_4_nodes(self):
        nodes = self._make_network(4)
        primary = nodes[0]
        request = {"block_hash": "abc123", "index": 1}

        pre_prepare = primary.propose(request)
        assert pre_prepare is not None
        assert pre_prepare.phase == PBFTPhase.PRE_PREPARE

        prepare_msgs = []
        for node in nodes[1:]:
            msg = node.handle_pre_prepare(pre_prepare)
            if msg:
                prepare_msgs.append(msg)

        commit_msgs = []
        for node in nodes:
            for prep in prepare_msgs:
                msg = node.handle_prepare(prep)
                if msg:
                    commit_msgs.append(msg)

        committed = []
        for node in nodes:
            for commit in commit_msgs:
                result = node.handle_commit(commit)
                if result:
                    committed.append(result)

        assert len(committed) > 0

    def test_fault_tolerance_calculation(self):
        nodes = self._make_network(7)
        primary = nodes[0]
        assert primary.f == 2  # tolera 2 nodos defectuosos con 7 nodos
        assert primary.quorum == 5

    def test_view_change(self):
        nodes = self._make_network(4)
        secondary = nodes[1]
        msg = secondary.trigger_view_change()
        assert secondary.view == 1
        assert secondary.is_primary is False

    def test_consensus_stats(self):
        nodes = self._make_network(4)
        stats = nodes[0].get_consensus_stats()
        assert "fault_tolerance_f" in stats
        assert "quorum_size" in stats
