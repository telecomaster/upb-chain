"""P2-4: límite del WAL; P1-5: sin alertas falsas al ponerse al día."""
import time

from blockchain.core.chain import Blockchain
from blockchain.core.storage import WAL_SIZE_LIMIT
from tests.helpers import make_app


def test_wal_tiene_journal_size_limit(tmp_path):
    bc = Blockchain("n", str(tmp_path / "n"), initial_difficulty=1, min_difficulty=1, max_difficulty=1)
    limite = bc.store._conn.execute("PRAGMA journal_size_limit").fetchone()[0]
    assert limite == WAL_SIZE_LIMIT == 8 * 1024 * 1024
    bc.store.checkpoint()
    bc.close()


def test_reorg_sin_descartados_no_alerta(tmp_path):
    node = make_app(tmp_path).state.node
    llamadas = []
    node.security_monitor.on_chain_reorg = lambda d: llamadas.append(d)
    node.on_chain_reorg(0, [], [])
    assert llamadas == []
    node.on_chain_reorg(0, [object()], [])
    assert llamadas == [1]


def test_bloque_viejo_no_levanta_alerta(tmp_path):
    node = make_app(tmp_path).state.node
    base = time.time() - 7200
    for i in range(12):                          # historia regular, vieja
        node.announce_block({"hash": f"{i:064d}", "header": {"index": i, "timestamp": base + 10 * i,
                                                              "difficulty": 1}, "transactions": []})
    node.announce_block({"hash": "f" * 64, "header": {"index": 13, "timestamp": base + 5000,
                                                       "difficulty": 1}, "transactions": []})
    assert len(node.block_anomaly_detector._block_times) == 13
    assert not [a for a in node.security_monitor.get_alerts() if a["event_type"] == "BLOCK_ANOMALY"]
