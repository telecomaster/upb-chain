"""Dashboard: bloques recientes (order=desc) y TXs recibidas por P2P hacia monitor y feed."""
from fastapi.testclient import TestClient

from blockchain.core.transaction import Transaction, TransactionType
from blockchain.core.wallet import Wallet
from tests.helpers import make_app


def _minar(c, n):
    for _ in range(n):
        assert c.post("/blocks/mine", json={"miner_address": "UPBMINER"}).status_code == 200


def test_blocks_orden_desc_y_paginacion(tmp_path):
    with TestClient(make_app(tmp_path)) as c:
        _minar(c, 12)                       # alturas 0..12 (13 bloques)
        asc = c.get("/blocks?page=0&size=10").json()
        assert [b["header"]["index"] for b in asc["blocks"]] == list(range(10))
        d0 = c.get("/blocks?page=0&size=10&order=desc").json()
        assert [b["header"]["index"] for b in d0["blocks"]] == list(range(12, 2, -1))
        d1 = c.get("/blocks?page=1&size=10&order=desc").json()
        assert [b["header"]["index"] for b in d1["blocks"]] == [2, 1, 0]
        assert d0["total"] == 13 and d0["order"] == "desc"
        assert c.get("/blocks?order=x").status_code == 422


def test_tx_recibida_por_p2p_pasa_por_monitor_y_feed(tmp_path):
    app = make_app(tmp_path)
    with TestClient(app):
        node = app.state.node
        monitor, eventos = [], []
        node.security_monitor.on_transaction = monitor.append
        node.events.publish = lambda ev, data=None: eventos.append((ev, data))
        w = Wallet.generate()
        tx = Transaction(type=TransactionType.DATA_RECORD, sender=w.address,
                         recipient="DEST", payload={"x": 1}, nonce=1)
        tx.sign(w.private_key_hex)
        node.p2p._handle_tx({"type": "TX", "data": tx.to_dict()})   # como si llegara de un par
        assert [t["tx_id"] for t in monitor] == [tx.tx_id]
        assert ("tx", {"tx_id": tx.tx_id, "pending": 1}) in eventos
