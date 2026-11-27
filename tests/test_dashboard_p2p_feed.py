"""Dashboard: /blocks con order=desc para mostrar los bloques más recientes."""
from fastapi.testclient import TestClient



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


