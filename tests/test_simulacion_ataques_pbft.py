"""/security/attack-simulation: resumen con descripción y escenarios PoW que no aplican en PBFT."""
import os

os.environ.setdefault("NODE_PORT", "0")

import pytest
from httpx import ASGITransport, AsyncClient

from security.attacks.simulator import full_security_analysis
from tests.helpers import make_app


def test_pbft_no_simula_51_ni_doble_gasto():
    r = full_security_analysis(node_count=4, consensus="pbft", pbft_f=1, pbft_n=4)
    for k in ("51_percent", "double_spend_6conf", "double_spend_12conf"):
        assert r[k]["applicable"] is False and r[k]["success"] is False
        assert "No aplica en PBFT" in r[k]["description"]
    assert "f=1" in r["51_percent"]["description"]
    assert r["_summary"]["description"]
    pow_ = full_security_analysis(node_count=4, honest_hash_rate=40.0, attacker_hash_rate=60.0, consensus="pow")
    assert pow_["51_percent"]["success"] is True and "applicable" not in pow_["51_percent"]


@pytest.mark.asyncio
async def test_endpoint_resumen_con_descripcion(tmp_path):
    app = make_app(tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://127.0.0.1") as c:
        data = (await c.get("/security/attack-simulation")).json()
    assert data["_summary"]["description"]
    assert all("description" in v for v in data.values())
