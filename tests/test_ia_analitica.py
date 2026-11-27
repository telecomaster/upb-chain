"""/ai/analytics: institución desde el registro de emisores y verificaciones locales (sin métrica fantasma)."""
import os
import time

os.environ.setdefault("NODE_PORT", "0")

import pytest
from httpx import ASGITransport, AsyncClient

from blockchain.core.wallet import Wallet
from tests.helpers import make_app


@pytest.mark.asyncio
async def test_analitica_institucion_y_verificaciones_locales(tmp_path):
    autoridad = Wallet.generate()
    app = make_app(tmp_path, autoridad=autoridad, mining_difficulty=1)
    emisor, estudiante = Wallet.generate(), Wallet.generate()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://127.0.0.1") as c:
        r = await c.post("/credentials/issuers",
                         json={"issuer_address": emisor.address, "institution_code": "UPB"})
        assert r.status_code == 200, r.text
        assert (await c.post("/blocks/mine", json={})).status_code == 200
        r = await c.post("/credentials/issue", json={
            "issuer_address": emisor.address, "student_address": estudiante.address,
            "private_key_hex": emisor.private_key_hex,
            "credential_data": {"student_name": "Ana", "program": "IA", "degree": f"Lic {time.time_ns()}",
                                "issue_date": "2026-06-10", "credential_type": "DEGREE", "grade": 90}})
        assert r.status_code == 200, r.text
        cid = r.json()["credential_id"]
        assert (await c.post("/blocks/mine", json={})).status_code == 200

        antes = (await c.get("/ai/analytics")).json()["credential_stats"]
        assert antes["top_institutions"] == {"UPB": 1}
        assert "verified" not in antes and antes["local_verifications"] == 0

        await c.get(f"/credentials/verify/{cid}")
        await c.get(f"/verify/{cid}")
        rep = (await c.get("/ai/analytics")).json()
        assert rep["credential_stats"]["local_verifications"] == 2
        assert not any("verificaciones registradas" in x for x in rep["recommendations"])
