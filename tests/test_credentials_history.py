"""Tests de P1-4: listado por emisor, historial de credencial y formulario del dashboard."""
import pytest

from blockchain.core.wallet import Wallet
from tests.test_credentials_chain import (  # noqa: F401  (fixtures y ayudantes)
    _datos, _emitir, _minar_api, _registrar, _revocar, client, nodo,
)

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_emisor_e_historial_emitir_minar_revocar_minar(client):
    emisor, alumno = Wallet.generate(), Wallet.generate()
    await _registrar(client, emisor)
    await _minar_api(client)
    cid = (await _emitir(client, emisor, alumno, _datos(grade=97))).json()["credential_id"]

    r = (await client.get(f"/credentials/issuer/{emisor.address}")).json()
    assert r["count"] == 1 and r["credentials"][0]["status"] == "PENDING"
    h = (await client.get(f"/credentials/{cid}/history")).json()
    assert [e["event"] for e in h["events"]] == ["ISSUE_PENDING"]

    b_emision = await _minar_api(client)
    h = (await client.get(f"/credentials/{cid}/history")).json()
    assert h["status"] == "CONFIRMED" and h["block_index"] == b_emision
    assert h["events"][0] == {"event": "ISSUED", "block": b_emision, "tx_id": h["tx_id"]}

    await _revocar(client, emisor, cid, "Motivo X")
    h = (await client.get(f"/credentials/{cid}/history")).json()
    assert h["events"][-1]["event"] == "REVOKE_PENDING"
    b_rev = await _minar_api(client)

    h = (await client.get(f"/credentials/{cid}/history")).json()
    assert h["status"] == "REVOKED" and h["revocation_block"] == b_rev
    assert [e["event"] for e in h["events"]] == ["ISSUED", "REVOKED"]
    assert h["events"][1]["reason"] == "Motivo X"
    lista = (await client.get(f"/credentials/issuer/{emisor.address}")).json()["credentials"]
    assert lista[0]["verdict"] == "REVOCADA"
    # No se exponen notas ni nombre
    for d in (lista[0], h):
        assert "grade" not in d and "student_name" not in d and "metadata" not in d
        assert "Carla" not in str(d)


@pytest.mark.asyncio
async def test_historial_desconocido_y_emisor_vacio(client):
    assert (await client.get("/credentials/" + "0" * 32 + "/history")).status_code == 404
    r = (await client.get("/credentials/issuer/nadie")).json()
    assert r["count"] == 0


@pytest.mark.asyncio
async def test_dashboard_contiene_formularios(client):
    t = (await client.get("/")).text
    for ident in ("revoke-id", "revoke-reason", "revoke-btn", "history-addr", "history-list"):
        assert f'id="{ident}"' in t
