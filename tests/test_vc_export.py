"""Tests de P2-3: Verifiable Credentials y did:web (capa de exportación, sin tocar consenso)."""
import asyncio
import copy
import importlib.util
import pathlib

import pytest

from blockchain.core.wallet import Wallet
from tests.test_credentials_chain import (  # noqa: F401  (fixtures y ayudantes)
    _datos, _emitir, _minar_api, _registrar, _revocar, client, nodo,
)

pytestmark = pytest.mark.integration

_RUTA = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "verificar_vc.py"
_spec = importlib.util.spec_from_file_location("verificar_vc", _RUTA)
verificar_vc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verificar_vc)


async def _confirmada(client, nodo):
    emisor, estudiante = Wallet.generate(), Wallet.generate()
    await _registrar(client, emisor)
    r = await _emitir(client, emisor, estudiante, _datos())
    assert r.status_code == 200, r.text
    await _minar_api(client)
    return emisor, estudiante, r.json()["credential_id"], r.json()["private_record"]


async def _verificar(vc, client):
    """verify_vc es síncrona: corre en un hilo y sus GET vuelven al bucle del test."""
    bucle = asyncio.get_running_loop()

    def fetch(ruta):
        r = asyncio.run_coroutine_threadsafe(client.get(ruta), bucle).result(timeout=30)
        r.raise_for_status()
        return r.json()
    return await asyncio.to_thread(verificar_vc.verify_vc, vc, fetch)


def _fallos(res):
    return [n for n, ok, _ in res if not ok]


@pytest.mark.asyncio
async def test_did_json_forma_y_llaves(client, nodo):
    emisor, _, _, _ = await _confirmada(client, nodo)
    r = await client.get("/.well-known/did.json")
    assert r.status_code == 200
    doc = r.json()
    assert doc["id"] == "did:web:test"
    ids = {m["id"]: m for m in doc["verificationMethod"]}
    for addr in (emisor.address, nodo.autoridad.address):
        m = ids[f"did:web:test#{addr}"]
        assert m["type"] == "JsonWebKey" and m["controller"] == "did:web:test"
        assert m["publicKeyJwk"]["kty"] == "EC" and m["publicKeyJwk"]["crv"] == "secp256k1"
    # La llave publicada es exactamente la del emisor.
    from blockchain.contracts.vc_export import jwk_from_public_key_hex
    assert ids[f"did:web:test#{emisor.address}"]["publicKeyJwk"] == jwk_from_public_key_hex(emisor.public_key_hex)
    assert set(doc["assertionMethod"]) == set(ids)


@pytest.mark.asyncio
async def test_did_domain_configurable(client, nodo):
    nodo.node.settings = nodo.node.settings.model_copy(update={"did_web_domain": "upb.edu.bo"})
    assert (await client.get("/.well-known/did.json")).json()["id"] == "did:web:upb.edu.bo"


@pytest.mark.asyncio
async def test_vc_miembros_y_anclas(client, nodo):
    emisor, estudiante, cid, _ = await _confirmada(client, nodo)
    r = await client.get(f"/credentials/{cid}/vc")
    assert r.status_code == 200
    vc = r.json()
    assert vc["@context"][0] == "https://www.w3.org/ns/credentials/v2"
    assert vc["type"] == ["VerifiableCredential", "OpenBadgeCredential"]
    assert "proof" not in vc
    assert vc["issuer"]["id"] == f"did:web:test#{emisor.address}"
    assert vc["credentialSubject"]["id"].endswith(estudiante.address)
    assert vc["credentialSubject"]["achievement"]["name"].startswith("Licenciatura en IA")
    assert vc["credentialStatus"]["status"] == "CONFIRMED"
    assert vc["credentialStatus"]["id"].endswith(f"/credentials/verify/{cid}")
    ev = vc["evidence"][0]
    prueba = (await client.get(f"/tx/{ev['txId']}/proof")).json()
    assert ev["blockHash"] == prueba["block_hash"] and ev["merkleProof"] == prueba["proof"]
    assert ev["merkleRoot"] == prueba["merkle_root"]
    assert ev["fieldsRoot"] == (await client.get(f"/credentials/verify/{cid}")).json()["credential"]["fields_root"]
    assert "Carla Rojas" not in r.text  # nada privado
    assert _fallos(await _verificar(vc, client)) == []


@pytest.mark.asyncio
async def test_vc_revocada_refleja_estado(client, nodo):
    emisor, _, cid, _ = await _confirmada(client, nodo)
    await _revocar(client, emisor, cid)
    await _minar_api(client)
    vc = (await client.get(f"/credentials/{cid}/vc")).json()
    assert vc["credentialStatus"]["status"] == "REVOKED"
    assert "estado vigente" in _fallos(await _verificar(vc, client))


@pytest.mark.asyncio
async def test_desconocida_404(client):
    cid = "0" * 32
    assert (await client.get(f"/credentials/{cid}/vc")).status_code == 404
    r = await client.post(f"/credentials/{cid}/vc/disclose",
                          json={"private_record": {"fields": {}, "salts": {}}, "fields": []})
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_divulgacion_verifica_y_manipulada_falla(client, nodo):
    _, _, cid, registro = await _confirmada(client, nodo)
    r = await client.post(f"/credentials/{cid}/vc/disclose",
                          json={"private_record": registro, "fields": ["grade"]})
    assert r.status_code == 200, r.text
    vc = r.json()
    div = vc["credentialSubject"]["upbDisclosure"]
    assert "UPBSaltedFieldDisclosure" in vc["credentialSubject"]["type"]
    assert [i["name"] for i in div["revealed"]] == ["grade"]
    assert "Carla Rojas" not in r.text  # solo lo elegido
    assert _fallos(await _verificar(vc, client)) == []

    malo = copy.deepcopy(vc)
    malo["credentialSubject"]["upbDisclosure"]["revealed"][0]["value"] = 100
    assert "divulgación: campo grade" in _fallos(await _verificar(malo, client))
    sal = copy.deepcopy(vc)
    sal["credentialSubject"]["upbDisclosure"]["fieldsRoot"] = "f" * 64
    assert "divulgación: raíz = fields_root en cadena" in _fallos(await _verificar(sal, client))


@pytest.mark.asyncio
async def test_registro_ajeno_se_rechaza_y_ancla_manipulada_falla(client, nodo):
    _, _, cid, registro = await _confirmada(client, nodo)
    ajeno = copy.deepcopy(registro)
    ajeno["fields"]["grade"] = 1
    r = await client.post(f"/credentials/{cid}/vc/disclose",
                          json={"private_record": ajeno, "fields": ["grade"]})
    assert r.status_code == 400
    vc = (await client.get(f"/credentials/{cid}/vc")).json()
    vc["evidence"][0]["blockHash"] = "a" * 64
    assert "hash del bloque recalculado" in _fallos(await _verificar(vc, client))
