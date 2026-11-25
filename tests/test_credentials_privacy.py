"""Tests de P1-2: datos personales fuera de la cadena (compromiso Merkle + divulgación selectiva)."""
import copy

import pytest

from blockchain.core import commitment
from blockchain.core.transaction import (
    Transaction,
    TransactionType,
    create_issuer_register_transaction,
)
from blockchain.core.wallet import Wallet
from tests.helpers import mine_candidate
from tests.test_credentials_chain import (  # noqa: F401  (fixtures y ayudantes)
    _cadena, _datos, _emitir, _minar_api, _registrar, client, nodo,
)

pytestmark = pytest.mark.integration

NOMBRE = "Carla Rojas Única"


async def _emitida_confirmada(client, **extra):
    emisor, alumno = Wallet.generate(), Wallet.generate()
    await _registrar(client, emisor)
    r = await _emitir(client, emisor, alumno, _datos(student_name=NOMBRE, grade=93.5, **extra))
    assert r.status_code == 200, r.text
    await _minar_api(client)
    return r.json()


@pytest.mark.asyncio
async def test_cadena_y_chain_json_no_contienen_datos_personales(client, nodo):
    emitida = await _emitida_confirmada(client)
    bc = nodo.app.blockchain
    texto = (bc.data_dir / "chain.json").read_text(encoding="utf-8")
    import json
    texto += json.dumps([b.to_dict() for b in bc.chain])
    assert NOMBRE not in texto and "93.5" not in texto
    assert emitida["fields_root"] in texto
    for s in emitida["private_record"]["salts"].values():
        assert s not in texto
    tx = next(t for b in bc.chain for t in b.transactions
              if t["type"] == "CREDENTIAL_ISSUE")
    assert not ({"student_name", "grade", "metadata"} & set(tx["payload"]))
    # El nodo no guarda el registro privado en ningún archivo de datos.
    assert not any(NOMBRE in p.read_text(encoding="utf-8", errors="ignore")
                   for p in bc.data_dir.rglob("*") if p.is_file())


@pytest.mark.asyncio
async def test_divulgacion_de_subconjunto_verifica(client):
    emitida = await _emitida_confirmada(client)
    cid, rec = emitida["credential_id"], emitida["private_record"]
    assert rec["credential_id"] == cid and rec["fields"]["student_name"] == NOMBRE
    assert commitment.record_root(rec) == emitida["fields_root"]

    r = await client.post("/credentials/disclosure",
                          json={"private_record": rec, "fields": ["grade"]})
    assert r.status_code == 200, r.text
    paquete = r.json()
    assert [x["name"] for x in paquete["revealed"]] == ["grade"]
    assert NOMBRE not in str(paquete)  # solo lo elegido

    v = await client.post(f"/credentials/{cid}/disclose-verify",
                          json={"revealed": paquete["revealed"]})
    assert v.status_code == 200
    body = v.json()
    assert body["all_verified"] and body["fields"] == [{"name": "grade", "verified": True}]
    assert body["fields_root"] == emitida["fields_root"]

    todo = (await client.post("/credentials/disclosure", json={
        "private_record": rec, "fields": list(rec["fields"])})).json()
    v = (await client.post(f"/credentials/{cid}/disclose-verify",
                           json={"revealed": todo["revealed"]})).json()
    assert v["all_verified"] and len(v["fields"]) == len(rec["fields"])


@pytest.mark.asyncio
async def test_divulgacion_alterada_falla(client):
    emitida = await _emitida_confirmada(client)
    cid, rec = emitida["credential_id"], emitida["private_record"]
    item = (await client.post("/credentials/disclosure", json={
        "private_record": rec, "fields": ["student_name"]})).json()["revealed"][0]

    async def comprobar(it):
        r = await client.post(f"/credentials/{cid}/disclose-verify", json={"revealed": [it]})
        return r.json()["fields"][0]["verified"]

    assert await comprobar(item)
    valor = {**item, "value": "Otra Persona"}
    sal = {**item, "salt": "00" * 16}
    nombre = {**item, "name": "grade"}
    prueba = copy.deepcopy(item)
    prueba["proof"][0]["hash"] = "11" * 32
    for malo in (valor, sal, nombre, prueba, {"name": "x"}):
        assert not await comprobar(malo)
    # Credencial inexistente
    r = await client.post("/credentials/" + "0" * 32 + "/disclose-verify",
                          json={"revealed": [item]})
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_disclosure_con_campo_inexistente_da_400(client):
    emitida = await _emitida_confirmada(client)
    r = await client.post("/credentials/disclosure", json={
        "private_record": emitida["private_record"], "fields": ["no_existe"]})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_verify_publico_sigue_y_muestra_raiz_sin_datos(client):
    emitida = await _emitida_confirmada(client)
    cid = emitida["credential_id"]
    t = (await client.get(f"/verify/{cid}")).text
    assert emitida["fields_root"] in t and NOMBRE not in t and "93.5" not in t
    v = (await client.get(f"/credentials/verify/{cid}")).json()
    assert v["valid"] and v["credential"]["fields_root"] == emitida["fields_root"]
    assert "student_name" not in v["credential"] and "grade" not in v["credential"]
    qr = await client.get(f"/credentials/{cid}/qr")
    assert qr.status_code == 200
    assert NOMBRE not in emitida["qr_data"]


@pytest.mark.asyncio
async def test_emitir_sin_nombre_da_400(client):
    emisor = Wallet.generate()
    await _registrar(client, emisor)
    datos = _datos()
    del datos["student_name"]
    r = await _emitir(client, emisor, Wallet.generate(), datos)
    assert r.status_code == 400


def _tx_en_claro(emisor, alumno, **payload):
    base = {"program": "IA", "degree": "Lic. IA", "issue_date": "2026-06-10",
            "credential_type": "DEGREE", "fields_root": "ab" * 32}
    base.update(payload)
    tx = Transaction(TransactionType.CREDENTIAL_ISSUE, emisor.address, alumno, base, nonce=1)
    tx.sign(emisor.private_key_hex)
    return tx


def test_tx_con_datos_personales_en_claro_se_rechaza_en_mempool_y_bloque(tmp_path):
    autoridad, emisor = Wallet.generate(), Wallet.generate()
    alumno = Wallet.generate().address
    bc = _cadena(tmp_path / "a", autoridad)
    registro = create_issuer_register_transaction(
        autoridad.address, emisor.address, "UPB", autoridad.private_key_hex, nonce=1)
    assert bc.add_transaction(registro)[0]
    ok, why = bc.add_block(mine_candidate(bc, [registro]))
    assert ok, why

    for extra in ({"student_name": "Ana"}, {"grade": 90}, {"metadata": {"a": 1}}):
        tx = _tx_en_claro(emisor, alumno, **extra)
        ok, why = bc.add_transaction(tx)
        assert not ok and "no permitidos" in why
        ok, why = bc.add_block(mine_candidate(bc, [tx]))
        assert not ok and "no permitidos" in why
    for malo in ({"fields_root": "xyz"}, {"fields_root": "AB" * 32}, {"campo_raro": 1}):
        tx = _tx_en_claro(emisor, alumno, **malo)
        assert not bc.add_transaction(tx)[0]
    sin_raiz = _tx_en_claro(emisor, alumno)
    del sin_raiz.payload["fields_root"]
    sin_raiz.sign(emisor.private_key_hex)
    assert not bc.add_transaction(sin_raiz)[0]
    # La válida sí entra.
    assert bc.add_transaction(_tx_en_claro(emisor, alumno))[0]


def test_compromiso_es_determinista_dado_sales_y_cambia_con_cualquier_campo():
    rec = commitment.build_private_record({"a": 1, "b": "x", "c": {"k": [1, 2]}})
    assert all(len(s) == 32 for s in rec["salts"].values())
    assert commitment.record_root(rec) == rec["fields_root"]
    rec2 = copy.deepcopy(rec)
    rec2["fields"]["b"] = "y"
    assert commitment.record_root(rec2) != rec["fields_root"]
    otro = commitment.build_private_record(rec["fields"])
    assert otro["fields_root"] != rec["fields_root"]  # sales distintas
