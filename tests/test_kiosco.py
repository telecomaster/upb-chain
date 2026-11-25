"""Tests de la idea 4: kiosco verificador (rutas y paridad JS/Python de Merkle y compromiso)."""
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from blockchain.core import commitment, merkle
from blockchain.core.wallet import Wallet
from tests.test_credentials_chain import (  # noqa: F401  (fixtures y ayudantes)
    _datos, _emitir, _minar_api, _registrar, client, nodo,
)

JS = Path(__file__).parent / "js" / "kiosco_cross_check.mjs"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_rutas_kiosco_y_estaticos(client):
    r = await client.get("/kiosco")
    assert r.status_code == 200 and "Kiosco verificador" in r.text
    assert "<script>" not in r.text and "onclick" not in r.text   # sin JS en línea
    r = await client.get("/kiosco/abc123def456")
    assert 'data-id="abc123def456"' in r.text
    assert 'data-id=""' in (await client.get("/kiosco")).text
    assert "<" not in (await client.get('/kiosco/"><x')).text.split('data-id="')[1].split('"')[0]
    assert (await client.get("/static/kiosco.js")).status_code == 200
    assert (await client.get("/static/kiosco.css")).status_code == 200


@pytest.mark.integration
@pytest.mark.asyncio
async def test_datos_que_consume_el_kiosco(client):
    emisor, estudiante = Wallet.generate(), Wallet.generate()
    await _registrar(client, emisor)
    r = await _emitir(client, emisor, estudiante, _datos())
    cid = r.json()["credential_id"]
    await _minar_api(client)
    st = (await client.get(f"/credentials/verify/{cid}")).json()
    assert st["verdict"] and st["tx_id"] and st["block_index"] is not None
    p = (await client.get(f"/tx/{st['tx_id']}/proof")).json()
    bloque = (await client.get(f"/blocks/{st['block_index']}")).json()
    assert p["merkle_root"] == bloque["header"]["merkle_root"]
    assert merkle.verify_proof(p["leaf"], p["proof"], bloque["header"]["merkle_root"])
    # PoW: no hay certificado
    assert (await client.get(f"/blocks/{st['block_index']}/certificate")).status_code == 404


def _casos():
    merkle_casos = []
    for n in (0, 1, 2, 3, 4, 5, 7, 8, 13):
        hojas = [hashlib.sha256(f"hoja{n}-{i}".encode()).hexdigest() for i in range(n)]
        merkle_casos.append({
            "leaves": hojas, "root": merkle.merkle_root_from_leaves(hojas),
            "proofs": [{"leaf": hojas[i], "proof": merkle.build_proof(hojas, i)} for i in range(n)]})
    campos = [
        {"name": "student_name", "value": "Ñandú Pérez ✓", "salt": "00" * 16},
        {"name": "grade", "value": 87.25, "salt": "ab" * 16},
        {"name": "metadata", "value": {"z": [1, "a", None, True], "a": {"y": 2, "b": "é\n\"q\""}},
         "salt": "0f" * 16},
        {"name": "n", "value": 0, "salt": "ff" * 16},
    ]
    esperadas = [commitment.field_leaf(c["name"], c["value"], c["salt"]) for c in campos]
    return merkle_casos, campos, esperadas


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js no está instalado")
def test_kiosco_js_coincide_con_python():
    merkle_casos, campos, esperadas = _casos()
    entrada = json.dumps({"merkle": merkle_casos, "campos": campos})
    res = subprocess.run(["node", str(JS)], input=entrada.encode("utf-8"),
                         capture_output=True, timeout=60, check=True)
    salida = json.loads(res.stdout.decode("utf-8"))
    assert salida["raices"] == [c["root"] for c in merkle_casos]
    assert all(all(oks) and len(oks) == len(c["proofs"])
               for oks, c in zip(salida["pruebas"], merkle_casos))
    assert salida["hojas"] == esperadas
