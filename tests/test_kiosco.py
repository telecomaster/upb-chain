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


# ── Verificación local en el navegador (JS) contra bloques reales ────────────

JS_LOCAL = Path(__file__).parent / "js" / "kiosco_verificar_local.mjs"


def _rehash(bloque: dict, **cabecera) -> dict:
    """Copia del bloque con campos de cabecera cambiados y su hash recalculado en Python."""
    from blockchain.core.block import Block, BlockHeader
    h = {**bloque["header"], **cabecera}
    return Block(BlockHeader(**h), bloque["transactions"]).to_dict()


def _correr_js(casos):
    res = subprocess.run(["node", str(JS_LOCAL)], input=json.dumps({"casos": casos}).encode("utf-8"),
                         capture_output=True, timeout=60, check=True)
    return json.loads(res.stdout.decode("utf-8"))


def _fallos(salida):
    return [c["texto"] for c in salida["checks"] if c["ok"] is False]


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js no está instalado")
async def test_kiosco_verifica_localmente_pow_y_pbft(client):
    from blockchain.consensus.pbft import COMMIT, sign_message
    emisor, estudiante = Wallet.generate(), Wallet.generate()
    await _registrar(client, emisor)
    r = await _emitir(client, emisor, estudiante, {**_datos(), "degree": "Ingeniería Electrónica ñ"})
    cid = r.json()["credential_id"]
    await _minar_api(client)
    st = (await client.get(f"/credentials/verify/{cid}")).json()
    bloque = (await client.get(f"/blocks/{st['block_index']}")).json()
    bloque.pop("anomaly", None)
    prueba = (await client.get(f"/tx/{st['tx_id']}/proof")).json()
    base = {"id": cid, "tx_id": st["tx_id"], "prueba": prueba}
    pow_ = {"mode": "pow"}

    # PBFT sintético sobre el mismo contenido: dificultad 0 y certificado con firmas reales.
    reps = [Wallet.generate() for _ in range(4)]
    consenso = {"mode": "pbft", "replicas": [
        {"id": f"r{i}", "public_key": w.public_key_hex} for i, w in enumerate(reps)]}
    bpbft = _rehash(bloque, difficulty=0, nonce=0)
    idx = bpbft["header"]["index"]

    def cert(n):
        return {"view": 0, "seq": idx, "digest": bpbft["hash"], "commits": [
            sign_message({"type": COMMIT, "view": 0, "seq": idx, "digest": bpbft["hash"],
                          "replica": f"r{i}"}, reps[i].private_key_hex) for i in range(n)]}

    mala_tx = json.loads(json.dumps(bloque))
    for t in mala_tx["transactions"]:
        if t["tx_id"] == st["tx_id"]:
            t["payload"]["degree"] = "Otro título"
    cert_repetido = cert(3)
    cert_repetido["commits"][0] = cert_repetido["commits"][1]      # firmante repetido
    prueba_pbft = {**prueba, "block_hash": bpbft["hash"]}
    salida = _correr_js([
        {**base, "bloque": bloque, "consenso": pow_, "cert": None},                          # 0 PoW ok
        {**base, "bloque": bpbft, "consenso": consenso, "cert": cert(3), "prueba": prueba_pbft},  # 1 PBFT 3/4
        {**base, "bloque": mala_tx, "consenso": pow_, "cert": None},                         # 2 TX alterada
        {**base, "bloque": _rehash(bloque, difficulty=200), "consenso": pow_, "cert": None},  # 3 sin trabajo
        {**base, "bloque": bpbft, "consenso": consenso, "cert": cert(2)},                    # 4 2 firmas
        {**base, "bloque": bpbft, "consenso": consenso, "cert": cert_repetido},              # 5 repetido
        {**base, "id": "0" * 32, "bloque": bloque, "consenso": pow_, "cert": None},          # 6 otro ID
    ])
    # El hash del bloque en JS (ensure_ascii=False) coincide con Python en un bloque real.
    assert salida[0]["hash"] == bloque["hash"] and salida[1]["hash"] == bpbft["hash"]
    assert _fallos(salida[0]) == [] and len(salida[0]["checks"]) == 7
    assert _fallos(salida[1]) == []
    assert any(c["ok"] is None and "no aplica" in c["texto"] for c in salida[1]["checks"])
    assert not any("dificultad" in c["texto"] for c in salida[1]["checks"])
    assert _fallos(salida[2])
    assert any("dificultad" in t for t in _fallos(salida[3]))
    assert any("Certificado PBFT" in t for t in _fallos(salida[4]))
    assert any("Certificado PBFT" in t for t in _fallos(salida[5]))
    assert any("ID de la credencial" in t for t in _fallos(salida[6]))
