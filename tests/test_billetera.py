"""Tests de P2-1: billetera web con firma en el navegador.

La firma JS (@noble/secp256k1) debe producir exactamente el mismo tx_id, mensaje, llave pública y
dirección que Python, y una firma que el verificador de Python acepte. Si hay ``node``, el JS real
se ejecuta; si no, esos tests se omiten.
"""
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("NODE_PORT", "0")

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from httpx import ASGITransport, AsyncClient

from blockchain.core.transaction import (
    Transaction,
    create_data_record_transaction,
    create_redeem_transaction,
    create_transfer_transaction,
    create_vote_transaction,
)
from blockchain.core.wallet import Wallet, derive_address, public_key_from_private
from tests.helpers import make_app

RAIZ = Path(__file__).resolve().parent.parent
VENDOR = RAIZ / "dashboard" / "static" / "vendor"
PRIV_RAW = "00" * 31 + "2a"      # llave fija de prueba (42)
NODE = shutil.which("node")
necesita_node = pytest.mark.skipif(NODE is None, reason="node no está instalado")


def _priv_der_hex(raw_hex: str) -> str:
    key = ec.derive_private_key(int(raw_hex, 16), ec.SECP256K1())
    return key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption()).hex()


PRIV_DER = _priv_der_hex(PRIV_RAW)
PUB = public_key_from_private(PRIV_DER)
DIR = derive_address(PUB)
OTRO = "UPB" + "A" * 32

CASOS = [
    {"kind": "transfer", "args": [OTRO, 5], "nonce": 1, "fee": 1, "timestamp": 1700000000.123},
    {"kind": "redeem", "args": [OTRO, 3, "Impresión ñandú"], "nonce": 2, "fee": 0, "timestamp": 1700000001},
    {"kind": "vote", "args": ["elec-1", "Sí \"quizá\"\n"], "nonce": 3, "fee": 0, "timestamp": 1700000002.5},
    {"kind": "data", "args": [OTRO, {"dato": "café ☕", "n": 7}], "nonce": 4, "fee": 0,
     "timestamp": 1700000003.000001},
]


def _python_tx(c) -> Transaction:
    k, a = c["kind"], c["args"]
    if k == "transfer":
        tx = create_transfer_transaction(DIR, a[0], a[1], PRIV_DER, nonce=c["nonce"], fee=c["fee"])
    elif k == "redeem":
        tx = create_redeem_transaction(DIR, a[0], a[1], PRIV_DER, nonce=c["nonce"], item=a[2])
    elif k == "vote":
        tx = create_vote_transaction(DIR, a[0], a[1], PRIV_DER, nonce=c["nonce"])
    else:
        tx = create_data_record_transaction(DIR, a[0], a[1], PRIV_DER, nonce=c["nonce"])
    return tx


def _firmar_en_js():
    arg = json.dumps({"priv": PRIV_RAW, "casos": CASOS})
    r = subprocess.run([NODE, str(RAIZ / "tests" / "js" / "cross_check.mjs")], input=arg.encode("utf-8"),
                       capture_output=True, timeout=60, cwd=RAIZ)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")
    return json.loads(r.stdout.decode("utf-8"))


@pytest.fixture(scope="module")
def txs_js():
    return _firmar_en_js()


@necesita_node
def test_js_misma_llave_publica_y_direccion(txs_js):
    for t in txs_js:
        assert t["public_key"] == PUB
        assert t["sender"] == DIR


@necesita_node
@pytest.mark.parametrize("i", range(len(CASOS)))
def test_js_mismo_tx_id_y_mensaje_firmado(txs_js, i):
    """Para los mismos campos, tx_id y mensaje firmado coinciden byte a byte con Python."""
    c = CASOS[i]
    js = txs_js[i]
    if c["kind"] in ("transfer", "redeem", "vote", "data"):
        py = _python_tx({**c, "timestamp": c["timestamp"]})
    # Python fija timestamp en la construcción: se reconstruye con el de JS para comparar.
    py_tx = Transaction.from_dict({**py.to_dict(), "timestamp": c["timestamp"]})
    py_tx.tx_id = py_tx._compute_id()
    assert js["payload"] == py.payload
    assert js["tx_id"] == py_tx.tx_id
    py_tx.public_key = js["public_key"]
    assert py_tx._get_signing_message() == Transaction.from_dict(js)._get_signing_message()


@necesita_node
@pytest.mark.parametrize("i", range(len(CASOS)))
def test_firma_js_la_acepta_el_verificador_de_python(txs_js, i):
    tx = Transaction.from_dict(txs_js[i])
    ok, motivo = tx.is_consensus_valid()
    assert ok, motivo
    # Una alteración cualquiera invalida la firma.
    mala = dict(txs_js[i])
    mala["payload"] = {**mala["payload"], "x": 1}
    assert not Transaction.from_dict(mala).is_consensus_valid()[0]


@necesita_node
def test_js_firma_del_reclamo_de_evento_la_verifica_python_y_el_tx_coincide():
    """P1-12: la firma JS del evento pasa ``claim_award`` (verify_signature) y la TX coincide con Python."""
    from blockchain.contracts.tokens import claim_message
    from blockchain.core.block import GENESIS_HASH
    from security.crypto_utils import verify_signature
    evento_priv = "00" * 31 + "07"
    evento_pub = public_key_from_private(_priv_der_hex(evento_priv))
    arg = json.dumps({"priv": evento_priv, "genesis": GENESIS_HASH, "codeId": "EV-ñ1", "address": DIR})
    r = subprocess.run([NODE, str(RAIZ / "tests" / "js" / "event_claim_check.mjs")], input=arg.encode("utf-8"),
                       capture_output=True, timeout=60, cwd=RAIZ)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")
    sig = json.loads(r.stdout.decode("utf-8"))["sig"]
    assert verify_signature(claim_message("EV-ñ1", DIR), sig, evento_pub)
    assert not verify_signature(claim_message("EV-ñ1", OTRO), sig, evento_pub)   # ligada a la dirección
    # La TX EVENT_CODE_CLAIM de la billetera tiene el mismo payload, tx_id y mensaje firmado que Python.
    caso = {"kind": "eventClaim", "args": ["EV-ñ1", sig], "nonce": 5, "fee": 0, "timestamp": 1700000009}
    arg = json.dumps({"priv": PRIV_RAW, "casos": [caso]})
    r = subprocess.run([NODE, str(RAIZ / "tests" / "js" / "cross_check.mjs")], input=arg.encode("utf-8"),
                       capture_output=True, timeout=60, cwd=RAIZ)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")
    js = json.loads(r.stdout.decode("utf-8"))[0]
    from blockchain.core.transaction import create_event_claim_transaction
    py = create_event_claim_transaction(DIR, "EV-ñ1", sig, PRIV_DER, nonce=5)
    py = Transaction.from_dict({**py.to_dict(), "timestamp": 1700000009})
    py.tx_id = py._compute_id()
    assert js["payload"] == py.payload and js["recipient"] == py.recipient and js["type"] == py.type
    assert js["tx_id"] == py.tx_id
    assert Transaction.from_dict(js).is_consensus_valid() == (True, "OK")


def test_firma_python_con_mismo_formato_que_noble_se_verifica():
    """Sin node: una firma ECDSA/SHA-256 en DER con S bajo (como emite noble) pasa el verificador."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature, encode_dss_signature)
    import base64
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    tx = Transaction.from_dict(_python_tx(CASOS[0]).to_dict())
    key = ec.derive_private_key(int(PRIV_RAW, 16), ec.SECP256K1())
    r, s = decode_dss_signature(key.sign(tx._get_signing_message().encode(), ec.ECDSA(hashes.SHA256())))
    if s > n // 2:
        s = n - s
    tx.signature = base64.b64encode(encode_dss_signature(r, s)).decode()
    assert tx.is_consensus_valid() == (True, "OK")


# ── Archivos estáticos y página ───────────────────────────────────────────────

def test_hash_de_la_libreria_vendida_coincide_con_el_readme():
    lib = VENDOR / "noble-secp256k1.bundle.js"
    h = hashlib.sha256(lib.read_bytes()).hexdigest()
    readme = (VENDOR / "README.md").read_text(encoding="utf-8")
    assert h in readme
    assert "2.2.3" in readme
    assert (VENDOR / "LICENSE-noble-secp256k1.txt").exists()


@pytest_asyncio.fixture
async def client(tmp_path):
    app = make_app(tmp_path, autoridad=Wallet.generate(), mining_difficulty=1)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://127.0.0.1") as ac:
        yield SimpleNamespace(http=ac, app=app)


@pytest.mark.asyncio
async def test_billetera_servida_y_estaticos(client):
    r = await client.http.get("/billetera")
    assert r.status_code == 200
    assert "Billetera" in r.text and "/static/billetera.js" in r.text
    assert "<script>" not in r.text          # sin JS en línea
    for ruta in ("/static/billetera.js", "/static/wallet-core.js",
                 "/static/vendor/noble-secp256k1.bundle.js"):
        assert (await client.http.get(ruta)).status_code == 200, ruta


@necesita_node
@pytest.mark.asyncio
async def test_tx_firmada_en_js_es_aceptada_por_la_api(client, txs_js):
    """La TX de la billetera (data record, sin saldo) entra al mempool vía POST /transactions."""
    tx = dict(txs_js[3])
    tx["timestamp"] = __import__("time").time()
    # Firmar de nuevo con timestamp actual (la API rechaza TX expiradas): usa el nodo.
    arg = json.dumps({"priv": PRIV_RAW, "casos": [{**CASOS[3], "timestamp": tx["timestamp"],
                                                   "nonce": 1}]})
    out = subprocess.run([NODE, str(RAIZ / "tests" / "js" / "cross_check.mjs")], input=arg.encode("utf-8"),
                         capture_output=True, timeout=60, cwd=RAIZ)
    assert out.returncode == 0, out.stderr
    firmada = json.loads(out.stdout.decode("utf-8"))[0]
    cuenta = (await client.http.get(f"/accounts/{DIR}")).json()
    assert cuenta["next_nonce"] == 1
    r = await client.http.post("/transactions", json=firmada)
    assert r.status_code == 200, r.text
    assert r.json()["tx_id"] == firmada["tx_id"]
    assert (await client.http.get(f"/accounts/{DIR}")).json()["next_nonce"] == 2
    # Firma corrupta: 400.
    firmada2 = {**firmada, "nonce": 2, "signature": firmada["signature"][:-6] + "AAAAAA"}
    assert (await client.http.post("/transactions", json=firmada2)).status_code == 400


@pytest.mark.asyncio
async def test_tx_firmada_con_timestamp_entero_es_aceptada(client):
    """Regresión: ``Date.now() / 1000`` es entero una vez cada 1000 ms. La API no debe convertir
    ese timestamp a float (``1700000000`` -> ``1700000000.0``): cambiaría el tx_id y la firma
    válida del navegador se rechazaría con "Firma inválida"."""
    import time
    w = Wallet.generate()
    tx = create_data_record_transaction(w.address, OTRO, {"dato": "x"}, w.private_key_hex, nonce=1)
    tx.timestamp = int(time.time())
    tx.tx_id = tx._compute_id()
    tx.sign(w.private_key_hex)
    cuerpo = tx.to_dict()
    assert isinstance(cuerpo["timestamp"], int)
    r = await client.http.post("/transactions", json=cuerpo)
    assert r.status_code == 200, r.text
    assert r.json()["tx_id"] == tx.tx_id
    # Un timestamp no numérico sigue rechazándose.
    for malo in ("1700000000", True):
        r = await client.http.post("/transactions", json={**cuerpo, "nonce": 2, "timestamp": malo})
        assert r.status_code in (400, 422), (malo, r.text)
