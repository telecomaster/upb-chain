"""Tests de P1-12 (panel del emisor): EVENT_CODE_CREATE firmada en el navegador.

- La TX que arma ``kinds.eventCreate`` en JS tiene el mismo tx_id/payload que Python, la firma
  la verifica Python y el contrato la acepta (node real; se omite sin node).
- Camino por la API: crear con TX firmada en JS -> minar -> reclamar por el camino existente.
- Las rutas y los ids del DOM del panel los cubre test_frontend_contrato.py.
"""
import json
import time
import subprocess
from pathlib import Path

import pytest

from blockchain.core.transaction import Transaction, create_event_code_transaction
from tests.test_billetera import (DIR, NODE, PRIV_DER, PRIV_RAW, necesita_node)
from tests.test_eventos_qr import (_der, _emisor, _enviar, _minar, _ok, _reclamo, client, nodo)  # noqa: F401

RAIZ = Path(__file__).resolve().parent.parent
TS = 1700000010


def _evento_js(priv=PRIV_RAW, nonce=1, codigo="EV-ñ1", expires=500, ts=TS):
    arg = json.dumps({"priv": priv, "codeId": codigo, "amount": 7, "maxClaims": 3, "expires": expires,
                      "reason": "Feria ñandú", "nonce": nonce, "timestamp": ts})
    r = subprocess.run([NODE, str(RAIZ / "tests" / "js" / "event_create_check.mjs")],
                       input=arg.encode("utf-8"), capture_output=True, timeout=60, cwd=RAIZ)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")
    return json.loads(r.stdout.decode("utf-8"))


@necesita_node
def test_js_eventcreate_coincide_con_python_y_la_firma_es_valida():
    js = _evento_js()
    tx_js = js["tx"]
    py = create_event_code_transaction(DIR, "EV-ñ1", js["evento"]["pub"], 7, 3, 500, "Feria ñandú",
                                       PRIV_DER, nonce=1)
    py = Transaction.from_dict({**py.to_dict(), "timestamp": TS})
    py.tx_id = py._compute_id()
    assert tx_js["tx_id"] == py.tx_id
    assert (tx_js["type"], tx_js["recipient"], tx_js["payload"]) == (py.type, py.recipient, py.payload)
    assert Transaction.from_dict(tx_js).is_consensus_valid() == (True, "OK")
    assert js["der"] == PRIV_DER                       # privateKeyDer == formato de wallet.py


@necesita_node
@pytest.mark.integration
@pytest.mark.asyncio
async def test_api_crear_con_tx_firmada_en_js_y_reclamar(client, nodo):  # noqa: F811
    await _emisor(client, nodo)
    from cryptography.hazmat.primitives import serialization
    emisor_raw = f"{serialization.load_der_private_key(bytes.fromhex(nodo.emisor.private_key_hex), password=None).private_numbers().private_value:064x}"
    nonce = (await _ok(await client.get(f"/accounts/{nodo.emisor.address}")))["next_nonce"]
    altura = (await _ok(await client.get("/catalog")))["height"]
    js = _evento_js(priv=emisor_raw, nonce=nonce, codigo="EV-js01", expires=altura + 100, ts=time.time())
    tx = js["tx"]
    assert tx["sender"] == nodo.emisor.address
    await _ok(await client.post("/transactions", json=tx))
    await _minar(client)
    estado = await _ok(await client.get("/tokens/event-codes/EV-js01"))
    assert (estado["status"], estado["claims_left"], estado["amount"]) == ("OPEN", 3, 7)
    # El reclamo usa el camino existente con la llave efímera generada "en el navegador".
    codigo = {"code_id": "EV-js01", "event_private_key": js["evento"]["priv"]}
    await _ok(await _enviar(client, _reclamo(nodo, codigo, nodo.ana)))
    await _minar(client)
    assert (await _ok(await client.get(f"/tokens/{nodo.ana.address}")))["balance"] == 7
    assert (await _ok(await client.get("/tokens/event-codes/EV-js01")))["claims_used"] == 1


def test_billetera_sirve_el_panel_y_el_qr_vendido(tmp_path):
    html = (RAIZ / "dashboard" / "templates" / "billetera.html").read_text(encoding="utf-8")
    for ident in ("sec-emisor", "btn-ev-crear", "ev-qr", "btn-ev-imprimir", "btn-ev-crear"):
        assert f'id="{ident}"' in html
    assert (RAIZ / "dashboard/static/vendor/qrcode-generator.esm.js").is_file()
    assert (RAIZ / "dashboard/static/vendor/LICENSE-qrcode-generator.txt").is_file()


def test_panel_de_recompensas_del_laboratorio_esta_en_el_dashboard():
    html = (RAIZ / "dashboard" / "templates" / "index.html").read_text(encoding="utf-8")
    assert 'id="lab-recibo"' in html and "_postIssuer('/laboratorio/recompensas'" in html
