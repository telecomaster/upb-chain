"""Tests de P1-3: verificación pública por QR (PNG y página /verify/{id})."""
from types import SimpleNamespace

import pytest

from api.app import _url_verificacion
from blockchain.core.wallet import Wallet
from tests.test_credentials_chain import (  # noqa: F401  (fixtures y ayudantes)
    _datos, _emitir, _minar_api, _registrar, _revocar, client, nodo,
)

pytestmark = pytest.mark.integration


async def _emitida(client, **extra):
    emisor, estudiante = Wallet.generate(), Wallet.generate()
    await _registrar(client, emisor)
    r = await _emitir(client, emisor, estudiante, _datos(**extra))
    assert r.status_code == 200, r.text
    return emisor, r.json()["credential_id"]


@pytest.mark.asyncio
async def test_pagina_pendiente_valida_y_revocada(client):
    emisor, cid = await _emitida(client)
    assert "PENDIENTE" in (await client.get(f"/verify/{cid}")).text
    await _minar_api(client)
    r = await client.get(f"/verify/{cid}")
    assert r.status_code == 200 and "VÁLIDA" in r.text and emisor.address in r.text
    assert "Confirmaciones" in r.text
    await _revocar(client, emisor, cid)
    await _minar_api(client)
    assert "REVOCADA" in (await client.get(f"/verify/{cid}")).text


@pytest.mark.asyncio
async def test_pagina_no_expone_notas_ni_nombre(client):
    _, cid = await _emitida(client, grade=87.25)  # con punto: no aparece por azar en ids hex
    await _minar_api(client)
    t = (await client.get(f"/verify/{cid}")).text
    assert "Carla Rojas" not in t and "87.25" not in t


@pytest.mark.asyncio
async def test_desconocido_404(client):
    r = await client.get("/verify/" + "0" * 32)
    assert r.status_code == 404 and "NO ENCONTRADA" in r.text
    assert (await client.get("/credentials/" + "0" * 32 + "/qr")).status_code == 404


@pytest.mark.asyncio
async def test_qr_png_con_url_publica(client, nodo):
    _, cid = await _emitida(client)
    r = await client.get(f"/credentials/{cid}/qr")
    assert r.status_code == 200 and r.headers["content-type"] == "image/png"
    assert r.content.startswith(b"\x89PNG")
    # La URL embebida usa PUBLIC_BASE_URL si está definida, si no la del request.
    req = SimpleNamespace(base_url="http://test/")
    nodo.node.settings = nodo.node.settings.model_copy(update={"public_base_url": ""})
    assert _url_verificacion(nodo.node, req, cid) == f"http://test/verify/{cid}"
    nodo.node.settings = nodo.node.settings.model_copy(update={"public_base_url": "https://upb.example/"})
    assert _url_verificacion(nodo.node, req, cid) == f"https://upb.example/verify/{cid}"


@pytest.mark.asyncio
async def test_html_se_escapa(client):
    _, cid = await _emitida(client, degree="<script>alert(1)</script>")
    await _minar_api(client)
    t = (await client.get(f"/verify/{cid}")).text
    assert "<script>alert(1)</script>" not in t
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in t
