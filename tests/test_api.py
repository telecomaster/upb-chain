"""
Tests de integración de la API REST de UPB-Chain.

Usa httpx.AsyncClient con ASGITransport para invocar la aplicación FastAPI
directamente sin levantar un servidor HTTP real.

NOTA: NODE_PORT=0 fuerza al nodo P2P a solicitar un puerto efímero al SO,
evitando conflictos en entornos de CI con múltiples procesos pytest.
El valor debe establecerse ANTES de importar api.app porque el `app` de módulo (create_app())
se construye una sola vez en la importación.
"""
import os
import time

os.environ.setdefault("NODE_PORT", "0")   # puerto P2P aleatorio → sin conflictos

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from api.app import app

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Fixture del cliente HTTP
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def client():
    """Cliente asíncrono conectado al ASGI de la app (lifespan incluido)."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac


# ---------------------------------------------------------------------------
# Health & Stats
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_health_returns_200_and_ok(client):
    """GET /health retorna 200 con status='ok'."""
    response = await client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"


@pytest.mark.asyncio
async def test_get_stats_returns_correct_structure(client):
    """GET /stats retorna las claves 'chain', 'network' y 'mining'."""
    response = await client.get("/stats")
    assert response.status_code == 200
    body = response.json()
    assert "chain" in body, "Falta clave 'chain' en /stats"
    assert "network" in body, "Falta clave 'network' en /stats"
    assert "mining" in body, "Falta clave 'mining' en /stats"


# ---------------------------------------------------------------------------
# Bloques
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_blocks_returns_paginated_list_with_total(client):
    """GET /blocks retorna lista paginada con campo 'total'."""
    response = await client.get("/blocks")
    assert response.status_code == 200
    body = response.json()
    assert "blocks" in body
    assert "total" in body
    assert isinstance(body["blocks"], list)
    assert body["total"] >= 1  # al menos el bloque génesis


@pytest.mark.asyncio
async def test_get_genesis_block_has_index_zero(client):
    """GET /blocks/0 retorna el bloque génesis con header.index == 0."""
    response = await client.get("/blocks/0")
    assert response.status_code == 200
    body = response.json()
    assert "header" in body
    assert body["header"]["index"] == 0


# ---------------------------------------------------------------------------
# Wallet
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_post_wallet_generate_returns_address_pub_priv(client):
    """POST /wallet/generate retorna 'address', 'public_key' y 'private_key'."""
    response = await client.post("/wallet/generate")
    assert response.status_code == 200
    body = response.json()
    assert "address" in body
    assert "public_key" in body
    assert "private_key" in body
    assert body["address"].startswith("UPB"), (
        f"Dirección no tiene prefijo UPB: {body['address']}"
    )


# ---------------------------------------------------------------------------
# Transacciones
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_post_transaction_valid_returns_tx_id_and_pending(client):
    """POST /transactions con TX válida retorna 'tx_id' y 'status: pending'."""
    wallet_resp = await client.post("/wallet/generate")
    wallet = wallet_resp.json()

    payload = {
        "type": "DATA_RECORD",
        "sender": wallet["address"],
        "recipient": "UPB_INTEGRATION_DEST",
        "payload": {"data": f"integration_test_{time.time_ns()}"},
        "fee": 0,
        "private_key_hex": wallet["private_key"],
    }
    response = await client.post("/transactions", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert "tx_id" in body, "Falta 'tx_id' en la respuesta"
    assert body["status"] == "pending"


@pytest.mark.asyncio
async def test_post_transaction_invalid_type_returns_error(client):
    """POST /transactions con tipo inválido retorna código de error >= 400."""
    payload = {
        "type": "TIPO_INVALIDO_XYZ_99",
        "sender": "UPBsomesender",
        "recipient": "UPBsomerecp",
        "payload": {"data": "test"},
    }
    response = await client.post("/transactions", json=payload)
    # ValueError en el handler → 500; validación Pydantic → 422
    # En cualquier caso el intento debe ser rechazado
    assert response.status_code >= 400, (
        f"Se esperaba un error (>=400), se obtuvo {response.status_code}"
    )


@pytest.mark.asyncio
async def test_get_pending_transactions_returns_list(client):
    """GET /transactions/pending retorna lista (puede estar vacía)."""
    response = await client.get("/transactions/pending")
    assert response.status_code == 200
    body = response.json()
    assert "transactions" in body
    assert isinstance(body["transactions"], list)


# ---------------------------------------------------------------------------
# Credenciales — Flujo completo
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_verify_nonexistent_credential_returns_valid_false(client):
    """GET /credentials/verify/<id_inexistente> retorna valid=false."""
    response = await client.get("/credentials/verify/no_existe_este_id_abc123xyz")
    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is False


# El flujo completo (registrar → emitir → PENDING → minar → VÁLIDA → reiniciar →
# revocar → REVOCADA) está en tests/test_credentials_chain.py (P0-6), sobre una
# cadena en tmp_path y con una autoridad controlada por el test.


# ---------------------------------------------------------------------------
# IA / Analytics
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_ai_analytics_returns_chain_height_and_tps(client):
    """GET /ai/analytics retorna estructura con 'chain_height' y 'throughput_tps'."""
    response = await client.get("/ai/analytics")
    assert response.status_code == 200
    body = response.json()
    assert "chain_height" in body, "Falta 'chain_height' en /ai/analytics"
    assert "throughput_tps" in body, "Falta 'throughput_tps' en /ai/analytics"


# ---------------------------------------------------------------------------
# Seguridad
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_security_threat_summary_returns_threat_level(client):
    """GET /security/threat-summary retorna 'threat_level'."""
    response = await client.get("/security/threat-summary")
    assert response.status_code == 200
    body = response.json()
    assert "threat_level" in body, "Falta 'threat_level' en /security/threat-summary"


@pytest.mark.asyncio
async def test_get_security_attack_simulation_returns_results(client):
    """GET /security/attack-simulation retorna resultados de los ataques simulados."""
    response = await client.get("/security/attack-simulation")
    assert response.status_code == 200
    body = response.json()
    assert "51_percent" in body, "Falta resultado del ataque 51% en simulación"
    assert "sybil_no_mitigation" in body, "Falta resultado Sybil en simulación"
    assert "double_spend_6conf" in body, "Falta resultado Double-Spend en simulación"


# ---------------------------------------------------------------------------
# P0-2: autenticación de transacciones (firma + llave pública)
# ---------------------------------------------------------------------------

def _signed_tx(wallet, sender=None, **kw):
    from blockchain.core.transaction import Transaction, TransactionType
    tx = Transaction(
        type=TransactionType.DATA_RECORD,
        sender=sender or wallet.address,
        recipient="UPB_AUTH_DEST",
        payload={"data": f"auth_{time.time_ns()}"},
        **{"nonce": 1, **kw},
    )
    tx.sign(wallet.private_key_hex)
    return tx


def _post_body(tx):
    return {
        "type": tx.type.value, "sender": tx.sender, "recipient": tx.recipient,
        "payload": tx.payload, "fee": tx.fee, "nonce": tx.nonce, "timestamp": tx.timestamp,
        "signature": tx.signature, "public_key": tx.public_key,
    }


@pytest.mark.asyncio
async def test_post_transaction_client_signed_accepted(client):
    from blockchain.core.wallet import Wallet
    tx = _signed_tx(Wallet.generate())
    r = await client.post("/transactions", json=_post_body(tx))
    assert r.status_code == 200, r.text
    assert r.json()["tx_id"] == tx.tx_id


@pytest.mark.asyncio
async def test_post_transaction_unsigned_rejected(client):
    from blockchain.core.wallet import Wallet
    w = Wallet.generate()
    r = await client.post("/transactions", json={
        "type": "DATA_RECORD", "sender": w.address, "recipient": "X",
        "payload": {"data": f"unsigned_{time.time_ns()}"},
    })
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_post_transaction_system_sender_rejected(client):
    r = await client.post("/transactions", json={
        "type": "TOKEN_TRANSFER", "sender": "SYSTEM", "recipient": "X",
        "payload": {"amount": 1000},
    })
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_post_transaction_forged_sender_rejected(client):
    """Firmada con la llave de A pero declarando el sender B."""
    from blockchain.core.wallet import Wallet
    a, b = Wallet.generate(), Wallet.generate()
    r = await client.post("/transactions", json={
        "type": "DATA_RECORD", "sender": b.address, "recipient": "X",
        "payload": {"data": f"forged_{time.time_ns()}"},
        "private_key_hex": a.private_key_hex,
    })
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_post_transaction_tampered_fee_or_amount_rejected(client):
    from blockchain.core.wallet import Wallet
    tx = _signed_tx(Wallet.generate())
    body = _post_body(tx)
    r = await client.post("/transactions", json={**body, "fee": 99})
    assert r.status_code == 400
    r = await client.post("/transactions", json={**body, "nonce": 2})
    assert r.status_code == 400
    r = await client.post("/transactions", json={**body, "payload": {**tx.payload, "amount": 5}})
    assert r.status_code == 400
