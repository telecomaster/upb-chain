"""
Tests de integración de la API REST de UPB-Chain.

Usa httpx.AsyncClient con ASGITransport para invocar la aplicación FastAPI
directamente sin levantar un servidor HTTP real.

NOTA: NODE_PORT=0 fuerza al nodo P2P a solicitar un puerto efímero al SO,
evitando conflictos en entornos de CI con múltiples procesos pytest.
El valor debe establecerse ANTES de importar api.app porque las variables
globales de módulo se evalúan una sola vez en la importación.
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
        "fee": 0.0,
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


@pytest.mark.asyncio
async def test_full_credential_flow(client):
    """Flujo completo: generar wallet → registrar emisor → emitir credencial → verificar."""
    # 1. Generar wallet emisora
    issuer_resp = await client.post("/wallet/generate")
    assert issuer_resp.status_code == 200
    issuer = issuer_resp.json()

    # 2. Generar wallet de estudiante
    student_resp = await client.post("/wallet/generate")
    assert student_resp.status_code == 200
    student = student_resp.json()

    # 3. Registrar emisor UPB
    reg_resp = await client.post(
        "/credentials/issuers",
        json={"issuer_address": issuer["address"], "institution_code": "UPB"},
    )
    assert reg_resp.status_code == 200, f"Registro de emisor falló: {reg_resp.text}"

    # 4. Emitir credencial (campos requeridos por el contrato Y por create_credential_transaction)
    unique_degree = f"Licenciatura_IA_{time.time_ns()}"
    issue_resp = await client.post(
        "/credentials/issue",
        json={
            "issuer_address": issuer["address"],
            "student_address": student["address"],
            "private_key_hex": issuer["private_key"],
            "credential_data": {
                # Requeridos por CredentialContract.issue_credential
                "student_name": "Carlos Mamani Quispe",
                "program": "Ingeniería en Inteligencia Artificial",
                "degree": unique_degree,
                "issue_date": "2025-06-10",
                "credential_type": "DEGREE",
                # Requeridos por create_credential_transaction
                "institution": "Universidad Privada Boliviana",
                "date": "2025-06-10",
                "grade": 91.0,
            },
        },
    )
    assert issue_resp.status_code == 200, f"Emisión falló: {issue_resp.text}"
    issue_body = issue_resp.json()
    assert "credential_id" in issue_body
    assert "tx_id" in issue_body
    credential_id = issue_body["credential_id"]

    # 5. Verificar que la credencial es válida
    verify_resp = await client.get(f"/credentials/verify/{credential_id}")
    assert verify_resp.status_code == 200
    verify_body = verify_resp.json()
    assert verify_body["valid"] is True, (
        f"Credencial debería ser válida, razón: {verify_body.get('reason')}"
    )


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
