"""
API REST de UPB-Chain — FastAPI.
Expone endpoints para bloques, transacciones, credenciales, análisis y seguridad.
"""
import asyncio
import hmac
import html
import io
import json
import logging
import os
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field

from config import load_settings, configure_logging
from blockchain.core.chain import Blockchain
from blockchain.core.merkle import build_proof, leaf_hash
from blockchain.core.transaction import (
    Transaction,
    TransactionType,
    create_credential_transaction,
    create_issuer_register_transaction,
    create_mint_transaction,
    create_revoke_transaction,
    create_transfer_transaction,
)
from blockchain.core.wallet import Wallet, derive_address, public_key_from_private
from blockchain.consensus.proof_of_work import ProofOfWork
from blockchain.consensus.pbft import PBFTNode
from blockchain.contracts.credential import CredentialState, credential_id_of_tx
from blockchain.network.node import P2PNode
from ai.anomaly.detector import TransactionAnomalyDetector, BlockAnomalyDetector
from ai.analytics.chain_stats import ChainAnalytics
from security.monitor import SecurityMonitor
from security.rate_limiter import TxRateLimiter
from security.attacks.simulator import full_security_analysis
from security.attacks.eclipse import EclipseAttack
from security.hardening import HardeningAuditor
from security.crypto_utils import generate_keypair, benchmark_crypto

settings = load_settings()
configure_logging(settings.log_level)
logger = logging.getLogger("upb_chain.api")

# ── Estado global de la aplicación ───────────────────────────────────────────

NODE_ID    = settings.node_id
NODE_HOST  = settings.node_host
NODE_PORT  = settings.node_port
API_PORT   = settings.api_port
PEERS      = settings.peers

def build_node_state(data_dir: str, node_id: str, authority_address: Optional[str] = None,
                     initial_difficulty: int = 4) -> Blockchain:
    """Carga la cadena con sus contratos (P1-13): cuentas, credenciales y votación.

    El estado de cada contrato se deriva reproduciendo la cadena al arrancar y
    se actualiza con cada bloque o reemplazo de cadena; la API lo lee con
    ``blockchain.contract_state(nombre)``. ``authority_address`` (por defecto la
    del génesis) es la única que firma TOKEN_MINT e ISSUER_REGISTER.
    """
    return Blockchain(node_id=node_id, data_dir=data_dir,
                      initial_difficulty=initial_difficulty,
                      authority_address=authority_address)


def load_authority_wallet(path: str, expected_address: str) -> Optional[Wallet]:
    """Carga la llave de la autoridad desde un archivo local (nunca versionado).

    Devuelve None si el archivo no existe o si la llave no corresponde a la
    dirección de autoridad del génesis (este nodo no podrá registrar emisores).
    """
    if not Path(path).exists():
        return None
    try:
        wallet = Wallet.load(path)
        public_key = public_key_from_private(wallet.private_key_hex)
        address = derive_address(public_key)
    except Exception:
        logger.warning(f"Llave de autoridad ilegible en {path}")
        return None
    if address != expected_address:
        logger.warning(f"La llave en {path} no es la autoridad del génesis; se ignora")
        return None
    return Wallet(private_key_hex=wallet.private_key_hex, public_key_hex=public_key,
                  address=address)


blockchain = build_node_state(
    settings.data_dir, NODE_ID, initial_difficulty=settings.mining_difficulty)
authority_wallet = load_authority_wallet(
    settings.authority_key_file, blockchain.contracts.contract("accounts").authority_address)
# La dificultad NO vive aquí: la dicta Blockchain._calculate_difficulty() (P0-4).
pow_engine      = ProofOfWork()
mining_lock     = asyncio.Lock()        # un solo minado a la vez (409 si ya hay uno)
mining_stop     = threading.Event()     # se activa al apagar el nodo para abortar el PoW
tx_anomaly_detector = TransactionAnomalyDetector()
anomaly_model_path = Path(settings.data_dir) / "models" / "tx_iforest.joblib"
if tx_anomaly_detector.load(anomaly_model_path):
    logger.info("Modelo de anomalías cargado de %s", anomaly_model_path)
block_anomaly_detector = BlockAnomalyDetector()
chain_analytics = ChainAnalytics()
security_monitor = SecurityMonitor()
security_monitor.TX_RATE_LIMIT = settings.tx_rate_limit
# P1-5: límite de admisión al mempool (política local, nunca regla de consenso).
tx_rate_limiter = TxRateLimiter(limit=settings.tx_rate_limit, window=security_monitor.TX_RATE_WINDOW)


def _screen_admitted_tx(tx: Transaction, report=None) -> None:
    """Tras admitir una TX: la registra en el contexto del detector y alerta si fue marcada (P1-6)."""
    if report is None:
        report = tx_anomaly_detector.predict(tx.to_dict())
    tx_anomaly_detector.observe(tx.to_dict())
    if report.is_anomaly:
        security_monitor.on_anomalous_transaction(tx.to_dict(), report.to_dict())


def _enforce_tx_rate_limit(sender: str) -> None:
    """429 (y alerta) si el emisor superó el límite de TX por minuto."""
    allowed, count = tx_rate_limiter.check(sender)
    if not allowed:
        security_monitor.on_tx_rate_limited(sender, count, tx_rate_limiter.limit)
        raise HTTPException(429, f"Límite de {tx_rate_limiter.limit} TX por minuto excedido")


def _on_chain_reorg(fork_height: int, dropped: list, added: list) -> None:
    """Reorganización → alerta (profundidad = bloques propios descartados) y bloques nuevos."""
    security_monitor.on_chain_reorg(len(dropped))
    for block in added:
        security_monitor.on_block(block.to_dict())


blockchain.add_reorg_listener(_on_chain_reorg)

pbft_peers = [NODE_ID] + [f"node_{i}" for i in range(2, 5)]
pbft_node = PBFTNode(
    node_id=NODE_ID,
    peers=pbft_peers,
    is_primary=(NODE_ID == "node_1"),
)

p2p = P2PNode(
    node_id=NODE_ID,
    host=NODE_HOST,
    port=NODE_PORT,
    advertise_host=settings.node_advertise_host or None,
    # P0-5: el nodo valida/añade bloques y TXs recibidos y, si un bloque no
    # extiende la punta, sincroniza con el emisor (replace_chain por trabajo).
    blockchain=blockchain,
    on_pbft_message=lambda m: logger.info(f"PBFT msg recibido: {m}"),
    # P1-5: bloques recibidos y aceptados, bloques inválidos y pares fuera de PEERS.
    on_new_block=security_monitor.on_block,
    on_invalid_block=security_monitor.on_invalid_block,
    on_unknown_peer=security_monitor.on_unknown_peer,
    known_peers=PEERS,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    p2p.start()
    # Los pares de PEERS se conectan (y reconectan con backoff) en segundo plano.
    for peer in PEERS:
        if ":" in peer:
            host, port = peer.rsplit(":", 1)
            p2p.add_peer(host, int(port))
    logger.info(f"UPB-Chain nodo {NODE_ID} iniciado")
    yield
    mining_stop.set()
    p2p.stop()
    logger.info("Nodo detenido")


app = FastAPI(
    title="UPB-Chain API",
    description="Blockchain académica con IA para la Universidad Privada Boliviana",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS restringido (P1-9): por defecto solo el propio origen del nodo en localhost.
CORS_ORIGINS = settings.cors_origins or [
    f"http://localhost:{API_PORT}", f"http://127.0.0.1:{API_PORT}"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o for o in CORS_ORIGINS if o != "*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

_HOSTS_LOCALES = {"127.0.0.1", "::1", "localhost", "testclient"}


async def require_admin(request: Request) -> None:
    """Dependencia para endpoints de administración (P1-9).

    Con ``ADMIN_API_KEY`` definida exige la cabecera ``X-API-Key`` (401 si falta
    o es incorrecta). Sin llave solo admite peticiones desde loopback (403 si no).
    Uso: ``@app.post("/ruta", dependencies=[Depends(require_admin)])``.
    """
    clave = settings.admin_api_key
    if clave:
        recibida = request.headers.get("x-api-key", "")
        if not hmac.compare_digest(recibida.encode("utf-8"), clave.encode("utf-8")):
            raise HTTPException(401, "llave de administración ausente o incorrecta")
        return
    host = request.client.host if request.client else ""
    if host not in _HOSTS_LOCALES:
        raise HTTPException(403, "endpoint de administración: solo local o con ADMIN_API_KEY")

try:
    app.mount("/static", StaticFiles(directory="dashboard/static"), name="static")
except Exception:
    pass


# ── Modelos Pydantic ──────────────────────────────────────────────────────────

class TransactionRequest(BaseModel):
    type: str
    sender: str
    recipient: str
    payload: dict
    private_key_hex: Optional[str] = None
    fee: int = Field(0, ge=0)       # entero, unidad mínima (P0-9)
    # Nonce del sender (P0-9). Si el servidor firma (private_key_hex) y se omite,
    # usa el siguiente (GET /accounts/{address}); una TX firmada por el cliente
    # debe traerlo, porque forma parte del mensaje firmado.
    nonce: Optional[int] = Field(None, ge=0)
    # Alternativa a private_key_hex: TX firmada por el cliente.
    signature: Optional[str] = None
    public_key: Optional[str] = None
    timestamp: Optional[float] = None


class CredentialRequest(BaseModel):
    issuer_address: str
    student_address: str
    private_key_hex: str
    credential_data: dict


class MineRequest(BaseModel):
    miner_address: str = "SYSTEM"


class RegisterIssuerRequest(BaseModel):
    issuer_address: str
    institution_code: str


class RevokeRequest(BaseModel):
    credential_id: str
    revoker_address: str
    private_key_hex: str
    reason: str = ""


class MintRequest(BaseModel):
    recipient: str
    amount: int = Field(gt=0)       # entero, unidad mínima (P0-9)


class TransferRequest(BaseModel):
    sender: str
    recipient: str
    amount: int = Field(gt=0)
    private_key_hex: str
    fee: int = Field(0, ge=0)


class PruneMempoolRequest(BaseModel):
    max_age_seconds: int = 3600


# ── Endpoints: información general ───────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    try:
        with open("dashboard/templates/index.html", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "<h1>UPB-Chain API — <a href='/docs'>Documentación</a></h1>"


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "node_id": NODE_ID,
        "height": blockchain.height,
        "timestamp": time.time(),
    }


@app.get("/stats")
async def stats():
    chain_stats = blockchain.get_stats()
    network_stats = p2p.get_network_stats()
    pow_stats = {**pow_engine.get_mining_stats(),
                 "difficulty": blockchain._calculate_difficulty()}
    threat = security_monitor.get_threat_summary()
    return {
        "chain": chain_stats,
        "network": network_stats,
        "mining": pow_stats,
        "security": threat,
        "pbft": pbft_node.get_consensus_stats(),
    }


# ── Endpoints: bloques ────────────────────────────────────────────────────────

@app.get("/blocks")
async def get_blocks(page: int = 0, size: int = 10):
    start = page * size
    end = start + size
    blocks = blockchain.chain[start:end]
    return {
        "blocks": [b.to_dict() for b in blocks],
        "total": len(blockchain.chain),
        "page": page,
        "size": size,
    }


@app.get("/blocks/hash/{block_hash}")
async def get_block_by_hash(block_hash: str):
    """Retorna un bloque buscado por su hash SHA-256."""
    block = blockchain.get_block_by_hash(block_hash)
    if not block:
        raise HTTPException(404, f"Bloque con hash '{block_hash}' no encontrado")
    return block.to_dict()


@app.get("/blocks/{index}")
async def get_block(index: int):
    if index < 0 or index >= len(blockchain.chain):
        raise HTTPException(404, "Bloque no encontrado")
    block = blockchain.chain[index]
    report = block_anomaly_detector.peek_block(block.to_dict())   # lectura pura: no muta el detector
    return {**block.to_dict(), "anomaly": report.to_dict()}


@app.post("/blocks/mine", dependencies=[Depends(require_admin)])
async def mine_block(request: MineRequest, background_tasks: BackgroundTasks):
    if mining_lock.locked():
        raise HTTPException(409, "minado en curso")
    async with mining_lock:
        mining_stop.clear()
        candidate = blockchain.create_candidate_block()
        # La dificultad sale de la regla de la cadena, nunca de un valor fijo.
        difficulty = candidate.header.difficulty
        # El PoW corre en un thread para no bloquear el event loop.
        result = await asyncio.to_thread(
            pow_engine.mine, candidate, difficulty=difficulty, stop_event=mining_stop
        )
        if not result:
            raise HTTPException(500, "Mining falló, timeout o abortado")
        ok, reason = blockchain.add_block(result.block)
        if not ok:
            # Típico: llegó un bloque de un peer y la punta cambió durante el minado.
            security_monitor.on_invalid_block(reason, NODE_ID)
            raise HTTPException(409, f"Bloque minado ya no es válido: {reason}")
        security_monitor.on_block(result.block.to_dict())
    # Difusión a los pares (E/S de red bloqueante) fuera del event loop (P0-5).
    await asyncio.to_thread(p2p.broadcast_block, result.block.to_dict())
    return {
        "block": result.block.to_dict(),
        "mining_stats": {
            "nonce": result.nonce,
            "time_s": result.time_elapsed,
            "hash_rate": result.hash_rate,
            "attempts": result.attempts,
        },
    }


# ── Endpoints: transacciones ──────────────────────────────────────────────────

@app.get("/transactions/pending")
async def get_pending():
    return {"transactions": [t.to_dict() for t in blockchain.get_pending_transactions()]}


@app.post("/transactions")
async def create_transaction(request: TransactionRequest):
    try:
        tx_type = TransactionType(request.type)
    except ValueError:
        raise HTTPException(422, f"Tipo de transacción inválido: {request.type}")

    nonce = request.nonce
    if nonce is None:
        if request.signature:
            raise HTTPException(400, "Falta el nonce de la TX firmada por el cliente")
        nonce = blockchain.next_nonce(request.sender)
    tx = Transaction(
        type=tx_type,
        sender=request.sender,
        recipient=request.recipient,
        payload=request.payload,
        fee=request.fee,
        nonce=nonce,
    )
    if request.signature:
        # TX firmada por el cliente: el servidor sólo verifica.
        if request.timestamp is not None:
            tx.timestamp = request.timestamp
            tx.tx_id = tx._compute_id()
        tx.signature = request.signature
        tx.public_key = request.public_key or ""
    elif request.private_key_hex:
        try:
            tx.sign(request.private_key_hex)
        except Exception:
            raise HTTPException(400, "Llave privada inválida")

    _enforce_tx_rate_limit(tx.sender)
    anomaly = tx_anomaly_detector.predict(tx.to_dict())
    security_monitor.on_transaction(tx.to_dict())

    ok, reason = blockchain.add_transaction(tx)
    if not ok:
        raise HTTPException(400, reason)

    _screen_admitted_tx(tx, anomaly)
    p2p.broadcast_transaction(tx.to_dict())

    return {
        "tx_id": tx.tx_id,
        "status": "pending",
        "anomaly": anomaly.to_dict(),
    }


@app.get("/tx/{tx_id}/proof")
async def get_tx_proof(tx_id: str):
    """Prueba de inclusión Merkle de una TX confirmada (P2-2)."""
    for block in blockchain.chain:
        for i, tx in enumerate(block.transactions):
            if tx.get("tx_id") == tx_id:
                hojas = [leaf_hash(t) for t in block.transactions]
                return {
                    "tx_id": tx_id,
                    "block_index": block.header.index,
                    "block_hash": block.hash,
                    "merkle_root": block.header.merkle_root,
                    "leaf": hojas[i],
                    "proof": build_proof(hojas, i),
                }
    if any(t.tx_id == tx_id for t in blockchain.mempool):
        raise HTTPException(404, "Transacción pendiente: aún no está en un bloque, sin prueba")
    raise HTTPException(404, "Transacción no encontrada")


@app.get("/transactions/{tx_id}")
async def get_transaction(tx_id: str):
    tx = blockchain.get_transaction(tx_id)
    if not tx:
        raise HTTPException(404, "Transacción no encontrada")
    return tx


@app.get("/accounts/{address}")
async def get_account(address: str):
    """Cuenta de ``address`` (P0-9): saldo y nonce confirmados y ``next_nonce``
    (el que debe firmar su próxima TX, contando las pendientes del mempool)."""
    return blockchain.account_info(address)


@app.get("/chain/balance/{address}")
async def get_address_balance(address: str):
    """Saldo confirmado (entero, unidad mínima) y total de fees quemadas (P0-9)."""
    balance = blockchain.get_balance(address)
    total_fees = blockchain.total_fees
    return {
        "address": address,
        "balance": balance,
        "chain_total_fees": total_fees,
    }


@app.post("/mempool/prune", dependencies=[Depends(require_admin)])
async def prune_mempool(request: PruneMempoolRequest):
    """Elimina del mempool las transacciones más viejas que max_age_seconds."""
    pruned = blockchain.prune_mempool(request.max_age_seconds)
    return {
        "pruned": pruned,
        "remaining": len(blockchain.mempool),
        "max_age_seconds": request.max_age_seconds,
    }


# ── Endpoints: tokens (P0-9) ──────────────────────────────────────────────────

@app.post("/tokens/mint", dependencies=[Depends(require_admin)])
async def mint_tokens(request: MintRequest):
    """Emite tokens con una TX TOKEN_MINT firmada por la autoridad del génesis.

    Solo funciona en el nodo con la llave de autoridad (como /credentials/issuers).
    """
    if authority_wallet is None:
        raise HTTPException(503, "Este nodo no tiene la llave de autoridad configurada")
    tx = create_mint_transaction(
        authority_address=authority_wallet.address,
        recipient=request.recipient,
        amount=request.amount,
        private_key_hex=authority_wallet.private_key_hex,
        nonce=blockchain.next_nonce(authority_wallet.address),
    )
    _submit_contract_tx(tx)
    return {"status": "PENDING", "tx_id": tx.tx_id, "nonce": tx.nonce}


@app.post("/tokens/transfer")
async def transfer_tokens(request: TransferRequest):
    """Transfiere tokens (TOKEN_TRANSFER). 400 si falta saldo para amount + fee."""
    try:
        tx = create_transfer_transaction(
            sender=request.sender,
            recipient=request.recipient,
            amount=request.amount,
            private_key_hex=request.private_key_hex,
            nonce=blockchain.next_nonce(request.sender),
            fee=request.fee,
        )
    except Exception:
        raise HTTPException(400, "Llave privada inválida")
    _submit_contract_tx(tx)
    return {"status": "PENDING", "tx_id": tx.tx_id, "nonce": tx.nonce}


# ── Endpoints: credenciales ───────────────────────────────────────────────────

def _credentials() -> CredentialState:
    """Estado confirmado del contrato de credenciales (P0-6, P1-13)."""
    return blockchain.contract_state("credentials")


def _submit_contract_tx(tx: Transaction) -> None:
    """Admite una TX al mempool (límite por emisor, firma, cuentas y reglas del contrato) o lanza 400/429."""
    _enforce_tx_rate_limit(tx.sender)
    ok, reason = blockchain.add_transaction(tx)
    if not ok:
        raise HTTPException(400, reason)
    security_monitor.on_transaction(tx.to_dict())
    _screen_admitted_tx(tx)
    p2p.broadcast_transaction(tx.to_dict())


@app.post("/credentials/issuers", dependencies=[Depends(require_admin)])
async def register_issuer(request: RegisterIssuerRequest):
    """Registra un emisor con una TX ISSUER_REGISTER firmada por la autoridad (P0-6).

    Solo funciona en el nodo que tiene la llave de autoridad (AUTHORITY_KEY_FILE).
    Una TX ISSUER_REGISTER firmada por otra llave se rechaza (también vía /transactions).
    """
    if authority_wallet is None:
        raise HTTPException(503, "Este nodo no tiene la llave de autoridad configurada")
    tx = create_issuer_register_transaction(
        authority_address=authority_wallet.address,
        issuer_address=request.issuer_address,
        institution_code=request.institution_code,
        private_key_hex=authority_wallet.private_key_hex,
        nonce=blockchain.next_nonce(authority_wallet.address),
    )
    _submit_contract_tx(tx)
    return {"status": "PENDING", "tx_id": tx.tx_id}


@app.post("/credentials/issue")
async def issue_credential(request: CredentialRequest):
    """Emite una credencial: firma la TX y la pone en el mempool.

    No toca el estado confirmado: la credencial queda PENDING hasta que un
    bloque la incluya. El emisor debe estar registrado (confirmado o pendiente).
    """
    try:
        tx = create_credential_transaction(
            issuer_address=request.issuer_address,
            student_address=request.student_address,
            credential_data=request.credential_data,
            private_key_hex=request.private_key_hex,
            nonce=blockchain.next_nonce(request.issuer_address),
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception:
        raise HTTPException(400, "Llave privada inválida")
    _submit_contract_tx(tx)

    data = request.credential_data
    credential_id = credential_id_of_tx(tx.to_dict())
    return {
        "credential_id": credential_id,
        "tx_id": tx.tx_id,
        "status": "PENDING",
        "qr_data": json.dumps({
            "id": credential_id,
            "student": data.get("student_name"),
            "degree": data.get("degree"),
            "date": data.get("issue_date"),
            "verify_url": f"upbchain://verify/{credential_id}",
        }),
    }


@app.post("/credentials/revoke")
async def revoke_credential(request: RevokeRequest):
    """Revoca una credencial con una TX CREDENTIAL_REVOKE firmada.

    Solo la acepta si la firma el emisor original o la autoridad del génesis.
    """
    try:
        tx = create_revoke_transaction(
            revoker_address=request.revoker_address,
            credential_id=request.credential_id,
            reason=request.reason,
            private_key_hex=request.private_key_hex,
            nonce=blockchain.next_nonce(request.revoker_address),
        )
    except Exception:
        raise HTTPException(400, "Llave privada inválida")
    _submit_contract_tx(tx)
    return {"tx_id": tx.tx_id, "status": "PENDING"}


@app.get("/credentials/verify/{credential_id}")
async def verify_credential(credential_id: str):
    """Estado de la credencial: PENDING, CONFIRMED (con bloque y confirmaciones),
    REVOKED, EXPIRED o NOT_FOUND. ``valid`` es true solo si está CONFIRMED."""
    return _credentials().credential_status(credential_id, blockchain.height,
                                            pending=blockchain.pending_dicts())


# ── Verificación pública por QR (P1-3) ────────────────────────────────────────

def _estado_publico(credential_id: str) -> dict:
    """Misma lógica de estado que ``/credentials/verify/{id}`` (sin duplicarla)."""
    return _credentials().credential_status(credential_id, blockchain.height,
                                            pending=blockchain.pending_dicts())


def _url_verificacion(request: Request, credential_id: str) -> str:
    """URL pública de la página de verificación (PUBLIC_BASE_URL o la del request)."""
    base = settings.public_base_url or str(request.base_url)
    return f"{base.rstrip('/')}/verify/{credential_id}"


@app.get("/credentials/{credential_id}/qr")
async def credential_qr(credential_id: str, request: Request):
    """PNG con un QR que apunta a la página pública ``/verify/{id}``."""
    if _estado_publico(credential_id)["status"] == "NOT_FOUND":
        raise HTTPException(404, "Credencial no encontrada")
    import qrcode
    img = qrcode.make(_url_verificacion(request, credential_id))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return Response(content=buf.getvalue(), media_type="image/png")


_VERIFY_COLORS = {"CONFIRMED": "#15803d", "PENDING": "#b45309", "REVOKED": "#b91c1c",
                  "EXPIRED": "#b91c1c", "NOT_FOUND": "#4b5563"}

_VERIFY_PAGE = """<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Verificación de credencial UPB</title>
<style>body{{font-family:system-ui,sans-serif;margin:0;background:#f3f4f6;color:#111}}
main{{max-width:480px;margin:0 auto;padding:16px}}
.card{{background:#fff;border-radius:12px;padding:20px;box-shadow:0 1px 4px #0002}}
.v{{font-size:1.8rem;font-weight:700;color:{color};margin:0 0 4px}}
dl{{margin:16px 0 0}}dt{{font-size:.75rem;color:#6b7280;margin-top:10px}}
dd{{margin:0;word-break:break-all}}</style></head>
<body><main><div class="card">
<p style="margin:0;color:#6b7280">UPB-Chain · Verificación de credencial</p>
<h1 class="v">{verdict}</h1><p>{reason}</p><dl>{rows}</dl></div></main></body></html>"""


@app.get("/verify/{credential_id}", response_class=HTMLResponse)
async def verify_page(credential_id: str):
    """Página pública y móvil de verificación. No expone notas ni datos personales."""
    st = _estado_publico(credential_id)
    cred = st.get("credential") or {}
    campos = [("ID", credential_id), ("Emisor", cred.get("issuer_address")),
              ("Tipo", cred.get("credential_type")), ("Título", cred.get("degree")),
              ("Fecha de emisión", cred.get("issue_date")),
              ("Bloque", st.get("block_index")),
              ("Confirmaciones", st.get("confirmations") if cred else None)]
    rows = "".join(f"<dt>{html.escape(k)}</dt><dd>{html.escape(str(v))}</dd>"
                   for k, v in campos if v is not None and v != "")
    body = _VERIFY_PAGE.format(
        color=_VERIFY_COLORS.get(st["status"], "#4b5563"),
        verdict=html.escape(st["verdict"]), reason=html.escape(st["reason"]), rows=rows)
    return HTMLResponse(body, status_code=404 if st["status"] == "NOT_FOUND" else 200)


@app.get("/credentials/issuer/{address}")
async def get_issuer_credentials(address: str):
    """Credenciales de un emisor (confirmadas y pendientes), solo resumen público."""
    pending, state = blockchain.pending_dicts(), _credentials()
    ids = state.issuer_credential_ids(address, pending=pending)
    items = [state.credential_summary(i, blockchain.height, pending=pending) for i in ids]
    return {"issuer_address": address, "count": len(items), "credentials": items}


@app.get("/credentials/{credential_id}/history")
async def credential_history(credential_id: str):
    """Historial: emitida en el bloque X, revocada en el bloque Y (derivado del contrato)."""
    r = _credentials().credential_summary(credential_id, blockchain.height,
                                          pending=blockchain.pending_dicts())
    if r["status"] == "NOT_FOUND":
        raise HTTPException(404, "Credencial no encontrada")
    if r["block_index"] is not None:
        eventos = [{"event": "ISSUED", "block": r["block_index"], "tx_id": r["tx_id"]}]
    else:
        eventos = [{"event": "ISSUE_PENDING", "block": None, "tx_id": r["tx_id"]}]
    if r["revocation_block"] is not None:
        eventos.append({"event": "REVOKED", "block": r["revocation_block"],
                        "tx_id": r["revocation_tx"], "reason": r["revocation_reason"]})
    elif r["pending_revocation"]:
        eventos.append({"event": "REVOKE_PENDING", "block": None, "tx_id": None})
    return {**r, "events": eventos}


@app.get("/credentials/student/{address}")
async def get_student_credentials(address: str):
    return {"credentials": _credentials().get_student_credentials(address)}


@app.get("/credentials/search")
async def search_credentials(q: str):
    """Busca credenciales por nombre de estudiante o grado (case-insensitive, substring).

    Query param:
        q: Término de búsqueda (mínimo 1 carácter).
    """
    if not q or not q.strip():
        raise HTTPException(400, "El parámetro 'q' no puede estar vacío")
    results = _credentials().search_credentials(q)
    return {"query": q, "count": len(results), "credentials": results}


@app.get("/credentials/all")
async def get_all_credentials(status: Optional[str] = None):
    """Retorna todas las credenciales registradas en el contrato.

    Query param:
        status: Filtro opcional de estado — ACTIVE | REVOKED | EXPIRED.
                Si se omite, retorna todas las credenciales.
    """
    credentials = _credentials().get_all_credentials(status_filter=status)
    return {
        "count": len(credentials),
        "status_filter": status,
        "credentials": credentials,
    }


# ── Endpoints: contratos (P1-13) ─────────────────────────────────────────────

@app.get("/contracts")
async def list_contracts():
    """Contratos que corre este nodo, en orden, con los tipos de TX que manejan."""
    registry = blockchain.contracts
    return {
        "height": registry.height,
        "contracts": [
            {"name": name,
             "handled_types": (None if registry.contract(name).HANDLED_TYPES is None
                               else sorted(registry.contract(name).HANDLED_TYPES))}
            for name in registry.names
        ],
    }


@app.get("/contracts/voting/{election_id}")
async def get_election(election_id: str):
    """Recuento de una elección del contrato de votación (votos confirmados).

    Para votar: ``POST /transactions`` con ``type=VOTE`` y payload
    ``{"election_id": ..., "choice": ...}``; un segundo voto de la misma
    dirección en la misma elección responde 400.
    """
    state = blockchain.contract_state("voting")
    votes = state.elections.get(election_id, {})
    pending = sum(1 for tx in blockchain.pending_dicts()
                  if tx.get("type") == TransactionType.VOTE.value
                  and (tx.get("payload") or {}).get("election_id") == election_id)
    if not votes and not pending:
        raise HTTPException(404, "Elección sin votos")
    return {
        "election_id": election_id,
        "total_votes": len(votes),
        "tally": state.tally(election_id),
        "voters": list(votes),
        "pending_votes": pending,
        "height": blockchain.contracts.height,
    }


# ── Endpoints: IA ─────────────────────────────────────────────────────────────

@app.get("/ai/analytics")
async def get_analytics():
    chain_data = [b.to_dict() for b in blockchain.chain]
    report = chain_analytics.analyze(chain_data)
    return report.to_dict()


@app.post("/ai/train", dependencies=[Depends(require_admin)])
async def train_anomaly_detector():
    all_txs = []
    for block in blockchain.chain:
        all_txs.extend(block.transactions)
    result = tx_anomaly_detector.train(all_txs)
    if result.get("trained"):
        tx_anomaly_detector.save(anomaly_model_path)
        result["model_path"] = str(anomaly_model_path)
    return result


@app.get("/ai/anomaly/stats")
async def anomaly_stats():
    return tx_anomaly_detector.get_stats()


# ── Endpoints: seguridad ──────────────────────────────────────────────────────

@app.get("/security/alerts")
async def get_alerts(level: Optional[str] = None):
    from security.monitor import AlertLevel
    lv = AlertLevel(level) if level else None
    return {"alerts": security_monitor.get_alerts(level=lv)}


@app.get("/security/threat-summary")
async def threat_summary():
    return security_monitor.get_threat_summary()


@app.get("/security/attack-simulation")
async def attack_simulation():
    return full_security_analysis(
        node_count=len(p2p.peers) + 1,
        honest_hash_rate=70.0,
        attacker_hash_rate=30.0,
    )


@app.get("/security/crypto-benchmark")
async def crypto_benchmark():
    return benchmark_crypto(iterations=5000)


@app.get("/security/hardening")
async def hardening_checklist():
    """Checklist de hardening en solo lectura (inspección de código, sin shell)."""
    return HardeningAuditor().run_audit()


@app.post("/security/eclipse-simulation")
async def eclipse_simulation(max_connections: int = Query(32, ge=1, le=256),
                             attacker_nodes: int = Query(10, ge=0, le=1000),
                             network_size: int = Query(50, ge=2, le=1000)):
    """Simulación académica de eclipse; solo cálculo, no toca la red.

    Parámetros acotados para que una petición no bloquee el nodo.
    """
    return EclipseAttack().simulate(
        max_connections=max_connections,
        attacker_nodes=attacker_nodes,
        network_size=network_size,
    ).__dict__


# ── Endpoints: wallet ─────────────────────────────────────────────────────────

@app.post("/wallet/generate")
async def generate_wallet():
    wallet = Wallet.generate()
    return {
        "address": wallet.address,
        "public_key": wallet.public_key_hex,
        "private_key": wallet.private_key_hex,
        "warning": "Guarda la llave privada en un lugar seguro. No se almacena en el servidor.",
    }


# ── Endpoints: red P2P ────────────────────────────────────────────────────────

@app.get("/network")
async def network_info():
    return p2p.get_network_stats()


@app.post("/network/peers", dependencies=[Depends(require_admin)])
def add_peer(host: str, port: int):
    # `def` (no async): el handshake es E/S bloqueante y FastAPI lo corre en un hilo.
    ok = p2p.connect_to_peer(host, port)
    return {"connected": ok}


@app.get("/network/sync")
async def sync_chain():
    return {"chain": [b.to_dict() for b in blockchain.chain], "height": blockchain.height}


@app.post("/network/sync", dependencies=[Depends(require_admin)])
def sync_now():
    """Fuerza la sincronización con todos los pares activos (P0-5)."""
    adopted = p2p.sync_with_peers()
    return {"adopted": adopted, "height": blockchain.height, "work": blockchain.total_work}
