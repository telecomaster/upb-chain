"""
API REST de UPB-Chain — FastAPI.
Expone endpoints para bloques, transacciones, credenciales, análisis y seguridad.

P2-9: no hay estado global. ``create_app(settings)`` construye un ``NodeState`` (cadena,
P2P, detectores, monitor, límite de TX, minado y llave de autoridad), lo guarda en
``app.state.node`` y los endpoints lo reciben con ``Depends(get_node)``. Dos apps en el
mismo proceso son independientes. ``app = create_app()`` al final mantiene
``uvicorn api.app:app``.
"""
import asyncio
import csv
import hmac
import html
import io
import json
import logging
import os
import threading
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, APIRouter, HTTPException, Depends, BackgroundTasks, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field

from config import Settings, load_settings, configure_logging
from blockchain.core.chain import Blockchain
from blockchain.core.merkle import build_proof, leaf_hash
from blockchain.core import commitment
from blockchain.core.transaction import (
    Transaction,
    TransactionType,
    create_credential_transaction_with_record,
    create_issuer_register_transaction,
    create_mint_transaction,
    create_revoke_transaction,
    create_transfer_transaction,
    create_issuer_budget_transaction,
    create_redeem_address_transaction,
    create_redeem_transaction,
    create_badge_award_transaction,
)
from blockchain.core.wallet import Wallet, derive_address, public_key_from_private
from blockchain.consensus.proof_of_work import ProofOfWork
from blockchain.consensus.pbft import PBFTNode
from blockchain.contracts.credential import CredentialState, credential_id_of_tx
from blockchain.contracts.tokens import (
    MAX_REASON, TOKEN_NAME, TOKEN_SYMBOL, is_semester, semester_of,
)
from blockchain.network.node import P2PNode
from ai.anomaly.detector import TransactionAnomalyDetector, BlockAnomalyDetector
from ai.analytics.chain_stats import ChainAnalytics
from security.monitor import SecurityMonitor
from security.rate_limiter import TxRateLimiter
from security.attacks.simulator import full_security_analysis
from security.attacks.eclipse import EclipseAttack
from security.hardening import HardeningAuditor
from security.crypto_utils import generate_keypair, benchmark_crypto

logger = logging.getLogger("upb_chain.api")


def build_node_state(data_dir: str, node_id: str, authority_address: Optional[str] = None,
                     initial_difficulty: int = 4, revalidate_on_start: str = "fast",
                     snapshot_interval: int = 100) -> Blockchain:
    """Carga la cadena con sus contratos (P1-13): cuentas, credenciales y votación.

    El estado de cada contrato se deriva reproduciendo la cadena al arrancar y
    se actualiza con cada bloque o reemplazo de cadena; la API lo lee con
    ``blockchain.contract_state(nombre)``. ``authority_address`` (por defecto la
    del génesis) es la única que firma TOKEN_MINT e ISSUER_REGISTER.
    """
    return Blockchain(node_id=node_id, data_dir=data_dir,
                      initial_difficulty=initial_difficulty,
                      authority_address=authority_address,
                      revalidate_on_start=revalidate_on_start,
                      snapshot_interval=snapshot_interval)


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


# ── Estado de un nodo ────────────────────────────────────────────────────────

@dataclass
class NodeState:
    """Todo lo que vive dentro de un nodo; una app = un ``NodeState`` (``app.state.node``)."""
    settings: Settings
    blockchain: Blockchain
    authority_wallet: Optional[Wallet]
    pow_engine: ProofOfWork
    mining_lock: asyncio.Lock          # un solo minado a la vez (409 si ya hay uno)
    mining_stop: threading.Event       # se activa al apagar el nodo para abortar el PoW
    tx_anomaly_detector: TransactionAnomalyDetector
    anomaly_model_path: Path
    block_anomaly_detector: BlockAnomalyDetector
    chain_analytics: ChainAnalytics
    security_monitor: SecurityMonitor
    tx_rate_limiter: TxRateLimiter
    pbft_node: PBFTNode
    p2p: P2PNode

    def on_chain_reorg(self, fork_height: int, dropped: list, added: list) -> None:
        """Reorganización -> alerta (profundidad = bloques propios descartados) y bloques nuevos."""
        self.security_monitor.on_chain_reorg(len(dropped))
        for block in added:
            self.security_monitor.on_block(block.to_dict())


def build_node(settings: Settings, authority_address: Optional[str] = None) -> NodeState:
    """Construye el estado completo de un nodo a partir de ``settings`` (sin arrancar la red)."""
    node_id = settings.node_id
    blockchain = build_node_state(
        settings.data_dir, node_id, authority_address=authority_address,
        initial_difficulty=settings.mining_difficulty,
        revalidate_on_start=settings.revalidate_on_start,
        snapshot_interval=settings.snapshot_interval)
    authority_wallet = load_authority_wallet(
        settings.authority_key_file, blockchain.contracts.contract("accounts").authority_address)
    tx_anomaly_detector = TransactionAnomalyDetector()
    anomaly_model_path = Path(settings.data_dir) / "models" / "tx_iforest.joblib"
    if tx_anomaly_detector.load(anomaly_model_path):
        logger.info("Modelo de anomalías cargado de %s", anomaly_model_path)
    security_monitor = SecurityMonitor()
    security_monitor.TX_RATE_LIMIT = settings.tx_rate_limit   # atributo de instancia
    # P1-5: límite de admisión al mempool (política local, nunca regla de consenso).
    tx_rate_limiter = TxRateLimiter(limit=settings.tx_rate_limit,
                                    window=security_monitor.TX_RATE_WINDOW)
    pbft_peers = [node_id] + [f"node_{i}" for i in range(2, 5)]
    pbft_node = PBFTNode(node_id=node_id, peers=pbft_peers, is_primary=(node_id == "node_1"))
    p2p = P2PNode(
        node_id=node_id,
        host=settings.node_host,
        port=settings.node_port,
        advertise_host=settings.node_advertise_host or None,
        # P0-5: el nodo valida/añade bloques y TXs recibidos y, si un bloque no
        # extiende la punta, sincroniza con el emisor (replace_chain por trabajo).
        blockchain=blockchain,
        on_pbft_message=lambda m: logger.info(f"PBFT msg recibido: {m}"),
        # P1-5: bloques recibidos y aceptados, bloques inválidos y pares fuera de PEERS.
        on_new_block=security_monitor.on_block,
        on_invalid_block=security_monitor.on_invalid_block,
        on_unknown_peer=security_monitor.on_unknown_peer,
        known_peers=settings.peers,
    )
    node = NodeState(
        settings=settings,
        blockchain=blockchain,
        authority_wallet=authority_wallet,
        # La dificultad NO vive aquí: la dicta Blockchain._calculate_difficulty() (P0-4).
        pow_engine=ProofOfWork(),
        mining_lock=asyncio.Lock(),
        mining_stop=threading.Event(),
        tx_anomaly_detector=tx_anomaly_detector,
        anomaly_model_path=anomaly_model_path,
        block_anomaly_detector=BlockAnomalyDetector(),
        chain_analytics=ChainAnalytics(),
        security_monitor=security_monitor,
        tx_rate_limiter=tx_rate_limiter,
        pbft_node=pbft_node,
        p2p=p2p,
    )
    blockchain.add_reorg_listener(node.on_chain_reorg)
    return node


def get_node(request: Request) -> NodeState:
    """Dependencia: el ``NodeState`` de la app que atiende la petición."""
    return request.app.state.node


def _screen_admitted_tx(node: NodeState, tx: Transaction, report=None) -> None:
    """Tras admitir una TX: la registra en el contexto del detector y alerta si fue marcada (P1-6)."""
    if report is None:
        report = node.tx_anomaly_detector.predict(tx.to_dict())
    node.tx_anomaly_detector.observe(tx.to_dict())
    if report.is_anomaly:
        node.security_monitor.on_anomalous_transaction(tx.to_dict(), report.to_dict())


def _enforce_tx_rate_limit(node: NodeState, sender: str) -> None:
    """429 (y alerta) si el emisor superó el límite de TX por minuto."""
    allowed, count = node.tx_rate_limiter.check(sender)
    if not allowed:
        node.security_monitor.on_tx_rate_limited(sender, count, node.tx_rate_limiter.limit)
        raise HTTPException(429, f"Límite de {node.tx_rate_limiter.limit} TX por minuto excedido")


_HOSTS_LOCALES = {"127.0.0.1", "::1", "localhost", "testclient"}


async def require_admin(request: Request) -> None:
    """Dependencia para endpoints de administración (P1-9).

    Con ``ADMIN_API_KEY`` definida exige la cabecera ``X-API-Key`` (401 si falta
    o es incorrecta). Sin llave solo admite peticiones desde loopback (403 si no).
    Uso: ``@router.post("/ruta", dependencies=[Depends(require_admin)])``.
    """
    clave = request.app.state.node.settings.admin_api_key
    if clave:
        recibida = request.headers.get("x-api-key", "")
        if not hmac.compare_digest(recibida.encode("utf-8"), clave.encode("utf-8")):
            raise HTTPException(401, "llave de administración ausente o incorrecta")
        return
    host = request.client.host if request.client else ""
    if host not in _HOSTS_LOCALES:
        raise HTTPException(403, "endpoint de administración: solo local o con ADMIN_API_KEY")


router = APIRouter()


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


class BudgetRequest(BaseModel):
    issuer_address: str
    amount: int = Field(ge=0)
    semester: Optional[str] = None      # "AAAA-1" | "AAAA-2"; por defecto, el actual


class RedeemAddressRequest(BaseModel):
    redeem_address: str
    label: str


class AwardRequest(BaseModel):
    issuer_address: str
    private_key_hex: str               # llave del EMISOR (no la de la autoridad)
    recipient: str
    amount: int = Field(gt=0)
    reason: str


class AwardCsvRequest(BaseModel):
    issuer_address: str
    private_key_hex: str
    csv: str                           # encabezado "address,amount,reason"


class RedeemRequest(BaseModel):
    sender: str
    private_key_hex: str
    redeem_address: str
    amount: int = Field(gt=0)
    item: str = ""


class BadgeRequest(BaseModel):
    issuer_address: str
    private_key_hex: str
    recipient: str
    badge_id: str
    name: str
    reason: str


class PruneMempoolRequest(BaseModel):
    max_age_seconds: int = 3600


# ── Endpoints: información general ───────────────────────────────────────────

@router.get("/", response_class=HTMLResponse)
async def root():
    try:
        with open("dashboard/templates/index.html", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "<h1>UPB-Chain API — <a href='/docs'>Documentación</a></h1>"


@router.get("/health")
async def health(node: NodeState = Depends(get_node)):
    return {
        "status": "ok",
        "node_id": node.settings.node_id,
        "height": node.blockchain.height,
        "timestamp": time.time(),
    }


@router.get("/stats")
async def stats(node: NodeState = Depends(get_node)):
    chain_stats = node.blockchain.get_stats()
    network_stats = node.p2p.get_network_stats()
    # Dificultad del próximo bloque, en bits (P2-5).
    pow_stats = {**node.pow_engine.get_mining_stats(),
                 "difficulty_bits": node.blockchain._calculate_difficulty()}
    threat = node.security_monitor.get_threat_summary()
    return {
        "chain": chain_stats,
        "network": network_stats,
        "mining": pow_stats,
        "security": threat,
        "pbft": node.pbft_node.get_consensus_stats(),
    }


# ── Endpoints: bloques ────────────────────────────────────────────────────────

@router.get("/blocks")
async def get_blocks(page: int = 0, size: int = 10, node: NodeState = Depends(get_node)):
    start = page * size
    end = start + size
    blocks = node.blockchain.chain[start:end]
    return {
        "blocks": [b.to_dict() for b in blocks],
        "total": len(node.blockchain.chain),
        "page": page,
        "size": size,
    }


@router.get("/blocks/hash/{block_hash}")
async def get_block_by_hash(block_hash: str, node: NodeState = Depends(get_node)):
    """Retorna un bloque buscado por su hash SHA-256."""
    block = node.blockchain.get_block_by_hash(block_hash)
    if not block:
        raise HTTPException(404, f"Bloque con hash '{block_hash}' no encontrado")
    return block.to_dict()


@router.get("/blocks/{index}")
async def get_block(index: int, node: NodeState = Depends(get_node)):
    if index < 0 or index >= len(node.blockchain.chain):
        raise HTTPException(404, "Bloque no encontrado")
    block = node.blockchain.chain[index]
    report = node.block_anomaly_detector.peek_block(block.to_dict())   # lectura pura: no muta el detector
    return {**block.to_dict(), "anomaly": report.to_dict()}


@router.post("/blocks/mine", dependencies=[Depends(require_admin)])
async def mine_block(request: MineRequest, background_tasks: BackgroundTasks, node: NodeState = Depends(get_node)):
    if node.mining_lock.locked():
        raise HTTPException(409, "minado en curso")
    async with node.mining_lock:
        node.mining_stop.clear()
        candidate = node.blockchain.create_candidate_block()
        # La dificultad sale de la regla de la cadena, nunca de un valor fijo.
        difficulty = candidate.header.difficulty
        # El PoW corre en un thread para no bloquear el event loop.
        result = await asyncio.to_thread(
            node.pow_engine.mine, candidate, difficulty=difficulty, stop_event=node.mining_stop
        )
        if not result:
            raise HTTPException(500, "Mining falló, timeout o abortado")
        ok, reason = node.blockchain.add_block(result.block)
        if not ok:
            # Típico: llegó un bloque de un peer y la punta cambió durante el minado.
            node.security_monitor.on_invalid_block(reason, node.settings.node_id)
            raise HTTPException(409, f"Bloque minado ya no es válido: {reason}")
        node.security_monitor.on_block(result.block.to_dict())
    # Difusión a los pares (E/S de red bloqueante) fuera del event loop (P0-5).
    await asyncio.to_thread(node.p2p.broadcast_block, result.block.to_dict())
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

@router.get("/transactions/pending")
async def get_pending(node: NodeState = Depends(get_node)):
    return {"transactions": [t.to_dict() for t in node.blockchain.get_pending_transactions()]}


@router.post("/transactions")
async def create_transaction(request: TransactionRequest, node: NodeState = Depends(get_node)):
    try:
        tx_type = TransactionType(request.type)
    except ValueError:
        raise HTTPException(422, f"Tipo de transacción inválido: {request.type}")

    nonce = request.nonce
    if nonce is None:
        if request.signature:
            raise HTTPException(400, "Falta el nonce de la TX firmada por el cliente")
        nonce = node.blockchain.next_nonce(request.sender)
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

    _enforce_tx_rate_limit(node, tx.sender)
    anomaly = node.tx_anomaly_detector.predict(tx.to_dict())
    node.security_monitor.on_transaction(tx.to_dict())

    ok, reason = node.blockchain.add_transaction(tx)
    if not ok:
        raise HTTPException(400, reason)

    _screen_admitted_tx(node, tx, anomaly)
    node.p2p.broadcast_transaction(tx.to_dict())

    return {
        "tx_id": tx.tx_id,
        "status": "pending",
        "anomaly": anomaly.to_dict(),
    }


@router.get("/tx/{tx_id}/proof")
async def get_tx_proof(tx_id: str, node: NodeState = Depends(get_node)):
    """Prueba de inclusión Merkle de una TX confirmada (P2-2).

    El índice de chain.db (P2-4) da el bloque y la posición sin recorrer la cadena.
    """
    found = node.blockchain.locate_transaction(tx_id)
    if found is not None:
        block, i = found
        hojas = [leaf_hash(t) for t in block.transactions]
        return {
            "tx_id": tx_id,
            "block_index": block.header.index,
            "block_hash": block.hash,
            "merkle_root": block.header.merkle_root,
            "leaf": hojas[i],
            "proof": build_proof(hojas, i),
        }
    if any(t.tx_id == tx_id for t in node.blockchain.mempool):
        raise HTTPException(404, "Transacción pendiente: aún no está en un bloque, sin prueba")
    raise HTTPException(404, "Transacción no encontrada")


@router.get("/transactions/{tx_id}")
async def get_transaction(tx_id: str, node: NodeState = Depends(get_node)):
    tx = node.blockchain.get_transaction(tx_id)
    if not tx:
        raise HTTPException(404, "Transacción no encontrada")
    return tx


@router.get("/accounts/{address}")
async def get_account(address: str, node: NodeState = Depends(get_node)):
    """Cuenta de ``address`` (P0-9): saldo y nonce confirmados y ``next_nonce``
    (el que debe firmar su próxima TX, contando las pendientes del mempool)."""
    return node.blockchain.account_info(address)


@router.get("/chain/balance/{address}")
async def get_address_balance(address: str, node: NodeState = Depends(get_node)):
    """Saldo confirmado (entero, unidad mínima) y total de fees quemadas (P0-9)."""
    balance = node.blockchain.get_balance(address)
    total_fees = node.blockchain.total_fees
    return {
        "address": address,
        "balance": balance,
        "chain_total_fees": total_fees,
    }


@router.post("/mempool/prune", dependencies=[Depends(require_admin)])
async def prune_mempool(request: PruneMempoolRequest, node: NodeState = Depends(get_node)):
    """Elimina del mempool las transacciones más viejas que max_age_seconds."""
    pruned = node.blockchain.prune_mempool(request.max_age_seconds)
    return {
        "pruned": pruned,
        "remaining": len(node.blockchain.mempool),
        "max_age_seconds": request.max_age_seconds,
    }


# ── Endpoints: tokens (P0-9) ──────────────────────────────────────────────────

@router.post("/tokens/mint", dependencies=[Depends(require_admin)])
async def mint_tokens(request: MintRequest, node: NodeState = Depends(get_node)):
    """Emite tokens con una TX TOKEN_MINT firmada por la autoridad del génesis.

    Solo funciona en el nodo con la llave de autoridad (como /credentials/issuers).
    """
    if node.authority_wallet is None:
        raise HTTPException(503, "Este nodo no tiene la llave de autoridad configurada")
    tx = create_mint_transaction(
        authority_address=node.authority_wallet.address,
        recipient=request.recipient,
        amount=request.amount,
        private_key_hex=node.authority_wallet.private_key_hex,
        nonce=node.blockchain.next_nonce(node.authority_wallet.address),
    )
    _submit_contract_tx(node, tx)
    return {"status": "PENDING", "tx_id": tx.tx_id, "nonce": tx.nonce}


@router.post("/tokens/transfer")
async def transfer_tokens(request: TransferRequest, node: NodeState = Depends(get_node)):
    """Transfiere tokens (TOKEN_TRANSFER). 400 si falta saldo para amount + fee."""
    try:
        tx = create_transfer_transaction(
            sender=request.sender,
            recipient=request.recipient,
            amount=request.amount,
            private_key_hex=request.private_key_hex,
            nonce=node.blockchain.next_nonce(request.sender),
            fee=request.fee,
        )
    except Exception:
        raise HTTPException(400, "Llave privada inválida")
    _submit_contract_tx(node, tx)
    return {"status": "PENDING", "tx_id": tx.tx_id, "nonce": tx.nonce}


# ── Endpoints: tokens e insignias para estudiantes (P1-12) ───────────────────
# Puntos de circuito cerrado, sin valor monetario (pendiente visto bueno legal).
# Las TXs de premio, canje e insignia las firma la llave del propio usuario
# (emisor o estudiante); las de presupuesto y direcciones de canje, la autoridad.

MAX_CSV_ROWS = 100


def _require_authority(node: NodeState) -> Wallet:
    if node.authority_wallet is None:
        raise HTTPException(503, "Este nodo no tiene la llave de autoridad configurada")
    return node.authority_wallet


def _signed(build) -> Transaction:
    """Construye y firma una TX con la llave del usuario; 400 si la llave no sirve."""
    try:
        return build()
    except Exception:
        raise HTTPException(400, "Llave privada inválida")


@router.post("/tokens/budget", dependencies=[Depends(require_admin)])
async def set_issuer_budget(request: BudgetRequest, node: NodeState = Depends(get_node)):
    """Fija el presupuesto semestral de un emisor (ISSUER_BUDGET, firma la autoridad)."""
    authority = _require_authority(node)
    semester = request.semester or semester_of(time.time())
    if not is_semester(semester):
        raise HTTPException(400, "semester debe tener la forma AAAA-1 o AAAA-2")
    tx = create_issuer_budget_transaction(
        authority.address, request.issuer_address, semester, request.amount,
        authority.private_key_hex, nonce=node.blockchain.next_nonce(authority.address))
    _submit_contract_tx(node, tx)
    return {"status": "PENDING", "tx_id": tx.tx_id, "semester": semester}


@router.get("/tokens/redeem-addresses")
async def list_redeem_addresses(node: NodeState = Depends(get_node)):
    """Direcciones de canje registradas y lo quemado en cada una."""
    state = node.blockchain.contract_state("tokens")
    return {"redeem_addresses": [
        {"address": a, "label": label, "redeemed": state.redeemed.get(a, 0)}
        for a, label in state.redeem_addresses.items()]}


@router.post("/tokens/redeem-addresses", dependencies=[Depends(require_admin)])
async def register_redeem_address(request: RedeemAddressRequest, node: NodeState = Depends(get_node)):
    """Registra una dirección de canje (REDEEM_ADDRESS_REGISTER, firma la autoridad)."""
    authority = _require_authority(node)
    tx = create_redeem_address_transaction(
        authority.address, request.redeem_address, request.label,
        authority.private_key_hex, nonce=node.blockchain.next_nonce(authority.address))
    _submit_contract_tx(node, tx)
    return {"status": "PENDING", "tx_id": tx.tx_id}


@router.post("/tokens/award")
async def award_tokens(request: AwardRequest, node: NodeState = Depends(get_node)):
    """Premio del docente: TOKEN_MINT firmada por el emisor, dentro de su presupuesto."""
    tx = _signed(lambda: create_mint_transaction(
        request.issuer_address, request.recipient, request.amount, request.private_key_hex,
        nonce=node.blockchain.next_nonce(request.issuer_address), reason=request.reason))
    _submit_contract_tx(node, tx)
    return {"status": "PENDING", "tx_id": tx.tx_id, "nonce": tx.nonce}


def _parse_award_csv(text: str):
    """Filas ``(línea, dirección, monto, motivo)`` y errores ``{"row", "error"}``."""
    rows, errors = [], []
    reader = csv.DictReader(io.StringIO(text.strip()))
    if [f.strip() for f in (reader.fieldnames or [])][:3] != ["address", "amount", "reason"]:
        return [], [{"row": 1, "error": "el encabezado debe ser address,amount,reason"}]
    for line, row in enumerate(reader, start=2):
        address = (row.get("address") or "").strip()
        amount = (row.get("amount") or "").strip()
        reason = (row.get("reason") or "").strip()
        if not address:
            errors.append({"row": line, "error": "falta address"})
        elif not (amount.isascii() and amount.isdigit()) or int(amount) <= 0:
            errors.append({"row": line, "error": "amount debe ser un entero > 0"})
        elif not reason or len(reason) > MAX_REASON:
            errors.append({"row": line, "error": f"reason: texto de 1 a {MAX_REASON} caracteres"})
        else:
            rows.append((line, address, int(amount), reason))
    if not rows and not errors:
        errors.append({"row": 2, "error": "el CSV no tiene filas"})
    if len(rows) + len(errors) > MAX_CSV_ROWS:
        errors.append({"row": 0, "error": f"máximo {MAX_CSV_ROWS} filas por carga"})
    return rows, errors


@router.post("/tokens/award/csv")
async def award_tokens_csv(request: AwardCsvRequest, node: NodeState = Depends(get_node)):
    """Premios en lote: una TOKEN_MINT por fila, firmadas por el emisor.

    TODO O NADA: primero se simula el lote completo (formato, firma, presupuesto,
    con las filas anteriores ya contadas); si alguna fila falla, responde 400 con
    los errores por fila y no envía ninguna. Así, corregir el CSV y reenviarlo
    no duplica premios. Si el límite de TX por minuto (P1-5) corta el envío a
    mitad, la respuesta 429 lista las TX que sí entraron.
    """
    rows, errors = _parse_award_csv(request.csv)
    if errors:
        raise HTTPException(400, {"message": "CSV inválido; no se envió ninguna fila",
                                  "errors": errors})
    base_nonce = node.blockchain.next_nonce(request.issuer_address)
    txs = [_signed(lambda i=i, a=a, m=m, r=r: create_mint_transaction(
               request.issuer_address, a, m, request.private_key_hex,
               nonce=base_nonce + i, reason=r))
           for i, (_, a, m, r) in enumerate(rows)]
    errors = [{"row": row[0], "error": reason}
              for row, (ok, reason) in zip(rows, node.blockchain.check_batch(txs)) if not ok]
    if errors:
        raise HTTPException(400, {"message": "Hay filas inválidas; no se envió ninguna",
                                  "errors": errors})
    submitted = []
    for (line, *_), tx in zip(rows, txs):
        try:
            _submit_contract_tx(node, tx)
        except HTTPException as e:
            raise HTTPException(e.status_code, {
                "message": f"Envío interrumpido en la fila {line}: {e.detail}",
                "submitted": submitted})
        submitted.append({"row": line, "tx_id": tx.tx_id})
    return {"status": "PENDING", "count": len(submitted), "submitted": submitted}


@router.post("/tokens/redeem")
async def redeem_tokens(request: RedeemRequest, node: NodeState = Depends(get_node)):
    """Canje: TOKEN_REDEEM firmada por el estudiante; quema el monto en una dirección de canje."""
    tx = _signed(lambda: create_redeem_transaction(
        request.sender, request.redeem_address, request.amount, request.private_key_hex,
        nonce=node.blockchain.next_nonce(request.sender), item=request.item))
    _submit_contract_tx(node, tx)
    return {"status": "PENDING", "tx_id": tx.tx_id, "nonce": tx.nonce}


@router.get("/tokens/{address}")
async def get_token_balance(address: str, node: NodeState = Depends(get_node)):
    """Saldo de puntos de ``address`` y premios confirmados que recibió."""
    state = node.blockchain.contract_state("tokens")
    return {
        "address": address,
        "symbol": TOKEN_SYMBOL,
        "name": TOKEN_NAME,
        "balance": node.blockchain.get_balance(address),
        "awards": state.awards.get(address, []),
        "height": node.blockchain.contracts.height,
    }


@router.get("/issuers/{address}/budget")
async def get_issuer_budget(address: str, semester: Optional[str] = None, node: NodeState = Depends(get_node)):
    """Presupuesto de emisión de un emisor: el del semestre pedido (o el actual) y todos."""
    semester = semester or semester_of(time.time())
    if not is_semester(semester):
        raise HTTPException(400, "semester debe tener la forma AAAA-1 o AAAA-2")
    state = node.blockchain.contract_state("tokens")
    return {
        "address": address,
        "is_issuer": _credentials(node).is_registered_issuer(address),
        "semester": semester,
        "budget": state.budget_of(address, semester),
        "minted": state.minted_by(address, semester),
        "remaining": state.remaining(address, semester),
        "budgets": state.budgets.get(address, {}),
        "minted_by_semester": state.minted.get(address, {}),
        "symbol": TOKEN_SYMBOL,
    }


@router.post("/badges/award")
async def award_badge(request: BadgeRequest, node: NodeState = Depends(get_node)):
    """Otorga una insignia intransferible (BADGE_AWARD firmada por el emisor)."""
    tx = _signed(lambda: create_badge_award_transaction(
        request.issuer_address, request.recipient, request.badge_id, request.name,
        request.reason, request.private_key_hex,
        nonce=node.blockchain.next_nonce(request.issuer_address)))
    _submit_contract_tx(node, tx)
    return {"status": "PENDING", "tx_id": tx.tx_id, "nonce": tx.nonce}


@router.get("/badges/{address}")
async def get_badges(address: str, node: NodeState = Depends(get_node)):
    """Insignias confirmadas de ``address`` (intransferibles)."""
    badges = node.blockchain.contract_state("badges").badges_of(address)
    return {"address": address, "badges": list(badges.values()),
            "height": node.blockchain.contracts.height}


# ── Endpoints: credenciales ───────────────────────────────────────────────────

def _credentials(node: NodeState) -> CredentialState:
    """Estado confirmado del contrato de credenciales (P0-6, P1-13)."""
    return node.blockchain.contract_state("credentials")


def _submit_contract_tx(node: NodeState, tx: Transaction) -> None:
    """Admite una TX al mempool (límite por emisor, firma, cuentas y reglas del contrato) o lanza 400/429."""
    _enforce_tx_rate_limit(node, tx.sender)
    ok, reason = node.blockchain.add_transaction(tx)
    if not ok:
        raise HTTPException(400, reason)
    node.security_monitor.on_transaction(tx.to_dict())
    _screen_admitted_tx(node, tx)
    node.p2p.broadcast_transaction(tx.to_dict())


@router.post("/credentials/issuers", dependencies=[Depends(require_admin)])
async def register_issuer(request: RegisterIssuerRequest, node: NodeState = Depends(get_node)):
    """Registra un emisor con una TX ISSUER_REGISTER firmada por la autoridad (P0-6).

    Solo funciona en el nodo que tiene la llave de autoridad (AUTHORITY_KEY_FILE).
    Una TX ISSUER_REGISTER firmada por otra llave se rechaza (también vía /transactions).
    """
    if node.authority_wallet is None:
        raise HTTPException(503, "Este nodo no tiene la llave de autoridad configurada")
    tx = create_issuer_register_transaction(
        authority_address=node.authority_wallet.address,
        issuer_address=request.issuer_address,
        institution_code=request.institution_code,
        private_key_hex=node.authority_wallet.private_key_hex,
        nonce=node.blockchain.next_nonce(node.authority_wallet.address),
    )
    _submit_contract_tx(node, tx)
    return {"status": "PENDING", "tx_id": tx.tx_id}


@router.post("/credentials/issue")
async def issue_credential(request: CredentialRequest, node: NodeState = Depends(get_node)):
    """Emite una credencial: firma la TX y la pone en el mempool.

    No toca el estado confirmado: la credencial queda PENDING hasta que un
    bloque la incluya. El emisor debe estar registrado (confirmado o pendiente).
    """
    try:
        tx, registro = create_credential_transaction_with_record(
            issuer_address=request.issuer_address,
            student_address=request.student_address,
            credential_data=request.credential_data,
            private_key_hex=request.private_key_hex,
            nonce=node.blockchain.next_nonce(request.issuer_address),
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception:
        raise HTTPException(400, "Llave privada inválida")
    _submit_contract_tx(node, tx)

    data = request.credential_data
    credential_id = credential_id_of_tx(tx.to_dict())
    registro["credential_id"] = credential_id
    return {
        "credential_id": credential_id,
        "tx_id": tx.tx_id,
        "status": "PENDING",
        "fields_root": registro["fields_root"],
        # Registro privado (campos + sales): se entrega UNA sola vez y el nodo no lo guarda.
        # Quien lo pierda no puede revelar sus datos; la cadena solo tiene la raíz.
        "private_record": registro,
        "qr_data": json.dumps({
            "id": credential_id,
            "degree": data.get("degree"),
            "date": data.get("issue_date"),
            "verify_url": f"upbchain://verify/{credential_id}",
        }),
    }


class DisclosureRequest(BaseModel):
    private_record: dict
    fields: List[str]


class DiscloseVerifyRequest(BaseModel):
    revealed: List[dict]


@router.post("/credentials/disclosure")
async def build_disclosure(request: DisclosureRequest):
    """Arma un paquete de divulgación selectiva desde el registro privado (P1-2).

    Cómputo puro: no guarda nada ni toca la cadena. El estudiante entrega el
    paquete al verificador, que lo comprueba con ``POST /credentials/{id}/disclose-verify``.
    """
    rec = request.private_record
    try:
        if not isinstance(rec.get("fields"), dict) or not isinstance(rec.get("salts"), dict):
            raise ValueError("Registro privado inválido: faltan fields/salts")
        paquete = commitment.build_disclosure(rec, request.fields)
    except (ValueError, KeyError, TypeError) as e:
        raise HTTPException(400, str(e))
    if rec.get("credential_id"):
        paquete["credential_id"] = rec["credential_id"]
    return paquete


@router.post("/credentials/{credential_id}/disclose-verify")
async def disclose_verify(credential_id: str, request: DiscloseVerifyRequest, node: NodeState = Depends(get_node)):
    """Comprueba campos revelados (valor, sal, prueba Merkle) contra ``fields_root`` en cadena."""
    cred = _credentials(node).get(credential_id)
    if cred is None:
        raise HTTPException(404, "Credencial no confirmada en la cadena")
    resultados = [{"name": it.get("name"),
                   "verified": commitment.verify_field(cred.fields_root, it)}
                  for it in request.revealed]
    return {
        "credential_id": credential_id,
        "fields_root": cred.fields_root,
        "credential_status": _estado_publico(node, credential_id)["status"],
        "all_verified": bool(resultados) and all(r["verified"] for r in resultados),
        "fields": resultados,
    }


@router.post("/credentials/revoke")
async def revoke_credential(request: RevokeRequest, node: NodeState = Depends(get_node)):
    """Revoca una credencial con una TX CREDENTIAL_REVOKE firmada.

    Solo la acepta si la firma el emisor original o la autoridad del génesis.
    """
    try:
        tx = create_revoke_transaction(
            revoker_address=request.revoker_address,
            credential_id=request.credential_id,
            reason=request.reason,
            private_key_hex=request.private_key_hex,
            nonce=node.blockchain.next_nonce(request.revoker_address),
        )
    except Exception:
        raise HTTPException(400, "Llave privada inválida")
    _submit_contract_tx(node, tx)
    return {"tx_id": tx.tx_id, "status": "PENDING"}


@router.get("/credentials/verify/{credential_id}")
async def verify_credential(credential_id: str, node: NodeState = Depends(get_node)):
    """Estado de la credencial: PENDING, CONFIRMED (con bloque y confirmaciones),
    REVOKED, EXPIRED o NOT_FOUND. ``valid`` es true solo si está CONFIRMED."""
    return _credentials(node).credential_status(credential_id, node.blockchain.height,
                                            pending=node.blockchain.pending_dicts())


# ── Verificación pública por QR (P1-3) ────────────────────────────────────────

def _estado_publico(node: NodeState, credential_id: str) -> dict:
    """Misma lógica de estado que ``/credentials/verify/{id}`` (sin duplicarla)."""
    return _credentials(node).credential_status(credential_id, node.blockchain.height,
                                            pending=node.blockchain.pending_dicts())


def _url_verificacion(node: NodeState, request: Request, credential_id: str) -> str:
    """URL pública de la página de verificación (PUBLIC_BASE_URL o la del request)."""
    base = node.settings.public_base_url or str(request.base_url)
    return f"{base.rstrip('/')}/verify/{credential_id}"


@router.get("/credentials/{credential_id}/qr")
async def credential_qr(credential_id: str, request: Request, node: NodeState = Depends(get_node)):
    """PNG con un QR que apunta a la página pública ``/verify/{id}``."""
    if _estado_publico(node, credential_id)["status"] == "NOT_FOUND":
        raise HTTPException(404, "Credencial no encontrada")
    import qrcode
    img = qrcode.make(_url_verificacion(node, request, credential_id))
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


@router.get("/verify/{credential_id}", response_class=HTMLResponse)
async def verify_page(credential_id: str, node: NodeState = Depends(get_node)):
    """Página pública y móvil de verificación. No expone notas ni datos personales."""
    st = _estado_publico(node, credential_id)
    cred = st.get("credential") or {}
    campos = [("ID", credential_id), ("Emisor", cred.get("issuer_address")),
              ("Tipo", cred.get("credential_type")), ("Título", cred.get("degree")),
              ("Fecha de emisión", cred.get("issue_date")),
              ("Raíz del compromiso (datos personales)", cred.get("fields_root")),
              ("Bloque", st.get("block_index")),
              ("Confirmaciones", st.get("confirmations") if cred else None)]
    rows = "".join(f"<dt>{html.escape(k)}</dt><dd>{html.escape(str(v))}</dd>"
                   for k, v in campos if v is not None and v != "")
    body = _VERIFY_PAGE.format(
        color=_VERIFY_COLORS.get(st["status"], "#4b5563"),
        verdict=html.escape(st["verdict"]), reason=html.escape(st["reason"]), rows=rows)
    return HTMLResponse(body, status_code=404 if st["status"] == "NOT_FOUND" else 200)


@router.get("/credentials/issuer/{address}")
async def get_issuer_credentials(address: str, node: NodeState = Depends(get_node)):
    """Credenciales de un emisor (confirmadas y pendientes), solo resumen público."""
    pending, state = node.blockchain.pending_dicts(), _credentials(node)
    ids = state.issuer_credential_ids(address, pending=pending)
    items = [state.credential_summary(i, node.blockchain.height, pending=pending) for i in ids]
    return {"issuer_address": address, "count": len(items), "credentials": items}


@router.get("/credentials/{credential_id}/history")
async def credential_history(credential_id: str, node: NodeState = Depends(get_node)):
    """Historial: emitida en el bloque X, revocada en el bloque Y (derivado del contrato)."""
    r = _credentials(node).credential_summary(credential_id, node.blockchain.height,
                                          pending=node.blockchain.pending_dicts())
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


@router.get("/credentials/student/{address}")
async def get_student_credentials(address: str, node: NodeState = Depends(get_node)):
    return {"credentials": _credentials(node).get_student_credentials(address)}


@router.get("/credentials/search")
async def search_credentials(q: str, node: NodeState = Depends(get_node)):
    """Busca credenciales por título o programa (case-insensitive, substring).
    El nombre del estudiante ya no está en la cadena (P1-2).

    Query param:
        q: Término de búsqueda (mínimo 1 carácter).
    """
    if not q or not q.strip():
        raise HTTPException(400, "El parámetro 'q' no puede estar vacío")
    results = _credentials(node).search_credentials(q)
    return {"query": q, "count": len(results), "credentials": results}


@router.get("/credentials/all")
async def get_all_credentials(status: Optional[str] = None, node: NodeState = Depends(get_node)):
    """Retorna todas las credenciales registradas en el contrato.

    Query param:
        status: Filtro opcional de estado — ACTIVE | REVOKED | EXPIRED.
                Si se omite, retorna todas las credenciales.
    """
    credentials = _credentials(node).get_all_credentials(status_filter=status)
    return {
        "count": len(credentials),
        "status_filter": status,
        "credentials": credentials,
    }


# ── Endpoints: contratos (P1-13) ─────────────────────────────────────────────

@router.get("/contracts")
async def list_contracts(node: NodeState = Depends(get_node)):
    """Contratos que corre este nodo, en orden, con los tipos de TX que manejan."""
    registry = node.blockchain.contracts
    return {
        "height": registry.height,
        "contracts": [
            {"name": name,
             "handled_types": (None if registry.contract(name).HANDLED_TYPES is None
                               else sorted(registry.contract(name).HANDLED_TYPES))}
            for name in registry.names
        ],
    }


@router.get("/contracts/voting/{election_id}")
async def get_election(election_id: str, node: NodeState = Depends(get_node)):
    """Recuento de una elección del contrato de votación (votos confirmados).

    Para votar: ``POST /transactions`` con ``type=VOTE`` y payload
    ``{"election_id": ..., "choice": ...}``; un segundo voto de la misma
    dirección en la misma elección responde 400.
    """
    state = node.blockchain.contract_state("voting")
    votes = state.elections.get(election_id, {})
    pending = sum(1 for tx in node.blockchain.pending_dicts()
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
        "height": node.blockchain.contracts.height,
    }


# ── Endpoints: IA ─────────────────────────────────────────────────────────────

@router.get("/ai/analytics")
async def get_analytics(node: NodeState = Depends(get_node)):
    chain_data = [b.to_dict() for b in node.blockchain.chain]
    report = node.chain_analytics.analyze(chain_data)
    return report.to_dict()


@router.post("/ai/train", dependencies=[Depends(require_admin)])
async def train_anomaly_detector(node: NodeState = Depends(get_node)):
    all_txs = []
    for block in node.blockchain.chain:
        all_txs.extend(block.transactions)
    result = node.tx_anomaly_detector.train(all_txs)
    if result.get("trained"):
        node.tx_anomaly_detector.save(node.anomaly_model_path)
        result["model_path"] = str(node.anomaly_model_path)
    return result


@router.get("/ai/anomaly/stats")
async def anomaly_stats(node: NodeState = Depends(get_node)):
    return node.tx_anomaly_detector.get_stats()


# ── Endpoints: seguridad ──────────────────────────────────────────────────────

@router.get("/security/alerts")
async def get_alerts(level: Optional[str] = None, node: NodeState = Depends(get_node)):
    from security.monitor import AlertLevel
    lv = AlertLevel(level) if level else None
    return {"alerts": node.security_monitor.get_alerts(level=lv)}


@router.get("/security/threat-summary")
async def threat_summary(node: NodeState = Depends(get_node)):
    return node.security_monitor.get_threat_summary()


@router.get("/security/attack-simulation")
async def attack_simulation(node: NodeState = Depends(get_node)):
    return full_security_analysis(
        node_count=len(node.p2p.peers) + 1,
        honest_hash_rate=70.0,
        attacker_hash_rate=30.0,
    )


@router.get("/security/crypto-benchmark")
async def crypto_benchmark():
    return benchmark_crypto(iterations=5000)


@router.get("/security/hardening")
async def hardening_checklist():
    """Checklist de hardening en solo lectura (inspección de código, sin shell)."""
    return HardeningAuditor().run_audit()


@router.post("/security/eclipse-simulation")
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

@router.post("/wallet/generate")
async def generate_wallet():
    wallet = Wallet.generate()
    return {
        "address": wallet.address,
        "public_key": wallet.public_key_hex,
        "private_key": wallet.private_key_hex,
        "warning": "Guarda la llave privada en un lugar seguro. No se almacena en el servidor.",
    }


# ── Endpoints: red P2P ────────────────────────────────────────────────────────

@router.get("/network")
async def network_info(node: NodeState = Depends(get_node)):
    return node.p2p.get_network_stats()


@router.post("/network/peers", dependencies=[Depends(require_admin)])
def add_peer(host: str, port: int, node: NodeState = Depends(get_node)):
    # `def` (no async): el handshake es E/S bloqueante y FastAPI lo corre en un hilo.
    ok = node.p2p.connect_to_peer(host, port)
    return {"connected": ok}


@router.get("/network/sync")
async def sync_chain(node: NodeState = Depends(get_node)):
    return {"chain": [b.to_dict() for b in node.blockchain.chain], "height": node.blockchain.height}


@router.post("/network/sync", dependencies=[Depends(require_admin)])
def sync_now(node: NodeState = Depends(get_node)):
    """Fuerza la sincronización con todos los pares activos (P0-5)."""
    adopted = node.p2p.sync_with_peers()
    return {"adopted": adopted, "height": node.blockchain.height, "work": node.blockchain.total_work}


# ── Fábrica de la aplicación ──────────────────────────────────────────────────

def create_app(settings: Optional[Settings] = None,
               authority_address: Optional[str] = None) -> FastAPI:
    """Crea una app FastAPI con su propio ``NodeState`` (``app.state.node``).

    Sin ``settings`` los lee del entorno y de ``.env`` (``load_settings()``). Cada llamada
    abre su cadena en ``settings.data_dir`` y su socket P2P en ``settings.node_port``
    (al arrancar la app, no al crearla). ``authority_address`` (solo tests) sustituye la
    autoridad del génesis por otra cuya llave sí se tiene.
    """
    settings = settings or load_settings()
    configure_logging(settings.log_level)
    node = build_node(settings, authority_address)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        node.p2p.start()
        # Los pares de PEERS se conectan (y reconectan con backoff) en segundo plano.
        for peer in settings.peers:
            if ":" in peer:
                host, port = peer.rsplit(":", 1)
                node.p2p.add_peer(host, int(port))
        logger.info(f"UPB-Chain nodo {settings.node_id} iniciado")
        yield
        node.mining_stop.set()
        node.p2p.stop()
        logger.info("Nodo detenido")

    app = FastAPI(
        title="UPB-Chain API",
        description="Blockchain académica con IA para la Universidad Privada Boliviana",
        version="1.0.0",
        lifespan=lifespan,
    )
    app.state.node = node

    # CORS restringido (P1-9): por defecto solo el propio origen del nodo en localhost.
    cors_origins = settings.cors_origins or [
        f"http://localhost:{settings.api_port}", f"http://127.0.0.1:{settings.api_port}"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o for o in cors_origins if o != "*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    try:
        app.mount("/static", StaticFiles(directory="dashboard/static"), name="static")
    except Exception:
        pass
    app.include_router(router)
    return app


app = create_app()
