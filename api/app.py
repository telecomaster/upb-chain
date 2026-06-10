"""
API REST de UPB-Chain — FastAPI.
Expone endpoints para bloques, transacciones, credenciales, análisis y seguridad.
"""
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from blockchain.core.chain import Blockchain
from blockchain.core.transaction import Transaction, TransactionType, create_credential_transaction
from blockchain.core.wallet import Wallet
from blockchain.consensus.proof_of_work import ProofOfWork
from blockchain.consensus.pbft import PBFTNode
from blockchain.contracts.credential import CredentialContract
from blockchain.network.node import P2PNode
from ai.anomaly.detector import TransactionAnomalyDetector, BlockAnomalyDetector
from ai.analytics.chain_stats import ChainAnalytics
from security.monitor import SecurityMonitor
from security.attacks.simulator import full_security_analysis
from security.crypto_utils import generate_keypair, benchmark_crypto

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("upb_chain.api")

# ── Estado global de la aplicación ───────────────────────────────────────────

NODE_ID    = os.getenv("NODE_ID", "node_1")
NODE_HOST  = os.getenv("NODE_HOST", "0.0.0.0")
NODE_PORT  = int(os.getenv("NODE_PORT", "8001"))
API_PORT   = int(os.getenv("API_PORT", "8000"))
PEERS      = os.getenv("PEERS", "").split(",") if os.getenv("PEERS") else []

blockchain      = Blockchain(node_id=NODE_ID)
pow_engine      = ProofOfWork(difficulty=4)
credential_contract = CredentialContract()
tx_anomaly_detector = TransactionAnomalyDetector()
block_anomaly_detector = BlockAnomalyDetector()
chain_analytics = ChainAnalytics()
security_monitor = SecurityMonitor()

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
    on_new_block=lambda b: blockchain.add_block(__import__("blockchain.core.block", fromlist=["Block"]).Block.from_dict(b)),
    on_new_tx=lambda t: blockchain.add_transaction(Transaction.from_dict(t)),
    on_pbft_message=lambda m: logger.info(f"PBFT msg recibido: {m}"),
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    p2p.start()
    for peer in PEERS:
        if ":" in peer:
            host, port = peer.split(":")
            p2p.connect_to_peer(host, int(port))
    logger.info(f"UPB-Chain nodo {NODE_ID} iniciado")
    yield
    p2p.stop()
    logger.info("Nodo detenido")


app = FastAPI(
    title="UPB-Chain API",
    description="Blockchain académica con IA para la Universidad Privada Boliviana",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

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
    fee: float = 0.0


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


class PruneMempoolRequest(BaseModel):
    max_age_seconds: int = 3600


# ── Endpoints: información general ───────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    try:
        with open("dashboard/templates/index.html") as f:
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
    pow_stats = pow_engine.get_mining_stats()
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
    report = block_anomaly_detector.record_block(block.to_dict())
    return {**block.to_dict(), "anomaly": report.to_dict()}


@app.post("/blocks/mine")
async def mine_block(request: MineRequest, background_tasks: BackgroundTasks):
    candidate = blockchain.create_candidate_block()
    result = pow_engine.mine(candidate)
    if not result:
        raise HTTPException(500, "Mining falló o timeout alcanzado")
    ok, reason = blockchain.add_block(result.block)
    if not ok:
        raise HTTPException(400, reason)
    p2p.broadcast_block(result.block.to_dict())
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
    tx = Transaction(
        type=TransactionType(request.type),
        sender=request.sender,
        recipient=request.recipient,
        payload=request.payload,
        fee=request.fee,
    )
    if request.private_key_hex:
        tx.sign(request.private_key_hex)

    anomaly = tx_anomaly_detector.predict(tx.to_dict())
    security_monitor.on_transaction(tx.to_dict())

    ok, reason = blockchain.add_transaction(tx)
    if not ok:
        raise HTTPException(400, reason)

    p2p.broadcast_transaction(tx.to_dict())

    return {
        "tx_id": tx.tx_id,
        "status": "pending",
        "anomaly": anomaly.to_dict(),
    }


@app.get("/transactions/{tx_id}")
async def get_transaction(tx_id: str):
    tx = blockchain.get_transaction(tx_id)
    if not tx:
        raise HTTPException(404, "Transacción no encontrada")
    return tx


@app.get("/chain/balance/{address}")
async def get_address_balance(address: str):
    """Retorna el balance neto de fees de una dirección sobre todos los bloques confirmados.

    balance = Σ fees recibidas (recipient == address)
            − Σ fees pagadas   (sender    == address)
    """
    balance = blockchain.get_balance(address)
    total_fees = blockchain.total_fees
    return {
        "address": address,
        "balance": balance,
        "chain_total_fees": total_fees,
    }


@app.post("/mempool/prune")
async def prune_mempool(request: PruneMempoolRequest):
    """Elimina del mempool las transacciones más viejas que max_age_seconds."""
    pruned = blockchain.prune_mempool(request.max_age_seconds)
    return {
        "pruned": pruned,
        "remaining": len(blockchain.mempool),
        "max_age_seconds": request.max_age_seconds,
    }


# ── Endpoints: credenciales ───────────────────────────────────────────────────

@app.post("/credentials/issuers")
async def register_issuer(request: RegisterIssuerRequest):
    ok, reason = credential_contract.register_issuer(
        request.issuer_address, request.institution_code
    )
    if not ok:
        raise HTTPException(400, reason)
    return {"status": "registered"}


@app.post("/credentials/issue")
async def issue_credential(request: CredentialRequest):
    ok, reason, credential = credential_contract.issue_credential(
        request.issuer_address,
        request.student_address,
        request.credential_data,
    )
    if not ok:
        raise HTTPException(400, reason)

    tx = create_credential_transaction(
        issuer_address=request.issuer_address,
        student_address=request.student_address,
        credential_data=request.credential_data,
        private_key_hex=request.private_key_hex,
    )
    blockchain.add_transaction(tx)
    p2p.broadcast_transaction(tx.to_dict())

    return {
        "credential_id": credential.credential_id,
        "tx_id": tx.tx_id,
        "qr_data": credential.generate_qr_data(),
    }


@app.get("/credentials/verify/{credential_id}")
async def verify_credential(credential_id: str):
    ok, reason, data = credential_contract.verify_credential(credential_id)
    return {"valid": ok, "reason": reason, "credential": data}


@app.get("/credentials/student/{address}")
async def get_student_credentials(address: str):
    return {"credentials": credential_contract.get_student_credentials(address)}


@app.get("/credentials/search")
async def search_credentials(q: str):
    """Busca credenciales por nombre de estudiante o grado (case-insensitive, substring).

    Query param:
        q: Término de búsqueda (mínimo 1 carácter).
    """
    if not q or not q.strip():
        raise HTTPException(400, "El parámetro 'q' no puede estar vacío")
    results = credential_contract.search_credentials(q)
    return {"query": q, "count": len(results), "credentials": results}


@app.get("/credentials/all")
async def get_all_credentials(status: Optional[str] = None):
    """Retorna todas las credenciales registradas en el contrato.

    Query param:
        status: Filtro opcional de estado — ACTIVE | REVOKED | EXPIRED.
                Si se omite, retorna todas las credenciales.
    """
    credentials = credential_contract.get_all_credentials(status_filter=status)
    return {
        "count": len(credentials),
        "status_filter": status,
        "credentials": credentials,
    }


# ── Endpoints: IA ─────────────────────────────────────────────────────────────

@app.get("/ai/analytics")
async def get_analytics():
    chain_data = [b.to_dict() for b in blockchain.chain]
    report = chain_analytics.analyze(chain_data)
    return report.to_dict()


@app.post("/ai/train")
async def train_anomaly_detector():
    all_txs = []
    for block in blockchain.chain:
        all_txs.extend(block.transactions)
    result = tx_anomaly_detector.train(all_txs)
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


@app.post("/network/peers")
async def add_peer(host: str, port: int):
    ok = p2p.connect_to_peer(host, port)
    return {"connected": ok}


@app.get("/network/sync")
async def sync_chain():
    return {"chain": [b.to_dict() for b in blockchain.chain], "height": blockchain.height}
