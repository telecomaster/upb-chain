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
from collections import deque
import base64
import csv
import hashlib
import hmac
import html
import io
import json
import logging
import os
import secrets
import threading
import time
from urllib.parse import urlencode
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Literal, Optional, Union

from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi import FastAPI, APIRouter, HTTPException, Depends, BackgroundTasks, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, Response, StreamingResponse
from pydantic import BaseModel, Field, FiniteFloat, StrictInt

from config import ConfigError, Settings, load_settings, configure_logging
from api.metrics import EventCounters, CONTENT_TYPE as METRICS_CONTENT_TYPE, build_registry, render as render_metrics
from blockchain.anchoring import AnchorService, quien_ancla, responsable_pbft
from blockchain.core.chain import Blockchain
from blockchain.core.limits import check_tx_size
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
    create_catalog_item_transaction,
    create_award_rule_transaction,
    create_election_transaction,
    create_event_code_transaction,
)
from blockchain.core.wallet import Wallet, derive_address, public_key_from_private
from blockchain.consensus.proof_of_work import ProofOfWork
from blockchain.consensus.termico import FrenoTermico
from blockchain.consensus.pbft import PBFTConfigError, PBFTReplica, PBFTTransport, ReplicaSet
from blockchain.core.block import GENESIS_HASH
from blockchain.contracts.credential import CredentialState, credential_id_of_tx
from blockchain.contracts import vc_export
from blockchain.contracts import programs
from blockchain.vm import AsmError, assemble, disassemble
from blockchain.vm.asm import address_to_int, int_to_address
from blockchain.contracts.tokens import (
    MAX_CLAIMS, MAX_REASON, TOKEN_NAME, TOKEN_SYMBOL, is_semester, semester_of,
)
from blockchain.network.node import P2PNode, MSG_AI_FLAG, MSG_AI_SUMMARY
from ai.anomaly.detector import TransactionAnomalyDetector, BlockAnomalyDetector, TYPE_MAP
from ai.anomaly import federated as _fed
from ai.analytics.chain_stats import ChainAnalytics
from security.monitor import SecurityMonitor
from api.events import EventBus, sse_stream
from security.rate_limiter import TxRateLimiter
from security.attacks.simulator import full_security_analysis
from security.attacks.eclipse import EclipseAttack
from security.attacks.recompensas import (
    PUNTOS_POR_ESCENARIO, escenarios_premiables, validar_recibo, verificar_repitiendo)
from security.hardening import HardeningAuditor
from security.crypto_utils import generate_keypair, benchmark_crypto

logger = logging.getLogger("upb_chain.api")


def build_node_state(data_dir: str, node_id: str, authority_address: Optional[str] = None,
                     initial_difficulty: int = 4, revalidate_on_start: str = "fast",
                     snapshot_interval: int = 100, consensus: str = "pow",
                     replica_set: Optional[ReplicaSet] = None,
                     mempool_max: int = 5000, mempool_max_per_sender: int = 64) -> Blockchain:
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
                      snapshot_interval=snapshot_interval,
                      consensus=consensus, replica_set=replica_set,
                      mempool_max=mempool_max, mempool_max_per_sender=mempool_max_per_sender)


def load_replica_set(settings: Settings) -> ReplicaSet:
    """Lista de réplicas PBFT (P1-1) desde ``PBFT_REPLICAS_FILE``; ConfigError si falla."""
    try:
        rs = ReplicaSet.from_file(settings.pbft_replicas_file)
    except PBFTConfigError as e:
        raise ConfigError(f"Configuración inválida:\n  PBFT_REPLICAS_FILE: {e}") from None
    if rs.f == 0:
        logger.warning(f"PBFT con {rs.n} réplica(s): f = 0, no tolera ninguna falla "
                       f"(se necesitan 4 para f = 1)")
    return rs


def load_replica_key(settings: Settings, rs: ReplicaSet) -> Wallet:
    """Llave de firma de esta réplica; debe coincidir con su llave pública en la lista."""
    path = settings.pbft_key_file
    try:
        wallet = Wallet.load(path)
        public_key = public_key_from_private(wallet.private_key_hex)
    except FileNotFoundError:
        raise ConfigError(f"Configuración inválida:\n  PBFT_KEY_FILE: {path} no existe "
                          f"(crearla con scripts/crear_llave_replica.py)") from None
    except Exception as e:
        raise ConfigError(f"Configuración inválida:\n  PBFT_KEY_FILE: {path} ilegible: {e}") from None
    if public_key != rs.get(settings.node_id).public_key:
        raise ConfigError(f"Configuración inválida:\n  PBFT_KEY_FILE: la llave de {path} no es "
                          f"la registrada para {settings.node_id} en {settings.pbft_replicas_file}")
    return wallet


def load_p2p_tls(settings: Settings) -> Optional[dict]:
    """Rutas del certificado de este nodo si ``P2P_TLS=on`` (ConfigError si faltan archivos)."""
    if settings.p2p_tls != "on":
        return None
    d = Path(settings.p2p_tls_dir)
    rutas = {"ca": d / "ca.crt", "cert": d / f"{settings.node_id}.crt",
             "key": d / f"{settings.node_id}.key"}
    faltan = [str(r) for r in rutas.values() if not r.is_file()]
    if faltan:
        raise ConfigError("Configuración inválida:\n  P2P_TLS_DIR: faltan " + ", ".join(faltan)
                          + " (crearlos con scripts/crear_ca.py y scripts/emitir_cert_nodo.py)")
    return {k: str(v) for k, v in rutas.items()}


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
    p2p: P2PNode
    events: EventBus                   # P2-7: bus de eventos para GET /events
    counters: EventCounters = field(default_factory=EventCounters)   # P2-10
    _bloques_vistos: deque = field(default_factory=lambda: deque(maxlen=64))   # hashes ya vistos por el detector
    _bloques_vistos: deque = field(default_factory=lambda: deque(maxlen=64))   # hashes ya vistos por el detector
    # P1-1: en modo pbft, la lista de réplicas; ``pbft`` solo si este nodo es réplica
    # (un nodo pbft fuera de la lista es observador: verifica certificados, no vota).
    replica_set: Optional[ReplicaSet] = None
    pbft: Optional[PBFTReplica] = None
    pbft_transport: Optional[PBFTTransport] = None
    anchors: Optional[AnchorService] = None   # idea 3: anclaje público (None = apagado)
    federated: Optional[_fed.FederadoIA] = None   # idea 6: IA federada (None = apagada)

    # ── IA federada (idea 6): resúmenes y banderas entre nodos; no es consenso ──
    def federated_sync(self) -> dict:
        """Publica el resumen local a los pares activos. 409 si aún no hay modelo entrenado."""
        resumen = self.tx_anomaly_detector.federated_summary()
        if resumen is None:
            raise HTTPException(409, "Entrena el detector (POST /ai/train) antes de sincronizar")
        self.federated.set_local(resumen)
        enviados = self.p2p.broadcast_ai(MSG_AI_SUMMARY, {"node_id": self.settings.node_id, **resumen})
        return {"enviados": enviados, "resumen": resumen}

    def federated_send_summary(self, host: Optional[str] = None, port: int = 0) -> int:
        """Reenvía nuestro último resumen (sin reentrenar): a un par recién conectado o a todos.
        Lo llaman el handshake de un par nuevo y la repetición periódica por bloques."""
        fed = self.federated
        resumen = fed.local() if fed is not None else None
        if resumen is None:
            return 0
        data = {"node_id": self.settings.node_id, **resumen}
        if host is not None:
            return int(self.p2p.send_ai(host, port, MSG_AI_SUMMARY, data))
        return self.p2p.broadcast_ai(MSG_AI_SUMMARY, data)

    def federated_screen(self, tx: dict, report) -> None:
        """Marca la TX (IF local o puntaje federado) y difunde un AI_FLAG; alerta si k nodos coinciden."""
        fed = self.federated
        if fed is None:
            return
        z, top = 0.0, [e["caracteristica"] for e in report.explicacion if e.get("contribucion", 0) > 0]
        x = self.tx_anomaly_detector._matrix([[report.features[n] for n in TransactionAnomalyDetector.FEATURE_NAMES]])[0]
        res = fed.puntuar(list(x))
        if res is not None:
            z, det = res
            top = [d["caracteristica"] for d in det if d["z"] >= _fed.Z_UMBRAL] or top
        if not (report.is_anomaly or z >= _fed.Z_UMBRAL):
            return
        flag, alertas = fed.marcar_local(tx.get("tx_id", ""), tx.get("sender", ""), report.score, z, top)
        threading.Thread(target=self.p2p.broadcast_ai, args=(MSG_AI_FLAG, flag), daemon=True).start()
        for a in alertas:
            self.security_monitor.on_federated_anomaly(a, fed.k)

    def federated_peer_tx(self, tx: dict) -> None:
        """TX de un par ya admitida: la revisa el detector local para poder votar (sin alerta ANOMALY)."""
        if self.federated is None:
            return
        report = self.tx_anomaly_detector.predict(tx)
        self.tx_anomaly_detector.observe(tx)
        self.federated_screen(tx, report)

    def on_ai_message(self, tipo: str, origen: str, data: dict) -> None:
        fed = self.federated
        if fed is None:
            return
        if tipo == MSG_AI_SUMMARY:
            fed.recibir_resumen(origen, {k: v for k, v in data.items() if k != "node_id"})
        elif tipo == MSG_AI_FLAG:
            for a in fed.recibir_flag(origen, data):
                self.security_monitor.on_federated_anomaly(a, fed.k)

    def on_pbft_committed(self, block, certificate: dict) -> None:
        """Bloque confirmado por PBFT: aviso + el primario lo difunde con su certificado
        (los nodos observadores y las réplicas atrasadas lo agregan verificándolo)."""
        self.announce_block(block.to_dict())
        self.counters.inc("pbft_committed")
        if self.pbft is not None and self.pbft.primary == self.settings.node_id:
            threading.Thread(target=self.p2p.broadcast_block,
                             args=(block.to_dict(), certificate), daemon=True).start()

    def consensus_status(self) -> dict:
        """Estado para ``GET /consensus`` (P1-1)."""
        bc = self.blockchain
        if self.settings.consensus == "pow":
            return {"mode": "pow", "height": bc.height,
                    "difficulty_bits": bc._calculate_difficulty(), "work": bc.total_work}
        if self.pbft is not None:
            return self.pbft.status()
        rs = self.replica_set
        cert = bc.certificates.get(bc.height) if bc.height > 0 else None
        view = cert["view"] if cert else 0
        return {"mode": "pbft", "replica_id": None, "is_replica": False, "view": view,
                "primary": rs.primary(view), "n": rs.n, "f": rs.f, "quorum": rs.quorum,
                "last_committed_seq": bc.height,
                "replicas": [{"id": r.id, "address": r.address, "public_key": r.public_key,
                              "primary": r.id == rs.primary(view)}
                             for r in rs.replicas]}

    def announce_block(self, block: dict) -> None:
        """Bloque nuevo (propio o de un par): monitor + evento ``block``."""
        self.security_monitor.on_block(block)
        self._observar_bloque(block)
        header = block.get("header", {})
        cada = self.settings.federated_resync_blocks
        if (self.federated is not None and cada > 0 and header.get("index", 0) > 0
                and header["index"] % cada == 0):
            threading.Thread(target=self.federated_send_summary, daemon=True).start()
        if self.anchors is not None and block.get("hash"):
            self.anchors.on_block(header.get("index", 0), block["hash"],
                                  header.get("timestamp"))
        self.events.publish("block", {
            "index": header.get("index"), "hash": block.get("hash"),
            "tx_count": len(block.get("transactions", [])),
            "pending": len(self.blockchain.mempool)})

    _VENTANA_BLOQUE_S = 600.0   # bloques más viejos no alimentan el detector

    def _observar_bloque(self, block: dict) -> None:
        """Alimenta el detector de bloques una sola vez por bloque y alerta si es anómalo."""
        h = block.get("hash")
        if not h or h in self._bloques_vistos:
            return
        ts = block.get("header", {}).get("timestamp")
        viejo = isinstance(ts, (int, float)) and time.time() - ts > self._VENTANA_BLOQUE_S
        self._bloques_vistos.append(h)
        try:
            report = self.block_anomaly_detector.record_block(block)
        except Exception:
            logger.exception("Detector de bloques falló")
            return
        # Un bloque viejo (puesta al día) entra a la ventana pero no levanta alerta.
        if report.is_anomaly and not viejo:
            self.security_monitor.on_block_anomaly(report.to_dict())

    def announce_tx(self, tx: dict) -> None:
        """TX admitida al mempool: monitor + evento ``tx``."""
        self.security_monitor.on_transaction(tx)
        self.events.publish("tx", {"tx_id": tx.get("tx_id"),
                                   "pending": len(self.blockchain.mempool)})

    def on_chain_reorg(self, fork_height: int, dropped: list, added: list) -> None:
        """Reorganización -> alerta (profundidad = bloques propios descartados) y bloques nuevos."""
        if dropped:    # una puesta al día (nada descartado) no es una reorganización
            self.security_monitor.on_chain_reorg(len(dropped))
        # La ventana del detector mezclaría la rama descartada: se vacía y se realimenta.
        self.block_anomaly_detector.reset()
        self._bloques_vistos.clear()
        self.events.publish("reorg", {"fork_height": fork_height, "dropped": len(dropped),
                                      "added": len(added)})
        for block in added:
            self.announce_block(block.to_dict())


def build_node(settings: Settings, authority_address: Optional[str] = None) -> NodeState:
    """Construye el estado completo de un nodo a partir de ``settings`` (sin arrancar la red)."""
    node_id = settings.node_id
    replica_set = load_replica_set(settings) if settings.consensus == "pbft" else None
    replica_wallet = (load_replica_key(settings, replica_set)
                      if replica_set is not None and replica_set.get(node_id) else None)
    blockchain = build_node_state(
        settings.data_dir, node_id, authority_address=authority_address,
        initial_difficulty=settings.mining_difficulty,
        revalidate_on_start=settings.revalidate_on_start,
        snapshot_interval=settings.snapshot_interval,
        consensus=settings.consensus, replica_set=replica_set,
        mempool_max=settings.mempool_max,
        mempool_max_per_sender=settings.mempool_max_per_sender)
    authority_wallet = load_authority_wallet(
        settings.authority_key_file, blockchain.contracts.contract("accounts").authority_address)
    tx_anomaly_detector = TransactionAnomalyDetector()
    anomaly_model_path = Path(settings.data_dir) / "models" / "tx_iforest.joblib"
    if tx_anomaly_detector.load(anomaly_model_path):
        logger.info("Modelo de anomalías cargado de %s", anomaly_model_path)
    events = EventBus()
    security_monitor = SecurityMonitor(alert_callback=lambda a: events.publish("alert", a.to_dict()))
    security_monitor.TX_RATE_LIMIT = settings.tx_rate_limit   # atributo de instancia
    # P1-5: límite de admisión al mempool (política local, nunca regla de consenso).
    tx_rate_limiter = TxRateLimiter(limit=settings.tx_rate_limit,
                                    window=security_monitor.TX_RATE_WINDOW)
    p2p = P2PNode(
        node_id=node_id,
        host=settings.node_host,
        port=settings.node_port,
        advertise_host=settings.node_advertise_host or None,
        # P0-5: el nodo valida/añade bloques y TXs recibidos y, si un bloque no
        # extiende la punta, sincroniza con el emisor (replace_chain por trabajo).
        blockchain=blockchain,
        consensus=settings.consensus,
        on_pbft_message=lambda m: node.pbft.receive(m) if node.pbft is not None else None,
        # P1-5: bloques recibidos y aceptados, bloques inválidos y pares fuera de PEERS.
        on_new_block=lambda b: node.announce_block(b),
        # TXs de pares ya admitidas al mempool: feed en vivo y monitor (solo alertas).
        on_new_tx=lambda t: (node.announce_tx(t), node.federated_peer_tx(t)),
        on_ai_message=lambda tipo, origen, data: node.on_ai_message(tipo, origen, data),
        on_peer_connected=lambda h, p: node.federated_send_summary(h, p),
        on_invalid_block=security_monitor.on_invalid_block,
        on_unknown_peer=security_monitor.on_unknown_peer,
        known_peers=settings.peers,
        # P2-6: TLS mutuo y lista blanca (por defecto, en pbft, los ids de las réplicas).
        tls=load_p2p_tls(settings),
        sync_interval=settings.p2p_ping_interval,
        ping_timeout=settings.p2p_ping_timeout,
        ping_misses=settings.p2p_ping_misses,
        allowlist=settings.p2p_allowlist or ([r.id for r in replica_set.replicas]
                                             if replica_set is not None else []),
    )
    node = NodeState(
        settings=settings,
        blockchain=blockchain,
        authority_wallet=authority_wallet,
        # La dificultad NO vive aquí: la dicta Blockchain._calculate_difficulty() (P0-4).
        pow_engine=ProofOfWork(freno=(
            FrenoTermico(settings.thermal_soft_c, settings.thermal_hard_c, settings.thermal_min_duty)
            if settings.thermal_throttle == "on" else None)),
        mining_lock=asyncio.Lock(),
        mining_stop=threading.Event(),
        tx_anomaly_detector=tx_anomaly_detector,
        anomaly_model_path=anomaly_model_path,
        block_anomaly_detector=BlockAnomalyDetector(),
        chain_analytics=ChainAnalytics(),
        security_monitor=security_monitor,
        tx_rate_limiter=tx_rate_limiter,
        p2p=p2p,
        events=events,
        replica_set=replica_set,
    )
    if settings.anchor_interval > 0:
        resp = lambda index: True   # noqa: E731
        if settings.anchor_role == "never":
            resp = lambda index: False   # noqa: E731
        elif settings.anchor_role == "auto" and replica_set is not None:
            resp = responsable_pbft([r.id for r in replica_set.replicas], node_id,
                                    settings.anchor_interval)
        node.anchors = AnchorService(blockchain.store, settings.anchor_interval,
                                     settings.anchor_calendars,
                                     tip=lambda: node.blockchain.height, responsable=resp)
    if settings.federated_ai == "on":
        node.federated = _fed.FederadoIA(node_id, k=settings.federated_k, type_map=TYPE_MAP,
                                         model_version=TransactionAnomalyDetector.MODEL_VERSION)
        node.federated.set_local(tx_anomaly_detector.federated_summary())
    blockchain.add_reorg_listener(node.on_chain_reorg)
    blockchain.add_certified_conflict_listener(security_monitor.on_certified_conflict)
    if replica_wallet is not None:
        transport = PBFTTransport(p2p, replica_set, node_id)
        node.pbft_transport = transport
        node.pbft = PBFTReplica(
            node_id, replica_wallet.private_key_hex, replica_set, blockchain,
            transport.multicast,
            view_timeout=settings.pbft_view_timeout,
            batch_interval=settings.pbft_batch_interval,
            on_event=lambda fase, datos: events.publish("pbft_phase", datos),
            on_committed=node.on_pbft_committed,
            on_equivocation=security_monitor.on_pbft_equivocation,
            on_invalid_block=security_monitor.on_invalid_block,
            request_sync=p2p.sync_with_peers,
            send_to=transport.send_to,
        )
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
    node.federated_screen(tx.to_dict(), report)


def _enforce_tx_rate_limit(node: NodeState, sender: str) -> None:
    """429 (y alerta) si el emisor superó el límite de TX por minuto."""
    allowed, count = node.tx_rate_limiter.check(sender)
    if not allowed:
        node.security_monitor.on_tx_rate_limited(sender, count, node.tx_rate_limiter.limit)
        node.counters.inc("tx_rate_limited")
        raise HTTPException(429, f"Límite de {node.tx_rate_limiter.limit} TX por minuto excedido")


def _enforce_tx_size(node: NodeState, tx: Transaction) -> None:
    """413 si la TX serializada supera el tope de consenso ``MAX_TX_BYTES`` (P0-3)."""
    ok, reason = check_tx_size(tx.to_dict())
    if not ok:
        node.counters.inc("tx_rejected")
        raise HTTPException(413, reason)


def _admit_tx(node: NodeState, tx: Transaction):
    """``add_transaction`` contando admitidas/rechazadas para /metrics (P2-10).

    Una TX demasiado grande responde 413 (no 400) antes de tocar el mempool (P0-3).
    """
    _enforce_tx_size(node, tx)
    ok, reason = node.blockchain.add_transaction(tx)
    node.counters.inc("tx_admitted" if ok else "tx_rejected")
    return ok, reason


_HOSTS_LOCALES = {"127.0.0.1", "::1", "localhost", "testclient"}


def _host_de_cabecera(valor: str) -> str:
    """Nombre de host sin puerto, en minúsculas ('[::1]:8000' -> '::1')."""
    valor = valor.strip().lower()
    if valor.startswith("["):
        return valor[1:].split("]", 1)[0]
    return valor.rsplit(":", 1)[0] if valor.count(":") == 1 else valor


def _nombre_loopback(nombre: str) -> bool:
    return nombre in {"127.0.0.1", "localhost", "::1"}


def _origen_loopback(origen: str) -> bool:
    """``Origin`` http(s) cuyo host es loopback (``null`` y otros esquemas: no)."""
    esquema, sep, resto = origen.strip().lower().partition("://")
    if not sep or esquema not in ("http", "https"):
        return False
    return _nombre_loopback(_host_de_cabecera(resto.split("/", 1)[0]))


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
    # Sin llave, la IP de origen no basta: una página web abierta en el navegador del
    # propio nodo conecta desde loopback (CSRF) y con DNS rebinding llega con otro Host.
    if not _nombre_loopback(_host_de_cabecera(request.headers.get("host", ""))):
        raise HTTPException(403, "endpoint de administración: la cabecera Host debe ser local "
                                 "(127.0.0.1, localhost, [::1]) o definir ADMIN_API_KEY")
    origen = request.headers.get("origin")
    if origen is not None and not _origen_loopback(origen):
        raise HTTPException(403, "endpoint de administración: Origin no local rechazado "
                                 "(posible CSRF); defina ADMIN_API_KEY para uso remoto")


async def require_metrics_access(request: Request) -> None:
    """Acceso a /metrics (P2-10): libre con ``METRICS_PUBLIC=true``; si no, como ``require_admin``."""
    if request.app.state.node.settings.metrics_public:
        return
    await require_admin(request)


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
    # Entero o float TAL CUAL llegó: forma parte del tx_id firmado, y convertir 1700000000 en
    # 1700000000.0 cambiaría el JSON canónico (Date.now()/1000 es entero 1 vez cada 1000 ms).
    timestamp: Optional[Union[StrictInt, FiniteFloat]] = None


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


class EventCodeRequest(BaseModel):
    issuer_address: str
    private_key_hex: str               # llave del EMISOR (educativo; la firma real va en el navegador)
    amount: int = Field(gt=0)          # puntos por reclamo
    max_claims: int = Field(ge=1, le=MAX_CLAIMS)
    expires_height: Optional[int] = None   # por defecto, altura actual + 1000 bloques
    reason: str
    code_id: Optional[str] = None      # por defecto, uno aleatorio


class RedeemRequest(BaseModel):
    sender: str
    private_key_hex: str
    redeem_address: str
    amount: int = Field(gt=0)
    item: str = ""
    item_id: str = ""       # ítem del catálogo (P2-12): amount debe ser su precio


class CatalogItemRequest(BaseModel):
    item_id: str
    title: str
    price: int
    stock: int
    redeem_address: str


class AwardRuleRequest(BaseModel):
    rule_id: str
    credential_type: str
    issuer_address: str
    amount: int


class ElectionRequest(BaseModel):
    creator_address: str
    private_key_hex: str
    election_id: str
    options: list
    weight_rule: str
    start_height: int
    end_height: int
    badge_weights: Optional[dict] = None
    cap: Optional[int] = None
    title: Optional[str] = None
    eligible_credential_type: Optional[str] = None
    eligible_program: Optional[str] = None


class BadgeRequest(BaseModel):
    issuer_address: str
    private_key_hex: str
    recipient: str
    badge_id: str
    name: str
    reason: str


class PruneMempoolRequest(BaseModel):
    max_age_seconds: int = 3600


# P2-11: argumentos y storage aceptan enteros o direcciones "UPB…" (se pasan a entero).
VmWord = Union[int, str]


class VmDeployRequest(BaseModel):
    sender: str
    private_key_hex: str               # firma en el servidor: educativo, en desuso (P2-1)
    code: Optional[str] = None         # bytecode en hex…
    source: Optional[str] = None       # …o texto .upbasm (se ensambla en el servidor)
    storage: List[List[VmWord]] = []   # storage inicial [[clave, valor], …]
    gas_limit: Optional[int] = Field(None, gt=0)   # por defecto, el gas del despliegue
    gas_price: int = Field(programs.MIN_GAS_PRICE, ge=programs.MIN_GAS_PRICE)
    fee: int = Field(0, ge=0)


class VmCallRequest(BaseModel):
    sender: str
    private_key_hex: str               # firma en el servidor: educativo, en desuso (P2-1)
    contract: str
    args: List[VmWord] = []
    value: int = Field(0, ge=0)
    gas_limit: int = Field(5_000, gt=0)
    gas_price: int = Field(programs.MIN_GAS_PRICE, ge=programs.MIN_GAS_PRICE)
    fee: int = Field(0, ge=0)


class VmSimulateRequest(BaseModel):
    contract: Optional[str] = None     # contrato desplegado (usa su código, storage y saldo)…
    code: Optional[str] = None         # …o bytecode en hex…
    source: Optional[str] = None       # …o texto .upbasm
    storage: List[List[VmWord]] = []   # solo con code/source
    balance: int = Field(0, ge=0)      # solo con code/source
    caller: Optional[str] = None       # dirección UPB (por defecto, 0)
    args: List[VmWord] = []
    value: int = Field(0, ge=0)
    gas_limit: int = Field(5_000, gt=0)
    block_height: Optional[int] = Field(None, ge=0)   # por defecto, la del próximo bloque
    trace: bool = True


class VmAssembleRequest(BaseModel):
    source: str


# ── Endpoints: información general ───────────────────────────────────────────

@router.get("/", response_class=HTMLResponse)
async def root():
    try:
        with open("dashboard/templates/index.html", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "<h1>UPB-Chain API — <a href='/docs'>Documentación</a></h1>"


@router.get("/billetera", response_class=HTMLResponse)
async def billetera():
    """Billetera web del estudiante (P2-1): firma en el navegador, la llave no llega al servidor."""
    with open("dashboard/templates/billetera.html", encoding="utf-8") as f:
        return f.read()


@router.get("/health")
async def health(node: NodeState = Depends(get_node)):
    return {
        "status": "ok",
        "node_id": node.settings.node_id,
        "height": node.blockchain.height,
        "timestamp": time.time(),
        # Para scripts/verificar_red.py: deben coincidir en todos los nodos de la red.
        "genesis_hash": node.blockchain.chain[0].hash,
        "consensus": node.settings.consensus,
        "p2p_tls": node.settings.p2p_tls,
        # ¿Este nodo tiene la llave de la autoridad del génesis? (mint/emisores dan 503 sin ella)
        "authority_key_loaded": node.authority_wallet is not None,
        # Freno térmico local (idea 5): None si está apagado. No afecta al consenso.
        "thermal": node.pow_engine.freno.estado() if node.pow_engine.freno else None,
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
        "pbft": node.consensus_status() if node.settings.consensus == "pbft" else {"mode": "pow"},
    }


# ── Endpoints: bloques ────────────────────────────────────────────────────────

@router.get("/blocks")
async def get_blocks(page: int = 0, size: int = 10, order: Literal["asc", "desc"] = "asc",
                     node: NodeState = Depends(get_node)):
    """Bloques paginados. ``order=asc`` (por defecto): del génesis hacia la punta;
    ``order=desc``: el más reciente primero (lo que usa el dashboard)."""
    cadena = node.blockchain.chain
    start = page * size
    end = start + size
    if order == "desc":
        blocks = cadena[::-1][start:end]
    else:
        blocks = cadena[start:end]
    return {
        "blocks": [b.to_dict() for b in blocks],
        "total": len(node.blockchain.chain),
        "page": page,
        "size": size,
        "order": order,
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


def _progress_publisher(node: NodeState, difficulty: int, max_per_s: float = 2.0):
    """Callback de progreso del PoW (corre en el hilo de minado): ≤ 2 eventos por segundo."""
    ultimo = [0.0]

    def cb(nonce: int, elapsed: float) -> None:
        ahora = time.monotonic()
        if ahora - ultimo[0] < 1.0 / max_per_s:
            return
        ultimo[0] = ahora
        node.events.publish("mining_progress", {
            "attempts": nonce, "elapsed_s": round(elapsed, 3), "difficulty": difficulty,
            "hash_rate": round(nonce / elapsed) if elapsed > 0 else 0,
            "expected_attempts": 2 ** difficulty,
            **(node.pow_engine.freno.estado() if node.pow_engine.freno else {})})
    return cb


@router.get("/events")
async def events_stream(request: Request, node: NodeState = Depends(get_node)):
    """Flujo SSE de eventos del nodo (P2-7): block, tx, alert, reorg, mining_progress, mining_done.

    SSE y no WebSocket: el flujo es solo servidor -> navegador, EventSource reconecta solo y
    no hace falta protocolo ni dependencia extra."""
    return StreamingResponse(
        sse_stream(node.events, is_disconnected=request.is_disconnected),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.get("/metrics", dependencies=[Depends(require_metrics_access)])
async def metrics(request: Request):
    """Métricas en formato de exposición de Prometheus (se leen al momento del scrape)."""
    return Response(render_metrics(request.app.state.metrics_registry),
                    media_type=METRICS_CONTENT_TYPE)


@router.get("/consensus")
async def consensus_info(node: NodeState = Depends(get_node)):
    """Modo de consenso y, en PBFT, vista, primario, réplicas y última altura confirmada (P1-1)."""
    return node.consensus_status()


@router.post("/blocks/mine", dependencies=[Depends(require_admin)])
async def mine_block(request: MineRequest, background_tasks: BackgroundTasks, node: NodeState = Depends(get_node)):
    if node.settings.consensus == "pbft":
        raise HTTPException(409, "Modo PBFT: los bloques no se minan; el primario propone "
                                 "uno automáticamente cuando hay transacciones pendientes")
    if node.mining_lock.locked():
        raise HTTPException(409, "minado en curso")
    async with node.mining_lock:
        node.mining_stop.clear()
        candidate = node.blockchain.create_candidate_block()
        # La dificultad sale de la regla de la cadena, nunca de un valor fijo.
        difficulty = candidate.header.difficulty
        # El PoW corre en un thread para no bloquear el event loop.
        result = await asyncio.to_thread(
            node.pow_engine.mine, candidate, difficulty=difficulty, stop_event=node.mining_stop,
            on_progress=_progress_publisher(node, difficulty)
        )
        node.events.publish("mining_done", {
            "ok": result is not None, "difficulty": difficulty,
            **({"attempts": result.attempts, "time_s": result.time_elapsed,
                "hash_rate": result.hash_rate} if result else {})})
        if not result:
            raise HTTPException(500, "Mining falló, timeout o abortado")
        ok, reason = node.blockchain.add_block(result.block)
        if not ok:
            # Típico: llegó un bloque de un peer y la punta cambió durante el minado.
            node.security_monitor.on_invalid_block(reason, node.settings.node_id)
            raise HTTPException(409, f"Bloque minado ya no es válido: {reason}")
        node.announce_block(result.block.to_dict())
        node.counters.inc("blocks_mined")
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
    """Admite una TX. ADVERTENCIA: ``private_key_hex`` hace que el servidor firme; es solo
    educativo y está en desuso. Use la billetera web (/billetera) y envíe ``signature``,
    ``public_key``, ``nonce`` y ``timestamp`` firmados en el cliente (P2-1)."""
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

    _enforce_tx_size(node, tx)          # antes del detector: no analizar payloads enormes
    _enforce_tx_rate_limit(node, tx.sender)
    anomaly = node.tx_anomaly_detector.predict(tx.to_dict())
    node.security_monitor.on_transaction(tx.to_dict())

    ok, reason = _admit_tx(node, tx)
    if not ok:
        raise HTTPException(400, reason)
    node.events.publish("tx", {"tx_id": tx.tx_id, "pending": len(node.blockchain.mempool)})

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
        raise HTTPException(503, _sin_autoridad(node))
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
    """Transfiere tokens (TOKEN_TRANSFER). 400 si falta saldo para amount + fee.

    ADVERTENCIA: recibe ``private_key_hex`` (firma en el servidor, solo educativo, en desuso);
    para uso real firme en el navegador con /billetera y use POST /transactions."""
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


def _sin_autoridad(node: NodeState) -> str:
    """Mensaje 503 que distingue llave ausente de llave que no es la del génesis."""
    base = "Este nodo no tiene la llave de autoridad configurada"
    ruta = node.settings.authority_key_file
    if Path(ruta).exists():
        return (f"{base}: {ruta} existe pero no corresponde a la dirección de autoridad "
                "del génesis (GENESIS_AUTHORITY_ADDRESS)")
    return f"{base} ({ruta} no existe)"


def _require_authority(node: NodeState) -> Wallet:
    if node.authority_wallet is None:
        raise HTTPException(503, _sin_autoridad(node))
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


def _direccion_valida(address: str) -> bool:
    """¿Es una dirección UPB canónica (``UPB`` + 32 hex en mayúsculas, la de ``derive_address``)?

    Reusa ``address_to_int`` / ``int_to_address`` (blockchain/vm/asm.py): la forma canónica
    evita que una variante en minúsculas sea otra cuenta que nadie controla.
    """
    try:
        return int_to_address(address_to_int(address)) == address
    except ValueError:
        return False


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
        elif not _direccion_valida(address):
            errors.append({"row": line, "error": "address no es una dirección UPB válida (UPB + 32 hex)"})
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


# ── Códigos QR de evento de un solo uso (P1-12) ──────────────────────────────

def _llave_cruda(private_key_hex: str) -> str:
    """Escalar secp256k1 (64 hex) de una llave privada DER: lo que lleva el QR y usa la billetera."""
    from cryptography.hazmat.primitives import serialization
    key = serialization.load_der_private_key(bytes.fromhex(private_key_hex), password=None)
    return f"{key.private_numbers().private_value:064x}"


@router.post("/tokens/event-codes")
async def create_event_code(request: EventCodeRequest, http: Request,
                            node: NodeState = Depends(get_node)):
    """Crea un código de evento (EVENT_CODE_CREATE firmada por el emisor, educativo).

    Genera la llave EFÍMERA del evento: la privada va en el QR (``claim_url``), la pública
    en la TX. Quien escanee el QR firma con ella el reclamo ligado a SU dirección. La llave
    del evento solo se devuelve aquí; el nodo no la guarda.
    """
    import qrcode
    event_key = Wallet.generate()
    code_id = request.code_id or "EV-" + secrets.token_hex(4)
    height = node.blockchain.contracts.height
    expires = request.expires_height if request.expires_height is not None else height + 1000
    tx = _signed(lambda: create_event_code_transaction(
        request.issuer_address, code_id, event_key.public_key_hex, request.amount,
        request.max_claims, expires, request.reason, request.private_key_hex,
        nonce=node.blockchain.next_nonce(request.issuer_address)))
    _submit_contract_tx(node, tx)
    base = (node.settings.public_base_url or str(http.base_url)).rstrip("/")
    secreto = _llave_cruda(event_key.private_key_hex)
    claim_url = f"{base}/billetera?{urlencode({'evento': code_id, 'k': secreto})}"
    buf = io.BytesIO()
    qrcode.make(claim_url).save(buf, format="PNG")
    return {"status": "PENDING", "tx_id": tx.tx_id, "code_id": code_id,
            "event_private_key": secreto, "event_pubkey": event_key.public_key_hex,
            "expires_height": expires, "claim_url": claim_url,
            "qr_png_base64": base64.b64encode(buf.getvalue()).decode("ascii")}


@router.get("/tokens/event-codes/{code_id}")
async def get_event_code(code_id: str, node: NodeState = Depends(get_node)):
    """Estado confirmado de un código de evento: reclamos usados, vencimiento y vigencia."""
    code = node.blockchain.contract_state("tokens").event_codes.get(code_id)
    if code is None:
        raise HTTPException(404, "Código de evento no encontrado (o aún sin confirmar)")
    height = node.blockchain.contracts.height
    used = len(code["claimed_by"])
    estado = ("EXHAUSTED" if used >= code["max_claims"]
              else "EXPIRED" if height >= code["expires_height"] else "OPEN")
    return {"code_id": code_id, "issuer": code["issuer"], "amount": code["amount"],
            "max_claims": code["max_claims"], "claims_used": used,
            "claims_left": code["max_claims"] - used, "expires_height": code["expires_height"],
            "height": height, "status": estado, "reason": code["reason"],
            "symbol": TOKEN_SYMBOL, "genesis_hash": GENESIS_HASH}


@router.post("/tokens/redeem")
async def redeem_tokens(request: RedeemRequest, node: NodeState = Depends(get_node)):
    """Canje: TOKEN_REDEEM firmada por el estudiante; quema el monto en una dirección de canje."""
    tx = _signed(lambda: create_redeem_transaction(
        request.sender, request.redeem_address, request.amount, request.private_key_hex,
        nonce=node.blockchain.next_nonce(request.sender), item=request.item,
        item_id=request.item_id))
    _submit_contract_tx(node, tx)
    return {"status": "PENDING", "tx_id": tx.tx_id, "nonce": tx.nonce}


# ── Catálogo de canjes, premios automáticos y elecciones (P2-12) ──────────────

@router.get("/catalog")
async def list_catalog(node: NodeState = Depends(get_node)):
    """Ítems canjeables confirmados (precio, stock y dirección de canje)."""
    state = node.blockchain.contract_state("tokens")
    return {"items": list(state.catalog.values()), "symbol": TOKEN_SYMBOL,
            "height": node.blockchain.contracts.height}


@router.post("/catalog", dependencies=[Depends(require_admin)])
async def publish_catalog_item(request: CatalogItemRequest, node: NodeState = Depends(get_node)):
    """Publica un ítem del catálogo (CATALOG_ITEM, firma la autoridad)."""
    authority = _require_authority(node)
    tx = create_catalog_item_transaction(
        authority.address, request.item_id, request.title, request.price, request.stock,
        request.redeem_address, authority.private_key_hex,
        nonce=node.blockchain.next_nonce(authority.address))
    _submit_contract_tx(node, tx)
    return {"status": "PENDING", "tx_id": tx.tx_id}


@router.get("/catalog/receipts/{address}")
async def get_receipts(address: str, node: NodeState = Depends(get_node)):
    """Recibos de canje del catálogo de ``address`` (id derivado del tx_id)."""
    state = node.blockchain.contract_state("tokens")
    return {"address": address,
            "receipts": [r for r in state.receipts.values() if r["buyer"] == address]}


@router.get("/tokens/award-rules")
async def list_award_rules(node: NodeState = Depends(get_node)):
    """Reglas de premio automático al emitir credenciales."""
    return {"rules": list(node.blockchain.contract_state("tokens").rules.values()),
            "symbol": TOKEN_SYMBOL}


@router.post("/tokens/award-rules", dependencies=[Depends(require_admin)])
async def create_award_rule(request: AwardRuleRequest, node: NodeState = Depends(get_node)):
    """Crea una regla de premio automático (AWARD_RULE, firma la autoridad)."""
    authority = _require_authority(node)
    tx = create_award_rule_transaction(
        authority.address, request.rule_id, request.credential_type, request.issuer_address,
        request.amount, authority.private_key_hex,
        nonce=node.blockchain.next_nonce(authority.address))
    _submit_contract_tx(node, tx)
    return {"status": "PENDING", "tx_id": tx.tx_id}


def _estado_eleccion(config: dict, height: int) -> str:
    """pending / open / closed según la altura CONFIRMADA (el próximo bloque es height + 1)."""
    if height >= config["end_height"]:
        return "closed"
    return "open" if height + 1 >= config["start_height"] else "pending"


def _resumen_eleccion(node: NodeState, eid: str, config: dict, state, height: int) -> dict:
    estado = _estado_eleccion(config, height)
    votos = state.elections.get(eid, {})
    out = {**{k: v for k, v in config.items() if k != "snapshot"},
           "status": estado, "open": estado == "open", "height": height,
           "tally": state.tally(eid), "total_votes": len(votos),
           "turnout": {"voters": len(votos), "total_weight": sum(state.weights.get(eid, {}).values())},
           "final": estado == "closed"}
    return out


@router.get("/elections")
async def list_elections(node: NodeState = Depends(get_node)):
    """Elecciones configuradas con estado (pending/open/closed), recuento y participación."""
    state = node.blockchain.contract_state("voting")
    height = node.blockchain.contracts.height
    return {"height": height, "elections": [
        _resumen_eleccion(node, eid, c, state, height) for eid, c in state.configs.items()]}


@router.get("/elections/{election_id}")
async def get_election_results(election_id: str, node: NodeState = Depends(get_node)):
    """Una elección; si está cerrada, resultado final con certificación verificable.

    El recuento solo es definitivo cuando ya existe el bloque ``end_height``. La
    certificación liga el recuento al hash de ese bloque de cierre: cualquiera puede
    recalcular el digest con los votos de la cadena. Los votos son PÚBLICOS en la cadena.
    """
    state = node.blockchain.contract_state("voting")
    config = state.configs.get(election_id)
    if config is None:
        raise HTTPException(404, "Elección no encontrada")
    height = node.blockchain.contracts.height
    out = _resumen_eleccion(node, election_id, config, state, height)
    if not out["final"]:
        out["tally"] = None        # parcial: no se publica como resultado hasta el cierre
        out["certification"] = None
        return out
    cierre = node.blockchain.chain[config["end_height"]]
    resultado = {"election_id": election_id, "tally": state.tally(election_id),
                 "voters": len(state.elections.get(election_id, {})),
                 "close_height": config["end_height"], "close_block_hash": cierre.hash}
    digest = hashlib.sha256(json.dumps(resultado, sort_keys=True,
                                       separators=(",", ":")).encode("utf-8")).hexdigest()
    out["certification"] = {**resultado, "digest": digest}
    return out


@router.post("/elections")
async def create_election(request: ElectionRequest, node: NodeState = Depends(get_node)):
    """Crea una elección (ELECTION_CREATE firmada por la autoridad o un emisor registrado)."""
    tx = _signed(lambda: create_election_transaction(
        request.creator_address, request.election_id, request.options, request.weight_rule,
        request.start_height, request.end_height, request.private_key_hex,
        nonce=node.blockchain.next_nonce(request.creator_address),
        badge_weights=request.badge_weights, cap=request.cap, title=request.title,
        eligible_credential_type=request.eligible_credential_type,
        eligible_program=request.eligible_program))
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


class LabRewardRequest(BaseModel):
    issuer_address: str
    private_key_hex: str               # llave del EMISOR (docente); el laboratorio no tiene ninguna
    recibo: dict                       # salida de scripts/laboratorio_ataques.py --direccion ...


_lab_lock = threading.Lock()           # el laboratorio usa puertos y nodos: una corrida a la vez


@router.get("/laboratorio/recompensas")
async def lab_rewards_info():
    """Escenarios del laboratorio que dan recompensa y cuánto (P1-12)."""
    return {"escenarios": escenarios_premiables(), "puntos": PUNTOS_POR_ESCENARIO,
            "symbol": TOKEN_SYMBOL}


@router.post("/laboratorio/recompensas", dependencies=[Depends(require_admin)])
async def lab_reward(request: LabRewardRequest, node: NodeState = Depends(get_node)):
    """Recompensa por completar un escenario del laboratorio (P1-12).

    Vuelve a correr el escenario del recibo (no confía en él) y, si el logro se cumple, el emisor
    firma una insignia ``lab-<escenario>`` y ``PUNTOS_POR_ESCENARIO`` PUPB (``laboratorio:<escenario>``).
    Una sola vez por dirección y escenario (unicidad de la insignia).
    """
    recibo = request.recibo
    motivo = validar_recibo(recibo)
    if motivo:
        raise HTTPException(400, motivo)
    student, escenario = recibo["direccion"], recibo["escenario"]
    if not _direccion_valida(student):
        raise HTTPException(400, "la dirección del recibo no es una dirección UPB válida")
    badge_id = f"lab-{escenario}"
    if node.blockchain.contract_state("badges").has_badge(student, badge_id):
        raise HTTPException(409, f"la dirección ya recibió la recompensa {badge_id}")
    restante = node.blockchain.contract_state("tokens").remaining(
        request.issuer_address, semester_of(time.time()))
    if restante < PUNTOS_POR_ESCENARIO:
        raise HTTPException(400, "el emisor no tiene presupuesto suficiente en el semestre")
    if not _lab_lock.acquire(blocking=False):
        raise HTTPException(429, "ya hay una corrida del laboratorio en curso; reintente")
    try:
        cumplido = await asyncio.to_thread(verificar_repitiendo, recibo)
    finally:
        _lab_lock.release()
    if not cumplido:
        raise HTTPException(400, "al repetir el escenario no se cumplió el logro")
    # Insignia primero: si es duplicada (incluso pendiente en el mempool) se rechaza antes de
    # acuñar, así no se pueden cobrar puntos dos veces por el mismo escenario.
    badge = _signed(lambda: create_badge_award_transaction(
        request.issuer_address, student, badge_id, f"Laboratorio: {escenario}",
        f"laboratorio:{escenario}", request.private_key_hex,
        nonce=node.blockchain.next_nonce(request.issuer_address)))
    _submit_contract_tx(node, badge)
    mint = _signed(lambda: create_mint_transaction(
        request.issuer_address, student, PUNTOS_POR_ESCENARIO, request.private_key_hex,
        nonce=node.blockchain.next_nonce(request.issuer_address),
        reason=f"laboratorio:{escenario}"))
    _submit_contract_tx(node, mint)
    return {"status": "PENDING", "badge_tx_id": badge.tx_id, "mint_tx_id": mint.tx_id,
            "badge_id": badge_id, "amount": PUNTOS_POR_ESCENARIO}


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
    ok, reason = _admit_tx(node, tx)
    if not ok:
        raise HTTPException(400, reason)
    node.announce_tx(tx.to_dict())
    _screen_admitted_tx(node, tx)
    node.p2p.broadcast_transaction(tx.to_dict())


@router.post("/credentials/issuers", dependencies=[Depends(require_admin)])
async def register_issuer(request: RegisterIssuerRequest, node: NodeState = Depends(get_node)):
    """Registra un emisor con una TX ISSUER_REGISTER firmada por la autoridad (P0-6).

    Solo funciona en el nodo que tiene la llave de autoridad (AUTHORITY_KEY_FILE).
    Una TX ISSUER_REGISTER firmada por otra llave se rechaza (también vía /transactions).
    """
    if node.authority_wallet is None:
        raise HTTPException(503, _sin_autoridad(node))
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
async def issue_credential(request: CredentialRequest, http: Request, node: NodeState = Depends(get_node)):
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
        "verify_url": _url_verificacion(node, http, credential_id),
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


# ── Verifiable Credentials y did:web (P2-3) ───────────────────────────────────

def _vc_dominio(node: NodeState, request: Request) -> str:
    s = node.settings
    return vc_export.did_domain(s.did_web_domain, s.public_base_url, str(request.base_url))


def _vc_base(node: NodeState, request: Request) -> str:
    return (node.settings.public_base_url or str(request.base_url)).rstrip("/")


@router.get("/.well-known/did.json")
async def did_document(request: Request, node: NodeState = Depends(get_node)):
    """Documento did:web de la UPB con las llaves de la autoridad y los emisores (P2-3).

    Solo aparecen llaves públicas que la cadena ya conoce (las de TXs firmadas).
    did:web exige servirlo por HTTPS en el dominio: lo dispone el despliegue.
    """
    claves = vc_export.public_keys_from_blocks(node.blockchain.chain)
    autoridad = node.blockchain.contracts.contract("accounts").authority_address
    doc = vc_export.build_did_document(_vc_dominio(node, request), claves, autoridad,
                                       _credentials(node).issuers())
    return Response(content=json.dumps(doc), media_type="application/did+ld+json")


def _vc_ancla(node: NodeState, cred) -> dict:
    found = node.blockchain.locate_transaction(cred.tx_hash)
    if found is None:
        raise HTTPException(404, "Credencial sin ancla en la cadena")
    block, i = found
    hojas = [leaf_hash(t) for t in block.transactions]
    return {"tx_id": cred.tx_hash, "block_index": block.header.index, "block_hash": block.hash,
            "merkle_root": block.header.merkle_root, "leaf": hojas[i], "proof": build_proof(hojas, i)}


def _vc_de(node: NodeState, request: Request, credential_id: str, disclosure=None) -> dict:
    cred = _credentials(node).get(credential_id)
    if cred is None:
        raise HTTPException(404, "Credencial no confirmada en la cadena")
    return vc_export.build_vc(_vc_dominio(node, request), _vc_base(node, request), cred.to_dict(),
                              _estado_publico(node, credential_id), _vc_ancla(node, cred),
                              disclosure=disclosure)


@router.get("/credentials/{credential_id}/vc")
async def credential_vc(credential_id: str, request: Request, node: NodeState = Depends(get_node)):
    """VC (alineada con VC 2.0 / Open Badges 3.0) sin ``proof`` propio y con el ancla en cadena."""
    return _vc_de(node, request, credential_id)


@router.post("/credentials/{credential_id}/vc/disclose")
async def credential_vc_disclose(credential_id: str, body: DisclosureRequest, request: Request,
                                 node: NodeState = Depends(get_node)):
    """VC con divulgación selectiva: campos privados elegidos con su sal y prueba Merkle."""
    cred = _credentials(node).get(credential_id)
    if cred is None:
        raise HTTPException(404, "Credencial no confirmada en la cadena")
    try:
        paquete = commitment.build_disclosure(body.private_record, body.fields)
    except (ValueError, KeyError, TypeError) as e:
        raise HTTPException(400, f"Registro privado inválido: {e}")
    if paquete["fields_root"] != cred.fields_root:
        raise HTTPException(400, "El registro privado no coincide con el fields_root en cadena")
    return _vc_de(node, request, credential_id, disclosure=paquete)


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
    node.counters.inc("verificaciones_locales")
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
    node.counters.inc("verificaciones_locales")
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
    motivo = st["reason"]
    if st.get("pending_revocation"):
        # La revocación ya está en el mempool: el empleador debe saberlo antes de que se mine.
        motivo += ". ⚠ Revocación pendiente de minado: el emisor ya pidió revocarla."
    body = _VERIFY_PAGE.format(
        color=_VERIFY_COLORS.get(st["status"], "#4b5563"),
        verdict=html.escape(st["verdict"]), reason=html.escape(motivo), rows=rows)
    return HTMLResponse(body, status_code=404 if st["status"] == "NOT_FOUND" else 200)


# ── Kiosco verificador (idea 4) ───────────────────────────────────────────────

@router.get("/anchors")
async def list_anchors(from_block: int = 0, include_orphaned: bool = False,
                       node: NodeState = Depends(get_node)):
    """Anclajes públicos (OpenTimestamps) desde ``from_block``; un elemento por bloque."""
    if node.anchors is None:
        return {"enabled": False, "anchors": []}
    rs = node.replica_set
    lista = node.anchors.listado(from_block, include_orphaned)
    if rs is not None and node.settings.anchor_role == "auto":
        ids = [r.id for r in rs.replicas]
        for a in lista:   # qué réplica ancla ese bloque (los demás nodos no tienen el .ots)
            a["anchored_by"] = quien_ancla(ids, a["block_index"], node.anchors.interval)
    return {"enabled": True, "interval": node.anchors.interval,
            "role": node.settings.anchor_role, "anchors": lista}


@router.get("/anchors/{block_index}.ots")
async def download_anchor(block_index: int, node: NodeState = Depends(get_node)):
    """Descarga el .ots del bloque anclado (verificar con el cliente oficial ``ots``)."""
    bc = node.blockchain
    if node.anchors is None or not 0 <= block_index <= bc.height:
        raise HTTPException(404, "Sin anclaje para ese bloque")
    ots = node.anchors.ots_de_bloque(block_index, bc.chain[block_index].hash)
    if ots is None:
        raise HTTPException(404, "Sin anclaje para ese bloque")
    return Response(ots, media_type="application/octet-stream", headers={
        "Content-Disposition": f'attachment; filename="bloque-{block_index}.ots"'})


@router.get("/kiosco", response_class=HTMLResponse)
@router.get("/kiosco/{credential_id}", response_class=HTMLResponse)
async def kiosco(credential_id: str = ""):
    """Página de pantalla completa para un kiosco: la prueba Merkle se verifica en el navegador."""
    with open("dashboard/templates/kiosco.html", encoding="utf-8") as f:
        return f.read().replace("__ID__", html.escape(credential_id, quote=True))


@router.get("/blocks/{index}/certificate")
async def block_certificate(index: int, node: NodeState = Depends(get_node)):
    """Certificado PBFT del bloque: firmantes distintos y los COMMIT firmados (para que un
    cliente, como el kiosco o ``verificar_prueba.py``, compruebe las firmas por su cuenta)."""
    cert = node.blockchain.certificates.get(index)
    if cert is None:
        raise HTTPException(404, "Sin certificado para ese bloque")
    commits = cert.get("commits") or []
    return {"index": index, "view": cert.get("view"), "digest": cert.get("digest"),
            "seq": cert.get("seq"), "signers": len({m.get("replica") for m in commits}),
            "commits": commits}


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
    if not votes and not pending and election_id not in state.configs:
        raise HTTPException(404, "Elección sin votos")
    config = state.configs.get(election_id)
    return {
        "election_id": election_id,
        "total_votes": len(votes),
        "tally": state.tally(election_id),     # ponderado si la elección tiene configuración
        "weighted": config is not None,
        "config": ({k: v for k, v in config.items() if k != "snapshot"} if config else None),
        "weights": state.weights.get(election_id, {}),
        "voters": list(votes),
        "pending_votes": pending,
        "height": node.blockchain.contracts.height,
    }


# ── Endpoints: contratos de estudiantes sobre la VM de pila (P2-11) ──────────
# Desplegar y llamar con ``private_key_hex`` firma en el servidor (educativo, en
# desuso como en P2-1): para uso real, firmar en el cliente y usar POST /transactions
# con type CONTRACT_DEPLOY/CONTRACT_CALL (ver docs/vm.md).

_VM_WARNING = ("Firma en el servidor con private_key_hex: solo educativo y en desuso (P2-1). "
               "Firme en el cliente y use POST /transactions.")


def _vm_word(value: VmWord) -> int:
    """Entero de 256 bits o dirección UPB → entero; 400 si no sirve."""
    try:
        word = address_to_int(value) if isinstance(value, str) else value
    except ValueError as e:
        raise HTTPException(400, str(e))
    if not 0 <= word < 1 << 256:
        raise HTTPException(400, f"{value} no cabe en 256 bits sin signo")
    return word


def _vm_storage(pairs: List[List[VmWord]]) -> List[List[int]]:
    if any(len(p) != 2 for p in pairs):
        raise HTTPException(400, "storage: cada elemento es [clave, valor]")
    return [[_vm_word(k), _vm_word(v)] for k, v in pairs]


def _vm_code(code: Optional[str], source: Optional[str]) -> str:
    """Bytecode hex desde ``code`` o ``source`` (exactamente uno); 400 si no ensambla."""
    if (code is None) == (source is None):
        raise HTTPException(400, "Envíe code (hex) o source (.upbasm), uno de los dos")
    if source is not None:
        try:
            return assemble(source).hex()
        except AsmError as e:
            raise HTTPException(400, f"Error de ensamblado: {e}")
    return code.lower()


def _vm_state(node: NodeState) -> "programs.VmState":
    return node.blockchain.contract_state("vm")


@router.post("/vm/assemble")
async def vm_assemble(request: VmAssembleRequest):
    """Ensambla texto .upbasm → bytecode hex y su desensamblado (cómputo puro)."""
    code = _vm_code(None, request.source)
    return {"code": code, "size": len(code) // 2, "disassembly": disassemble(bytes.fromhex(code))}


@router.post("/contracts/vm/deploy")
async def vm_deploy(request: VmDeployRequest, node: NodeState = Depends(get_node)):
    """Despliega un contrato (CONTRACT_DEPLOY). 400 si el bytecode está mal formado o falta saldo.

    ADVERTENCIA: firma en el servidor con ``private_key_hex`` (educativo, en desuso)."""
    code = _vm_code(request.code, request.source)
    storage = _vm_storage(request.storage)
    payload = {"code": code, "gas_limit": request.gas_limit or programs.deploy_gas(code, storage),
               "gas_price": request.gas_price}
    if storage:
        payload["storage"] = storage
    nonce = node.blockchain.next_nonce(request.sender)
    address = programs.contract_address(request.sender, nonce)
    tx = Transaction(type=TransactionType.CONTRACT_DEPLOY, sender=request.sender,
                     recipient=address, payload=payload, fee=request.fee, nonce=nonce)
    _signed(lambda: tx.sign(request.private_key_hex))
    _submit_contract_tx(node, tx)
    return {"status": "PENDING", "tx_id": tx.tx_id, "address": address, "nonce": nonce,
            "gas": programs.deploy_gas(code, storage), "warning": _VM_WARNING}


@router.post("/contracts/vm/call")
async def vm_call(request: VmCallRequest, node: NodeState = Depends(get_node)):
    """Llama a un contrato (CONTRACT_CALL). El resultado (ok/revert/error, gas) queda en
    ``GET /contracts/vm/receipts/{tx_id}`` cuando se mina. Una llamada que falla al
    ejecutarse es VÁLIDA y cobra gas; 400 solo si la TX es inválida (ver docs/vm.md).

    ADVERTENCIA: firma en el servidor con ``private_key_hex`` (educativo, en desuso)."""
    payload = {"args": [_vm_word(a) for a in request.args], "value": request.value,
               "gas_limit": request.gas_limit, "gas_price": request.gas_price}
    tx = Transaction(type=TransactionType.CONTRACT_CALL, sender=request.sender,
                     recipient=request.contract, payload=payload, fee=request.fee,
                     nonce=node.blockchain.next_nonce(request.sender))
    _signed(lambda: tx.sign(request.private_key_hex))
    _submit_contract_tx(node, tx)
    return {"status": "PENDING", "tx_id": tx.tx_id, "nonce": tx.nonce, "warning": _VM_WARNING}


@router.post("/vm/simulate")
async def vm_simulate(request: VmSimulateRequest, node: NodeState = Depends(get_node)):
    """Ejecución de prueba (dry-run): NO cambia ningún estado ni crea TXs.

    Devuelve estado final, gas usado (incluye el fijo de la llamada), valor de
    retorno, storage resultante, logs, transferencias y la traza (acotada)."""
    if request.contract is not None:
        if request.code is not None or request.source is not None:
            raise HTTPException(400, "Con contract no se envía code ni source")
        entry = _vm_state(node).contract(request.contract)
        if entry is None:
            raise HTTPException(404, "Contrato inexistente")
        code, storage, balance = entry["code"], dict(entry["storage"]), entry["balance"]
    else:
        code = _vm_code(request.code, request.source)
        storage, balance = {k: v for k, v in _vm_storage(request.storage)}, request.balance
    if not programs.CALL_BASE_GAS <= request.gas_limit <= programs.MAX_GAS_LIMIT:
        raise HTTPException(400, f"gas_limit entre {programs.CALL_BASE_GAS} y {programs.MAX_GAS_LIMIT}")
    try:
        programs.validate_code(bytes.fromhex(code))
    except ValueError as e:
        raise HTTPException(400, f"bytecode inválido: {e}")
    height = request.block_height
    if height is None:
        height = node.blockchain.height + 1
    result = programs.call_code(
        code, storage=storage, caller=_vm_word(request.caller) if request.caller else 0,
        value=request.value, args=tuple(_vm_word(a) for a in request.args),
        block_height=height, balance=balance, gas_limit=request.gas_limit,
        trace=request.trace)
    return {
        "status": result.status, "error": result.error, "gas_used": result.gas_used,
        "return_value": result.return_value, "steps": result.steps,
        "storage": [[k, v] for k, v in result.storage.items()] if result.ok else None,
        "logs": result.logs,
        "transfers": [[programs.int_to_address(t), a] for t, a in result.transfers],
        "trace": result.trace,
        "trace_truncated": bool(request.trace) and result.steps > len(result.trace),
        "block_height": height,
    }


@router.get("/contracts/vm")
async def vm_list(node: NodeState = Depends(get_node)):
    """Contratos desplegados (confirmados)."""
    state = _vm_state(node)
    return {"height": node.blockchain.contracts.height, "gas_burned": state.gas_burned,
            "contracts": [{"address": a, "creator": c["creator"], "size": len(c["code"]) // 2,
                           "balance": c["balance"], "calls": c["calls"],
                           "deployed_at": c["deployed_at"]}
                          for a, c in state.contracts.items()]}


@router.get("/contracts/vm/receipts/{tx_id}")
async def vm_receipt(tx_id: str, node: NodeState = Depends(get_node)):
    """Recibo de una TX de contrato confirmada: estado, gas usado y cobrado, retorno."""
    receipt = _vm_state(node).receipts.get(tx_id)
    if receipt is None:
        raise HTTPException(404, "Sin recibo: la TX no existe o aún no está en un bloque")
    return {"tx_id": tx_id, **receipt}


@router.get("/contracts/vm/{address}")
async def vm_contract(address: str, node: NodeState = Depends(get_node)):
    """Código (hex y desensamblado), storage, saldo y últimos logs de un contrato."""
    state = _vm_state(node)
    entry = state.contract(address)
    if entry is None:
        raise HTTPException(404, "Contrato inexistente")
    return {"address": address,
            **{k: entry[k] for k in ("creator", "code", "balance", "calls", "deployed_at")},
            "disassembly": disassemble(bytes.fromhex(entry["code"])),
            "storage": [[k, v] for k, v in entry["storage"].items()],
            "logs": state.logs.get(address, []),
            "height": node.blockchain.contracts.height}


@router.get("/contracts/vm/{address}/storage/{key}")
async def vm_storage_slot(address: str, key: int, node: NodeState = Depends(get_node)):
    """Una casilla del storage (0 si no existe)."""
    entry = _vm_state(node).contract(address)
    if entry is None:
        raise HTTPException(404, "Contrato inexistente")
    return {"address": address, "key": key, "value": entry["storage"].get(key, 0)}


@router.get("/contracts/vm/{address}/logs")
async def vm_logs(address: str, node: NodeState = Depends(get_node)):
    """Últimos logs del contrato (``programs.MAX_LOGS_KEPT``)."""
    state = _vm_state(node)
    if state.contract(address) is None:
        raise HTTPException(404, "Contrato inexistente")
    return {"address": address, "logs": state.logs.get(address, [])}


# ── Endpoints: IA ─────────────────────────────────────────────────────────────

@router.get("/ai/analytics")
async def get_analytics(node: NodeState = Depends(get_node)):
    chain_data = [b.to_dict() for b in node.blockchain.chain]
    report = node.chain_analytics.analyze(
        chain_data, issuers=_credentials(node).issuers(),
        local_verifications=node.counters.get("verificaciones_locales"))
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
        if node.federated is not None:
            result["federado"] = node.federated_sync()["enviados"]
    return result


@router.get("/ai/federated")
async def federated_state(node: NodeState = Depends(get_node)):
    """Idea 6: resúmenes de los pares, referencia agregada y banderas recientes."""
    if node.federated is None:
        return {"enabled": False}
    return {"enabled": True, **node.federated.estado()}


@router.post("/ai/federated/sync", dependencies=[Depends(require_admin)])
async def federated_sync(node: NodeState = Depends(get_node)):
    if node.federated is None:
        raise HTTPException(409, "IA federada apagada (FEDERATED_AI=on)")
    return node.federated_sync()


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
    # Las tasas de hash 70/30 son una hipótesis didáctica (no una medición de la red).
    rs = node.replica_set
    return full_security_analysis(
        node_count=len(node.p2p.peers_snapshot()) + 1,
        honest_hash_rate=70.0,
        attacker_hash_rate=30.0,
        consensus=node.settings.consensus,
        pbft_f=rs.f if rs is not None else None,
        pbft_n=rs.n if rs is not None else None,
    )


@router.get("/security/crypto-benchmark")
async def crypto_benchmark():
    return benchmark_crypto(iterations=5000)


@router.get("/security/hardening")
async def hardening_checklist(node: NodeState = Depends(get_node)):
    """Checklist de hardening en solo lectura (inspección de código, sin shell)."""
    return HardeningAuditor(settings=node.settings).run_audit()


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


@router.post("/network/sync", dependencies=[Depends(require_admin)])
def sync_now(node: NodeState = Depends(get_node)):
    """Fuerza la sincronización con todos los pares activos (P0-5)."""
    adopted = node.p2p.sync_with_peers()
    return {"adopted": adopted, "height": node.blockchain.height, "work": node.blockchain.total_work}


# ── Fábrica de la aplicación ──────────────────────────────────────────────────

MAX_BODY_BYTES = 2 * 1024 * 1024   # P1-9: tope del cuerpo HTTP (TX 64 KiB, CSV de 100 filas)


class BodyLimitMiddleware:
    """ASGI puro: 413 si el cuerpo supera ``limit`` (por Content-Length o contando el stream)."""

    def __init__(self, app, limit: int = MAX_BODY_BYTES):
        self.app = app
        self.limit = limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        for name, value in scope["headers"]:
            if name == b"content-length":
                try:
                    if int(value) > self.limit:
                        return await self._rechazar(scope, receive, send)
                except ValueError:
                    pass
        visto = 0
        excedido = False
        respondio = False

        async def limitado_receive():
            nonlocal visto, excedido
            msg = await receive()
            if msg["type"] == "http.request":
                visto += len(msg.get("body", b""))
                if visto > self.limit:
                    excedido = True
                    return {"type": "http.request", "body": b"", "more_body": False}
            return msg

        async def limitado_send(msg):
            nonlocal respondio
            if excedido and not respondio:
                respondio = True
                if msg["type"] == "http.response.start":
                    return await self._enviar_413(send)
            if excedido and msg["type"] == "http.response.body" and respondio:
                return
            if msg["type"] == "http.response.start":
                respondio = True
            await send(msg)

        await self.app(scope, limitado_receive, limitado_send)

    async def _enviar_413(self, send):
        cuerpo = json.dumps({"detail": "cuerpo de la petición demasiado grande"}).encode()
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(cuerpo)).encode())]})
        await send({"type": "http.response.body", "body": cuerpo})

    async def _rechazar(self, scope, receive, send):
        await self._enviar_413(send)


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
        # PBFT (P1-1): las réplicas también son pares (gossip de TXs y sincronización).
        if node.replica_set is not None:
            for r in node.replica_set.replicas:
                if r.id != settings.node_id:
                    node.p2p.add_peer(r.host, r.port)
        if node.pbft is not None:
            node.pbft_transport.start()
            node.pbft.start()
        # did:web (P2-3): sin dominio fijo, cada nodo firma/exporta con el host de la petición
        # y un VC no verifica contra otro nodo de la red.
        multinodo = bool(settings.peers) or settings.consensus == "pbft"
        if multinodo and not (settings.did_web_domain or settings.public_base_url):
            logger.warning("Red multinodo sin DID_WEB_DOMAIN ni PUBLIC_BASE_URL: los VC exportados "
                           "por este nodo no verificarán contra los demás; definir el mismo "
                           "DID_WEB_DOMAIN (o PUBLIC_BASE_URL) en todos los nodos")
        if node.anchors is not None:
            node.anchors.retry_failed()
        logger.info(f"UPB-Chain nodo {settings.node_id} iniciado ({settings.consensus})")
        yield
        node.mining_stop.set()
        if node.pbft is not None:
            node.pbft.stop()
            node.pbft_transport.stop()
        node.p2p.stop()
        if node.anchors is not None:
            node.anchors.close()
        logger.info("Nodo detenido")

    app = FastAPI(
        title="UPB-Chain API",
        description="Blockchain académica con IA para la Universidad Privada Boliviana",
        version="1.0.0",
        lifespan=lifespan,
    )
    @app.exception_handler(RequestValidationError)
    async def _validacion(request: Request, exc: RequestValidationError):
        # Sin eco de `input`: un NaN/inf en el cuerpo no se puede serializar a JSON.
        errores = [{"loc": list(e.get("loc", ())), "msg": e.get("msg"), "type": e.get("type")}
                   for e in exc.errors()]
        return JSONResponse(status_code=422, content={"detail": errores})

    app.state.node = node
    app.state.metrics_registry = build_registry(node)   # P2-10: uno por app

    # CORS restringido (P1-9): por defecto solo el propio origen del nodo en localhost.
    cors_origins = settings.cors_origins or [
        f"http://localhost:{settings.api_port}", f"http://127.0.0.1:{settings.api_port}"]
    app.add_middleware(BodyLimitMiddleware)
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
