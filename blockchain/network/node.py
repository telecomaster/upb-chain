"""
Nodo P2P de UPB-Chain.
Gestiona pares, sincronización de cadena y propagación de bloques y transacciones.

Protocolo de mensajería (v2 — length-prefix framing)
=====================================================
Cada mensaje se transmite como::

    [ 4 bytes big-endian uint32 = longitud del payload ][ payload JSON UTF-8 ]

Conexiones persistentes (P2-6): hay UNA conexión TCP larga por par y canal ("ctl" para
HANDSHAKE/sincronización/gossip, "pbft" para los mensajes PBFT, de modo que bajar una cadena
grande no retrase a PBFT). Por cada conexión el cliente envía un mensaje y, si corresponde, lee su
respuesta (peticiones serializadas por un candado); el servidor atiende mensajes en bucle hasta
que el cliente cierre o pase ``idle_timeout`` sin tráfico. Antes de reutilizarla se comprueba que
siga viva (si el par la cerró, se reabre una vez); los TCP keepalive y la consulta periódica
``SYNC_REQUEST`` hacen de latido. Si el par cae, ``_mark_failed`` agenda la reconexión con
backoff exponencial y se vuelve a hacer HANDSHAKE.

TLS mutuo y lista blanca (P2-6)
-------------------------------
Con ``tls=`` (rutas ``ca``/``cert``/``key``) ambos extremos envuelven el socket en TLS 1.3 con
``CERT_REQUIRED``; la identidad del par es el CN de su certificado (ver ``network/tls.py``). Si
hay ``allowlist`` (node_ids) y el CN no figura, se corta la conexión y se avisa por
``on_unknown_peer``. El ``node_id`` anunciado en HANDSHAKE debe coincidir con el CN. SIN TLS la
lista blanca solo es informativa: el ``node_id`` anunciado no está autenticado, así que solo
sirve para avisar (no rechaza).

Mensajes (P0-5)
---------------
- ``HANDSHAKE``  → ``HANDSHAKE`` | ``REJECT``. Ambos lados envían su estado
  (``_status()``): node_id, host/port anunciados, genesis_hash, height, work
  (trabajo acumulado), tip y peers conocidos. Génesis distinto → ``REJECT``.
  Quien tenga menos trabajo pide la cadena del otro.
- ``SYNC_REQUEST`` → ``SYNC_RESPONSE`` con el mismo estado (consulta periódica).
- ``GET_CHAIN`` → ``CHAIN`` con la cadena completa (lista de bloques).
- ``NEW_BLOCK`` (sin respuesta): si extiende la punta se valida, se añade y se
  re-propaga una vez; si no la extiende se sincroniza con el emisor
  (``origin``); si es inválido se ignora con un log.
- ``NEW_TX`` (sin respuesta): admisión al mempool; si entra, se re-propaga.
- ``GET_PEERS`` → ``PEERS``; ``PING`` → ``PONG``.
- ``PBFT`` (sin respuesta, P1-1): ``data`` = un mensaje PBFT firmado
  (PRE_PREPARE, PREPARE, COMMIT, VIEW_CHANGE o NEW_VIEW) para la réplica
  local (``on_pbft_message``). Se envía directo a cada réplica (``send_pbft``),
  no por gossip.

Modo de consenso (P1-1)
-----------------------
El estado anunciado lleva ``consensus`` ("pow" o "pbft"); es de toda la red:
un par con otro modo recibe ``REJECT`` igual que con otro génesis. En pbft,
``NEW_BLOCK`` lleva ``certificate`` y ``CHAIN`` lleva ``certificates``
({altura: certificado}); la cadena los verifica en lugar del trabajo.

Compatibilidad backward
-----------------------
Si el primer byte recibido es ``{`` o ``[`` (inicio de JSON plano),
``_recv_framed`` asume protocolo legado (JSON + newline) y lo decodifica.
"""
import json
import logging
import os
import select
import socket
import ssl
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set

from blockchain.core.block import GENESIS_HASH, Block
from blockchain.core.transaction import Transaction
from blockchain.network import tls as _tls

logger = logging.getLogger("upb_chain.network")

# ── Tipos de mensaje ──────────────────────────────────────────────────────────
MSG_HANDSHAKE   = "HANDSHAKE"
MSG_REJECT      = "REJECT"
MSG_BLOCK       = "NEW_BLOCK"
MSG_TRANSACTION = "NEW_TX"
MSG_GET_CHAIN   = "GET_CHAIN"
MSG_CHAIN       = "CHAIN"
MSG_GET_PEERS   = "GET_PEERS"
MSG_PEERS       = "PEERS"
MSG_PING        = "PING"
MSG_PONG        = "PONG"
MSG_PBFT        = "PBFT"
MSG_SYNC_REQUEST  = "SYNC_REQUEST"
MSG_SYNC_RESPONSE = "SYNC_RESPONSE"

# Direcciones que no sirven para que otro nodo nos contacte.
_UNSPECIFIED_HOSTS = {"", "0.0.0.0", "::", "[::]"}


@dataclass
class Peer:
    host: str
    port: int
    node_id: str = ""
    last_seen: float = field(default_factory=time.time)
    latency_ms: float = 0.0
    is_active: bool = False        # True tras un HANDSHAKE exitoso
    failed_attempts: int = 0       # fallos consecutivos (para el backoff)
    next_retry: float = 0.0        # instante del próximo intento de reconexión
    next_status: float = 0.0       # instante de la próxima consulta de estado
    height: int = 0
    work: int = 0

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "node_id": self.node_id,
            "last_seen": self.last_seen,
            "is_active": self.is_active,
            "height": self.height,
        }


def _cerrar(sock) -> None:
    """Cierra un socket despertando a quien esté bloqueado leyéndolo en otro hilo."""
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except (OSError, ValueError):
        pass
    try:
        sock.close()
    except OSError:
        pass


class _Link:
    """Conexión saliente persistente a un par (un candado serializa petición/respuesta)."""

    def __init__(self, node: "P2PNode", host: str, port: int):
        self.node, self.host, self.port = node, host, port
        self.sock: Optional[socket.socket] = None
        self.cn: Optional[str] = None
        self.lock = threading.Lock()

    def viva(self) -> bool:
        """False si el par cerró la conexión o hay datos sin pedir (el par nunca habla primero)."""
        try:
            if getattr(self.sock, "pending", lambda: 0)():
                return False
            legible, _, _ = select.select([self.sock], [], [], 0)
            return not legible
        except (OSError, ValueError):
            return False

    def abrir(self, timeout: float) -> None:
        node = self.node
        sock = socket.create_connection((self.host, self.port), timeout=timeout)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if node._tls_client is not None:
                sock = node._tls_client.wrap_socket(sock)
                self.cn = _tls.cn_del_par(sock)
                if not node._autorizado(self.cn):
                    node._alertar(f"{self.cn}@{self.host}")
                    raise PermissionError(f"par {self.cn!r} fuera de la lista blanca")
        except BaseException:
            _cerrar(sock)
            raise
        self.sock = sock

    def close(self) -> None:
        if self.sock is not None:
            _cerrar(self.sock)
            self.sock = None


class P2PNode:
    BUFFER_SIZE = 65536
    _MAX_PAYLOAD = 10_000_000   # 10 MB — límite de seguridad

    def __init__(
        self,
        node_id: str,
        host: str,
        port: int,
        on_new_block: Optional[Callable] = None,
        on_new_tx: Optional[Callable] = None,
        on_pbft_message: Optional[Callable] = None,
        advertise_host: Optional[str] = None,
        blockchain=None,
        sync_interval: float = 15.0,
        retry_base: float = 1.0,
        retry_max: float = 60.0,
        timeout: float = 10.0,
        on_invalid_block: Optional[Callable] = None,
        on_unknown_peer: Optional[Callable] = None,
        known_peers: Optional[List[str]] = None,
        consensus: str = "pow",
        tls: Optional[Dict[str, str]] = None,
        allowlist: Optional[List[str]] = None,
        idle_timeout: float = 120.0,
    ):
        """
        - ``blockchain``: si se pasa, el nodo valida y añade bloques/TXs recibidos,
          responde ``GET_CHAIN`` y sincroniza con ``replace_chain``. ``on_new_block``
          y ``on_new_tx`` pasan a ser avisos DESPUÉS de aceptar (dict recibido).
        - ``on_invalid_block(reason, origen)``: aviso cuando un bloque recibido que
          extiende la punta es rechazado (P1-5).
        - ``on_unknown_peer(direccion)`` + ``known_peers``: si ``known_peers`` (PEERS) no
          está vacío, se avisa una vez por cada par entrante que no figure en esa lista.
          Sin lista configurada (red abierta) no hay "desconocidos" y no se avisa.
        - ``tls``: ``{"ca", "cert", "key"}`` (rutas PEM) activa el TLS mutuo (P2-6).
        - ``allowlist``: node_ids permitidos (CN del certificado con TLS; informativa sin TLS).
        - ``idle_timeout``: segundos sin tráfico tras los que el servidor cierra una conexión.
        - ``port=0`` elige un puerto libre (útil en tests); ver ``self.port`` tras ``start()``.
        - ``sync_interval``: cada cuánto se consulta el estado de los pares activos.
        - ``retry_base``/``retry_max``: backoff exponencial de reconexión (segundos).
        """
        self.node_id = node_id
        self.host = host
        self.port = port
        # Dirección que se anuncia a los pares (NODE_ADVERTISE_HOST); por defecto, host.
        self.advertise_host = advertise_host or host
        self.blockchain = blockchain
        self.genesis_hash = blockchain.chain[0].hash if blockchain is not None else GENESIS_HASH
        self.sync_interval = sync_interval
        self.retry_base = retry_base
        self.retry_max = retry_max
        self.timeout = timeout

        self.peers: Dict[str, Peer] = {}
        self._peers_lock = threading.Lock()
        self._seen_messages: Set[str] = set()
        self._seen_lock = threading.Lock()
        self._sync_lock = threading.Lock()
        self._running = False
        self._stop_event = threading.Event()

        self.on_new_block = on_new_block
        self.on_new_tx = on_new_tx
        self.on_pbft_message = on_pbft_message
        self.on_invalid_block = on_invalid_block
        self.on_unknown_peer = on_unknown_peer
        self.known_peers: Set[str] = set(known_peers or [])
        # Modo de consenso de la red (P1-1): un par con otro modo se rechaza.
        self.consensus = consensus

        self.allowlist: Set[str] = set(allowlist or [])
        self.idle_timeout = idle_timeout
        self._tls_server = self._tls_client = None
        if tls:
            self._tls_server, self._tls_client = _tls.crear_contextos(
                tls["ca"], tls["cert"], tls["key"])
        self._links: Dict[tuple, "_Link"] = {}      # conexiones salientes por (host, port, canal)
        self._links_lock = threading.Lock()
        self._inbound: Set[socket.socket] = set()   # conexiones entrantes abiertas (para stop())
        self._inbound_lock = threading.Lock()
        self._local = threading.local()             # CN del par de la conexión que atiende el hilo
        self._alerted: Set[str] = set()             # identidades ya avisadas (sin spam de alertas)
        self._server: Optional[socket.socket] = None
        self._threads: List[threading.Thread] = []

        # ── Métricas ──────────────────────────────────────────────────────────
        self._start_time: float = time.time()
        self._messages_sent: int = 0
        self._messages_received: int = 0
        self._bytes_sent: int = 0
        self._bytes_received: int = 0
        self._stats_lock = threading.Lock()

    # ── Ciclo de vida ─────────────────────────────────────────────────────────

    def start(self) -> None:
        self._running = True
        self._stop_event.clear()
        self._start_time = time.time()
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # En Windows SO_REUSEADDR permite que DOS procesos usen el mismo puerto: sólo en POSIX.
        if os.name != "nt":
            self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((self.host, self.port))
        self.port = self._server.getsockname()[1]
        self._server.listen(32)
        self._server.settimeout(0.5)   # para que stop() no quede colgado en accept()
        if self.advertise_host in _UNSPECIFIED_HOSTS:
            logger.warning(
                "NODE_ADVERTISE_HOST no definido: los pares usarán la IP de origen de la conexión"
            )
        logger.info(f"Nodo {self.node_id} escuchando en {self.host}:{self.port}")

        for target in (self._accept_loop, self._maintenance_loop):
            t = threading.Thread(target=target, daemon=True, name=f"p2p-{self.node_id}")
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        """Detiene los hilos y cierra el socket de escucha (espera hasta ~2 s)."""
        self._running = False
        self._stop_event.set()
        if self._server:
            try:
                self._server.close()
            except OSError:
                pass
        with self._links_lock:
            links, self._links = list(self._links.values()), {}
        for link in links:
            link.close()
        with self._inbound_lock:
            inbound, self._inbound = list(self._inbound), set()
        for conn in inbound:
            _cerrar(conn)
        for t in self._threads:
            if t is not threading.current_thread():
                t.join(timeout=2)
        self._threads = []

    def _accept_loop(self) -> None:
        while self._running:
            try:
                conn, addr = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    logger.exception("Error en accept loop")
                break
            t = threading.Thread(target=self._handle_connection, args=(conn, addr), daemon=True)
            t.start()

    def _handle_connection(self, conn: socket.socket, addr) -> None:
        """Atiende una conexión entrante: TLS (si aplica) y un bucle de mensajes hasta que cierre."""
        self._local.cn = None
        with self._inbound_lock:
            self._inbound.add(conn)
        try:
            conn.settimeout(self.timeout)
            if self._tls_server is not None:
                try:
                    crudo = conn
                    conn = self._tls_server.wrap_socket(crudo, server_side=True)
                    with self._inbound_lock:
                        self._inbound.discard(crudo)
                except (ssl.SSLError, OSError) as e:
                    logger.warning(f"TLS rechazado desde {addr[0]}: {e}")
                    self._alertar(f"{addr[0]} (certificado inválido)")
                    return
                with self._inbound_lock:
                    self._inbound.add(conn)
                self._local.cn = _tls.cn_del_par(conn)
                if not self._autorizado(self._local.cn):
                    logger.warning(f"Par {self._local.cn!r} ({addr[0]}) fuera de la lista blanca")
                    self._alertar(f"{self._local.cn}@{addr[0]}")
                    return
            conn.settimeout(self.idle_timeout)
            while self._running:
                try:
                    message = self._recv_framed(conn)
                except (ConnectionError, socket.timeout, ssl.SSLError):
                    break               # cierre limpio del par, inactividad o error de TLS
                self._dispatch(message, conn)
        except Exception:
            if self._running:
                logger.exception(f"Error manejando conexión de {addr}")
        finally:
            with self._inbound_lock:
                self._inbound.discard(conn)
            _cerrar(conn)

    def _autorizado(self, node_id: Optional[str]) -> bool:
        """Con TLS: ¿el CN del par está en la lista blanca? (lista vacía = cualquier cert de la CA)."""
        return bool(node_id) and (not self.allowlist or node_id in self.allowlist)

    def _alertar(self, identidad: str) -> None:
        """Avisa una vez por identidad a ``on_unknown_peer`` (monitor de seguridad)."""
        with self._peers_lock:
            if identidad in self._alerted:
                return
            self._alerted.add(identidad)
        self._notify(self.on_unknown_peer, identidad)

    # ── Framing (v2) ──────────────────────────────────────────────────────────

    def _send_framed(self, conn: socket.socket, message: dict) -> None:
        """
        Envía un mensaje con length-prefix framing:
        [ 4 bytes big-endian uint32 ][ payload JSON UTF-8 ]
        Actualiza contadores de métricas de forma thread-safe.
        """
        payload = json.dumps(message).encode("utf-8")
        header = struct.pack(">I", len(payload))
        conn.sendall(header + payload)
        with self._stats_lock:
            self._messages_sent += 1
            self._bytes_sent += 4 + len(payload)

    def _recv_framed(self, conn: socket.socket) -> dict:
        """
        Recibe un mensaje usando length-prefix framing.
        Compatibilidad backward: si el primer byte es ``{`` o ``[`` (JSON plano),
        lee hasta newline usando el protocolo legado.
        """
        header = self._recv_exact(conn, 4)

        # ── Protocolo legado: JSON plano + newline ────────────────────────────
        if header[0] in (ord("{"), ord("[")):
            rest = b""
            while b"\n" not in rest:
                chunk = conn.recv(self.BUFFER_SIZE)
                if not chunk:
                    break
                rest += chunk
            full = header + rest
            with self._stats_lock:
                self._messages_received += 1
                self._bytes_received += len(full)
            return json.loads(full.decode("utf-8").strip())

        # ── Protocolo moderno: length-prefix ─────────────────────────────────
        length = struct.unpack(">I", header)[0]
        if length == 0 or length > self._MAX_PAYLOAD:
            raise ValueError(f"Longitud de mensaje inválida: {length}")
        payload = self._recv_exact(conn, length)
        with self._stats_lock:
            self._messages_received += 1
            self._bytes_received += 4 + length
        return json.loads(payload.decode("utf-8"))

    @staticmethod
    def _recv_exact(conn: socket.socket, n: int) -> bytes:
        """Lee exactamente *n* bytes del socket. Lanza ConnectionError si la conexión se cierra."""
        data = b""
        while len(data) < n:
            chunk = conn.recv(n - len(data))
            if not chunk:
                raise ConnectionError(f"Conexión cerrada al leer {n} bytes")
            data += chunk
        return data

    def _request(self, host: str, port: int, message: dict, expect_reply: bool = True,
                 timeout: Optional[float] = None, channel: str = "ctl") -> Optional[dict]:
        """Envía `message` por la conexión persistente al par y (opcional) devuelve la respuesta.

        Si la conexión reutilizada falla por haberla cerrado el par, se reabre y se reintenta
        una vez (los mensajes con ``id`` se deduplican en el receptor). Un timeout no se reintenta.
        """
        key = (host, port, channel)
        with self._links_lock:
            link = self._links.setdefault(key, _Link(self, host, port))
        timeout = timeout or self.timeout
        with link.lock:
            for intento in (0, 1):
                reutilizada = link.sock is not None and link.viva()
                try:
                    if not reutilizada:
                        link.close()
                        link.abrir(timeout)
                    link.sock.settimeout(timeout)
                    self._send_framed(link.sock, message)
                    return self._recv_framed(link.sock) if expect_reply else None
                except (OSError, ssl.SSLError, ValueError) as e:
                    link.close()
                    if not reutilizada or intento or isinstance(e, socket.timeout):
                        raise

    def _cn_de(self, host: str, port: int) -> Optional[str]:
        link = self._links.get((host, port, "ctl"))
        return link.cn if link is not None else None

    # ── Estado local ──────────────────────────────────────────────────────────

    def _status(self) -> dict:
        """Estado que se anuncia en HANDSHAKE y SYNC_RESPONSE."""
        bc = self.blockchain
        with self._peers_lock:
            known = [p.address for p in self.peers.values() if p.is_active]
        return {
            "node_id": self.node_id,
            "host": self.advertise_host,
            "port": self.port,
            "genesis_hash": self.genesis_hash,
            "consensus": self.consensus,
            "height": bc.height if bc is not None else 0,
            "work": bc.total_work if bc is not None else 0,
            "tip": bc.last_block.hash if bc is not None else self.genesis_hash,
            "peers": known,
        }

    def _incompatible(self, status: dict) -> Optional[str]:
        """Motivo para rechazar a un par (otro génesis u otro modo de consenso), o None."""
        if status.get("genesis_hash") != self.genesis_hash:
            return "Génesis distinto"
        # Un par sin el campo es anterior a P1-1, es decir, PoW.
        if status.get("consensus", "pow") != self.consensus:
            return (f"Modo de consenso distinto ({status.get('consensus', 'pow')} "
                    f"!= {self.consensus})")
        return None

    def _local_work(self) -> int:
        return self.blockchain.total_work if self.blockchain is not None else 0

    @staticmethod
    def _peer_host(advertised: str, conn: Optional[socket.socket]) -> str:
        """Host anunciado por el par; si es 0.0.0.0/vacío, la IP de origen del socket."""
        if advertised not in _UNSPECIFIED_HOSTS:
            return advertised
        try:
            return conn.getpeername()[0] if conn is not None else ""
        except OSError:
            return ""

    def _is_self(self, host: str, port: int, node_id: str = "") -> bool:
        if node_id and node_id == self.node_id:
            return True
        return port == self.port and host in ({self.advertise_host, "127.0.0.1", "localhost"} - {""})

    def _mark_seen(self, msg_id: str) -> bool:
        """Registra `msg_id`; devuelve False si ya se había visto (dedupe)."""
        if not msg_id:
            return True
        with self._seen_lock:
            if msg_id in self._seen_messages:
                return False
            self._seen_messages.add(msg_id)
            if len(self._seen_messages) > 10_000:
                self._seen_messages = set(list(self._seen_messages)[-5000:])
        return True

    # ── Despacho de mensajes ──────────────────────────────────────────────────

    def _dispatch(self, message: dict, conn: socket.socket) -> None:
        msg_type = message.get("type")
        if not self._mark_seen(message.get("id", "")):
            return

        if msg_type == MSG_HANDSHAKE:
            self._handle_handshake(message, conn)
        elif msg_type == MSG_BLOCK:
            self._handle_block(message, conn)
        elif msg_type == MSG_TRANSACTION:
            self._handle_tx(message)
        elif msg_type == MSG_GET_CHAIN:
            chain = list(self.blockchain.chain) if self.blockchain is not None else []
            reply = {"type": MSG_CHAIN, "data": [b.to_dict() for b in chain]}
            certs = getattr(self.blockchain, "certificates", None)
            if certs:
                reply["certificates"] = {str(h): c for h, c in dict(certs).items()}
            self._send_framed(conn, reply)
        elif msg_type == MSG_SYNC_REQUEST:
            self._send_framed(conn, {"type": MSG_SYNC_RESPONSE, **self._status()})
        elif msg_type == MSG_GET_PEERS:
            with self._peers_lock:
                peer_list = [p.to_dict() for p in self.peers.values() if p.is_active]
            self._send_framed(conn, {"type": MSG_PEERS, "data": peer_list})
        elif msg_type == MSG_PING:
            self._send_framed(conn, {"type": MSG_PONG, "node_id": self.node_id})
        elif msg_type == MSG_PBFT and self.on_pbft_message:
            self._notify(self.on_pbft_message, message.get("data"))

    def _handle_handshake(self, message: dict, conn: socket.socket) -> None:
        peer_id = message.get("node_id", "unknown")
        cn = getattr(self._local, "cn", None)
        if self._tls_server is not None and peer_id != cn:
            motivo = f"node_id {peer_id!r} no coincide con el CN del certificado ({cn!r})"
            logger.warning(f"Par rechazado: {motivo}")
            self._send_framed(conn, {"type": MSG_REJECT, "reason": motivo})
            return
        if self._tls_server is None and self.allowlist and peer_id not in self.allowlist:
            # Sin TLS el node_id no está autenticado: solo se avisa, no se rechaza.
            self._alertar(f"{peer_id} (no autenticado)")
        motivo = self._incompatible(message)
        if motivo:
            logger.warning(f"Par {peer_id} rechazado: {motivo}")
            self._send_framed(conn, {"type": MSG_REJECT, "reason": motivo})
            return
        host = self._peer_host(message.get("host", ""), conn)
        port = int(message.get("port") or 0)
        if not host or not port or self._is_self(host, port, peer_id):
            self._send_framed(conn, {"type": MSG_HANDSHAKE, **self._status()})
            return
        if self.on_unknown_peer and self.known_peers and f"{host}:{port}" not in self.known_peers:
            with self._peers_lock:
                nuevo = f"{host}:{port}" not in self.peers
            if nuevo:
                self._notify(self.on_unknown_peer, f"{host}:{port}")
        # Se registra al par ANTES de responder: si no, el cliente recibe el HANDSHAKE y
        # puede observar que este nodo aún no lo conoce (carrera intermitente).
        self._register_peer(host, port, message)
        self._send_framed(conn, {"type": MSG_HANDSHAKE, **self._status()})
        self._learn_peers(message.get("peers", []))
        if int(message.get("work", 0)) > self._local_work():
            self._spawn(self.sync_with, f"{host}:{port}")

    def _handle_block(self, message: dict, conn: socket.socket) -> None:
        data = message.get("data") or {}
        if self.blockchain is None:          # modo sin cadena: sólo aviso + gossip
            if self.on_new_block:
                self.on_new_block(data)
            self._gossip(message)
            return
        try:
            block = Block.from_dict(data)
        except (KeyError, TypeError, ValueError, AttributeError):
            logger.warning("Bloque malformado ignorado")
            return
        bc = self.blockchain
        if bc.get_block_by_hash(block.hash) is not None:
            return
        tip = bc.last_block
        extends = block.header.index == tip.header.index + 1 and block.header.previous_hash == tip.hash
        if extends:
            certificate = message.get("certificate")
            ok, reason = (bc.add_block(block, certificate=certificate) if certificate is not None
                          else bc.add_block(block))
            if ok:
                logger.info(f"Bloque #{block.header.index} recibido y añadido")
                if self.on_new_block:
                    self.on_new_block(data)
                self._gossip(message)
                return
            if bc.last_block.hash == tip.hash:   # la punta no cambió: el bloque es inválido
                logger.warning(f"Bloque #{block.header.index} inválido ignorado: {reason}")
                origin = message.get("origin") or {}
                self._notify(self.on_invalid_block, reason,
                             origin.get("node_id") or message.get("node_id") or "par desconocido")
                return
        # No extiende nuestra punta: puede venir de una cadena con más trabajo.
        origin = message.get("origin") or {}
        host = self._peer_host(origin.get("host", ""), conn)
        port = int(origin.get("port") or 0)
        if host and port and not self._is_self(host, port):
            logger.info(f"Bloque #{block.header.index} no extiende la punta: sincronizando con {host}:{port}")
            self.sync_with(f"{host}:{port}")

    @staticmethod
    def _notify(callback: Optional[Callable], *args) -> None:
        """Avisa a un observador sin dejar que sus errores rompan el manejo del mensaje."""
        if callback is None:
            return
        try:
            callback(*args)
        except Exception:
            logger.exception("Error en un callback del nodo P2P")

    def _handle_tx(self, message: dict) -> None:
        data = message.get("data") or {}
        if self.blockchain is None:
            if self.on_new_tx:
                self.on_new_tx(data)
            self._gossip(message)
            return
        try:
            tx = Transaction.from_dict(data)
        except (KeyError, TypeError, ValueError, AttributeError):
            logger.warning("TX malformada ignorada")
            return
        ok, reason = self.blockchain.add_transaction(tx)
        if not ok:
            logger.debug(f"TX {str(data.get('tx_id'))[:8]}… no admitida: {reason}")
            return
        if self.on_new_tx:
            self.on_new_tx(data)
        self._gossip(message)

    # ── Pares ─────────────────────────────────────────────────────────────────

    def _register_peer(self, host: str, port: int, status: dict) -> Peer:
        """Marca un par como activo con el estado recibido en HANDSHAKE/SYNC_RESPONSE."""
        address = f"{host}:{port}"
        now = time.time()
        with self._peers_lock:
            peer = self.peers.get(address)
            if peer is None:
                peer = Peer(host=host, port=port)
                self.peers[address] = peer
                logger.info(f"Par conectado: {status.get('node_id', '?')} @ {address}")
            peer.node_id = status.get("node_id", peer.node_id)
            peer.height = int(status.get("height", 0))
            peer.work = int(status.get("work", 0))
            peer.is_active = True
            peer.failed_attempts = 0
            peer.last_seen = now
            peer.next_status = now + self.sync_interval
        return peer

    def add_peer(self, host: str, port: int) -> None:
        """Agrega un par conocido (p. ej. de PEERS); el hilo de mantenimiento lo conecta."""
        if self._is_self(host, port):
            return
        with self._peers_lock:
            self.peers.setdefault(f"{host}:{port}", Peer(host=host, port=port))

    def _learn_peers(self, addresses: List[str]) -> None:
        for address in addresses or []:
            try:
                host, port = str(address).rsplit(":", 1)
                if host not in _UNSPECIFIED_HOSTS:
                    self.add_peer(host, int(port))
            except ValueError:
                continue

    def _mark_failed(self, peer: Peer) -> None:
        """Marca un par inactivo y agenda la reconexión con backoff exponencial."""
        with self._peers_lock:
            if peer.is_active:
                logger.warning(f"Par {peer.address} desconectado")
            peer.is_active = False
            peer.failed_attempts += 1
            delay = min(self.retry_max, self.retry_base * 2 ** (peer.failed_attempts - 1))
            peer.next_retry = time.time() + delay

    def connect_to_peer(self, host: str, port: int) -> bool:
        """HANDSHAKE con un par; si tiene más trabajo, se sincroniza. False si falla o se rechaza."""
        self.add_peer(host, port)
        peer = self.peers.get(f"{host}:{port}")
        try:
            start = time.perf_counter()
            reply = self._request(host, port, {"type": MSG_HANDSHAKE, **self._status()})
        except Exception as e:
            logger.debug(f"No se pudo conectar a {host}:{port}: {e}")
            if peer is not None:
                self._mark_failed(peer)
            return False
        cn = self._cn_de(host, port)
        if self._tls_client is not None and reply.get("type") == MSG_HANDSHAKE \
                and reply.get("node_id") != cn:
            reply = {"type": MSG_REJECT, "reason": f"node_id {reply.get('node_id')!r} "
                                                   f"no coincide con el CN del certificado ({cn!r})"}
        if reply.get("type") != MSG_HANDSHAKE or self._incompatible(reply):
            motivo = reply.get("reason") or self._incompatible(reply) or "respuesta inválida"
            logger.warning(f"Par {host}:{port} rechazado: {motivo}")
            with self._peers_lock:
                self.peers.pop(f"{host}:{port}", None)
            return False
        if self._is_self(host, port, reply.get("node_id", "")):
            with self._peers_lock:
                self.peers.pop(f"{host}:{port}", None)
            return False
        peer = self._register_peer(host, port, reply)
        peer.latency_ms = (time.perf_counter() - start) * 1000
        self._learn_peers(reply.get("peers", []))
        if peer.work > self._local_work():
            self.sync_with(peer.address)
        return True

    # ── Sincronización ────────────────────────────────────────────────────────

    def request_chain_sync(self, peer_address: str) -> Optional[List[dict]]:
        """Pide la cadena completa (``GET_CHAIN``) a ``"host:port"``. None si falla."""
        response = self._fetch_chain(peer_address)
        return response.get("data", []) if response is not None else None

    def _fetch_chain(self, peer_address: str) -> Optional[dict]:
        """Respuesta ``CHAIN`` completa (bloques y, en pbft, certificados) o None."""
        try:
            host, port = peer_address.rsplit(":", 1)
            response = self._request(host, int(port), {"type": MSG_GET_CHAIN, "node_id": self.node_id})
            if response.get("type") == MSG_CHAIN:
                return response
            logger.debug(f"request_chain_sync: respuesta inesperada de {peer_address}: {response.get('type')}")
        except Exception as e:
            logger.warning(f"request_chain_sync falló para {peer_address}: {e}")
        return None

    def sync_with(self, peer_address: str) -> bool:
        """Descarga la cadena del par y llama ``replace_chain`` (que decide por trabajo)."""
        if self.blockchain is None:
            return False
        with self._sync_lock:
            response = self._fetch_chain(peer_address)
            chain = response.get("data") if response is not None else None
            if not chain:
                return False
            certificates = response.get("certificates")
            ok, reason = (self.blockchain.replace_chain(chain, certificates) if certificates
                          else self.blockchain.replace_chain(chain))
        if ok:
            logger.info(f"Sincronizado con {peer_address}: altura {self.blockchain.height}")
        else:
            logger.debug(f"Cadena de {peer_address} no adoptada: {reason}")
        return ok

    def sync_with_peers(self) -> int:
        """Sincroniza con todos los pares activos; devuelve cuántas veces se adoptó cadena."""
        with self._peers_lock:
            active = [p.address for p in self.peers.values() if p.is_active]
        return sum(1 for address in active if self.sync_with(address))

    def _check_status(self, peer: Peer) -> None:
        """Consulta periódica (SYNC_REQUEST): latencia, altura y trabajo del par."""
        try:
            start = time.perf_counter()
            reply = self._request(peer.host, peer.port, {"type": MSG_SYNC_REQUEST})
        except Exception:
            self._mark_failed(peer)
            return
        if reply.get("type") != MSG_SYNC_RESPONSE or self._incompatible(reply):
            self._mark_failed(peer)
            return
        self._register_peer(peer.host, peer.port, reply)
        peer.latency_ms = (time.perf_counter() - start) * 1000
        if peer.work > self._local_work():
            self.sync_with(peer.address)

    def _maintenance_loop(self) -> None:
        """Reconecta pares caídos (con backoff) y consulta el estado de los activos."""
        tick = max(0.05, min(0.5, self.retry_base, self.sync_interval))
        while not self._stop_event.is_set():
            now = time.time()
            with self._peers_lock:
                peers = list(self.peers.values())
            for peer in peers:
                if self._stop_event.is_set():
                    break
                if not peer.is_active and now >= peer.next_retry:
                    self.connect_to_peer(peer.host, peer.port)
                elif peer.is_active and now >= peer.next_status:
                    self._check_status(peer)
            self._stop_event.wait(tick)

    @staticmethod
    def _spawn(target, *args) -> None:
        threading.Thread(target=target, args=args, daemon=True).start()

    # ── Envío de mensajes ─────────────────────────────────────────────────────

    def _send_message(self, conn: socket.socket, message: dict) -> None:
        """Alias de _send_framed para compatibilidad con código existente."""
        self._send_framed(conn, message)

    def _new_message(self, msg_type: str, data: dict) -> dict:
        msg = {"type": msg_type, "data": data, "id": str(uuid.uuid4())}
        self._mark_seen(msg["id"])   # no re-procesar nuestro propio mensaje
        return msg

    def broadcast_block(self, block_dict: dict, certificate: Optional[dict] = None) -> int:
        message = self._new_message(MSG_BLOCK, block_dict)
        if certificate is not None:
            message["certificate"] = certificate      # modo pbft (P1-1)
        return self._broadcast(message)

    def broadcast_transaction(self, tx_dict: dict) -> int:
        return self._broadcast(self._new_message(MSG_TRANSACTION, tx_dict))

    def send_pbft(self, host: str, port: int, pbft_msg: dict, timeout: float = 2.0) -> None:
        """Entrega directa (sin gossip ni respuesta) de un mensaje PBFT a una réplica."""
        self._request(host, port, {"type": MSG_PBFT, "data": pbft_msg}, expect_reply=False,
                      timeout=timeout, channel="pbft")

    def _broadcast(self, message: dict) -> int:
        # `origin`: a quién pedir la cadena si el bloque no extiende la punta del receptor.
        message = {**message, "origin": {"host": self.advertise_host, "port": self.port}}
        sent = 0
        with self._peers_lock:
            active = [p for p in self.peers.values() if p.is_active]
        for peer in active:
            try:
                self._request(peer.host, peer.port, message, expect_reply=False)
                sent += 1
            except Exception:
                self._mark_failed(peer)
        return sent

    def broadcast_to_subset(self, message: dict, max_peers: int = 3) -> int:
        """
        Envía *message* únicamente a los *max_peers* peers con menor latencia.
        Retorna el número de peers a los que se envió exitosamente.
        """
        with self._peers_lock:
            active = sorted(
                [p for p in self.peers.values() if p.is_active],
                key=lambda p: p.latency_ms if p.latency_ms > 0 else float("inf"),
            )
        sent = 0
        for peer in active[:max_peers]:
            try:
                self._request(peer.host, peer.port, message, expect_reply=False)
                sent += 1
            except Exception as e:
                logger.debug(f"broadcast_to_subset: error con {peer.address}: {e}")
                self._mark_failed(peer)
        return sent

    def _gossip(self, message: dict) -> None:
        """Re-propaga un mensaje aceptado (mismo id: los pares lo deduplican)."""
        self._broadcast(message)

    # ── Estadísticas ──────────────────────────────────────────────────────────

    def get_network_stats(self) -> dict:
        with self._peers_lock:
            peers = list(self.peers.values())
        active = [p for p in peers if p.is_active]
        latencies = [p.latency_ms for p in active if p.latency_ms > 0]
        with self._stats_lock:
            msgs_sent     = self._messages_sent
            msgs_received = self._messages_received
            bytes_sent    = self._bytes_sent
            bytes_received = self._bytes_received
        return {
            "node_id":          self.node_id,
            "address":          f"{self.advertise_host}:{self.port}",
            "total_peers":      len(peers),
            "active_peers":     len(active),
            "peers":            [p.to_dict() for p in peers],
            "avg_latency_ms":   sum(latencies) / len(latencies) if latencies else 0,
            "uptime_seconds":   time.time() - self._start_time,
            "messages_sent":    msgs_sent,
            "messages_received": msgs_received,
            "bytes_sent":       bytes_sent,
            "bytes_received":   bytes_received,
        }
