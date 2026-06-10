"""
Nodo P2P de UPB-Chain.
Gestiona descubrimiento de pares, sincronización de cadena y propagación de transacciones.

Protocolo de mensajería (v2 — length-prefix framing)
=====================================================
Cada mensaje se transmite como::

    [ 4 bytes big-endian uint32 = longitud del payload ][ payload JSON UTF-8 ]

Compatibilidad backward
-----------------------
Si el primer byte recibido es ``{`` o ``[`` (inicio de JSON plano),
``_recv_framed`` asume protocolo legado (JSON + newline) y lo decodifica
correctamente.  Esto permite convivir con nodos que aún no actualizaron.
"""
import json
import logging
import socket
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set

logger = logging.getLogger("upb_chain.network")

# ── Tipos de mensaje existentes ───────────────────────────────────────────────
MSG_HANDSHAKE   = "HANDSHAKE"
MSG_BLOCK       = "NEW_BLOCK"
MSG_TRANSACTION = "NEW_TX"
MSG_GET_CHAIN   = "GET_CHAIN"
MSG_CHAIN       = "CHAIN"
MSG_GET_PEERS   = "GET_PEERS"
MSG_PEERS       = "PEERS"
MSG_PING        = "PING"
MSG_PONG        = "PONG"
MSG_PBFT        = "PBFT"

# ── Tipos de mensaje nuevos (sincronización) ──────────────────────────────────
MSG_SYNC_REQUEST  = "SYNC_REQUEST"
MSG_SYNC_RESPONSE = "SYNC_RESPONSE"
MSG_BLOCK_REQUEST = "GET_BLOCK"
MSG_BLOCK_RESPONSE = "BLOCK"


@dataclass
class Peer:
    host: str
    port: int
    node_id: str = ""
    last_seen: float = field(default_factory=time.time)
    latency_ms: float = 0.0
    is_active: bool = True
    failed_pings: int = 0          # pings consecutivos fallidos

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "node_id": self.node_id,
            "last_seen": self.last_seen,
        }


class P2PNode:
    BUFFER_SIZE = 65536
    _MAX_PAYLOAD  = 10_000_000   # 10 MB — límite de seguridad
    _FAILED_PING_THRESHOLD = 3   # pings fallidos antes de marcar inactivo

    def __init__(
        self,
        node_id: str,
        host: str,
        port: int,
        on_new_block: Optional[Callable] = None,
        on_new_tx: Optional[Callable] = None,
        on_pbft_message: Optional[Callable] = None,
    ):
        self.node_id = node_id
        self.host = host
        self.port = port
        self.peers: Dict[str, Peer] = {}
        self._seen_messages: Set[str] = set()
        self._running = False

        self.on_new_block = on_new_block
        self.on_new_tx = on_new_tx
        self.on_pbft_message = on_pbft_message

        self._server: Optional[socket.socket] = None
        self._threads: List[threading.Thread] = []

        # ── Métricas ──────────────────────────────────────────────────────────
        self._start_time: float = time.time()
        self._messages_sent: int = 0
        self._messages_received: int = 0
        self._bytes_sent: int = 0
        self._bytes_received: int = 0
        self._stats_lock = threading.Lock()

    # ── Servidor ──────────────────────────────────────────────────────────────

    def start(self) -> None:
        self._running = True
        self._start_time = time.time()
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((self.host, self.port))
        self._server.listen(32)
        logger.info(f"Nodo {self.node_id} escuchando en {self.host}:{self.port}")

        listener = threading.Thread(target=self._accept_loop, daemon=True)
        listener.start()
        self._threads.append(listener)

        heartbeat = threading.Thread(target=self._heartbeat_loop, daemon=True)
        heartbeat.start()
        self._threads.append(heartbeat)

    def stop(self) -> None:
        self._running = False
        if self._server:
            self._server.close()

    def _accept_loop(self) -> None:
        while self._running:
            try:
                conn, addr = self._server.accept()
                t = threading.Thread(
                    target=self._handle_connection,
                    args=(conn, addr),
                    daemon=True,
                )
                t.start()
            except Exception:
                if self._running:
                    logger.exception("Error en accept loop")

    def _handle_connection(self, conn: socket.socket, addr) -> None:
        """Recibe un mensaje del socket y lo despacha. Usa _recv_framed."""
        try:
            message = self._recv_framed(conn)
            self._dispatch(message, conn)
        except Exception:
            logger.exception(f"Error manejando conexión de {addr}")
        finally:
            conn.close()

    # ── Framing (v2) ──────────────────────────────────────────────────────────

    def _send_framed(self, conn: socket.socket, message: dict) -> None:
        """
        Envía un mensaje con length-prefix framing:
        [ 4 bytes big-endian uint32 ][ payload JSON UTF-8 ]
        Actualiza contadores de métricas de forma thread-safe.
        """
        payload = json.dumps(message).encode()
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
        Actualiza contadores de métricas de forma thread-safe.
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
            return json.loads(full.decode().strip())

        # ── Protocolo moderno: length-prefix ─────────────────────────────────
        length = struct.unpack(">I", header)[0]
        if length == 0 or length > self._MAX_PAYLOAD:
            raise ValueError(f"Longitud de mensaje inválida: {length}")
        payload = self._recv_exact(conn, length)
        with self._stats_lock:
            self._messages_received += 1
            self._bytes_received += 4 + length
        return json.loads(payload.decode())

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

    # ── Protocolo de mensajería ───────────────────────────────────────────────

    def _dispatch(self, message: dict, conn: socket.socket) -> None:
        msg_type = message.get("type")
        msg_id = message.get("id", "")

        if msg_id and msg_id in self._seen_messages:
            return
        if msg_id:
            self._seen_messages.add(msg_id)
            if len(self._seen_messages) > 10_000:
                self._seen_messages = set(list(self._seen_messages)[-5000:])

        if msg_type == MSG_HANDSHAKE:
            self._handle_handshake(message, conn)
        elif msg_type == MSG_BLOCK and self.on_new_block:
            self.on_new_block(message["data"])
            self._gossip(message)
        elif msg_type == MSG_TRANSACTION and self.on_new_tx:
            self.on_new_tx(message["data"])
            self._gossip(message)
        elif msg_type == MSG_GET_CHAIN:
            self._send_framed(conn, {"type": MSG_GET_CHAIN})
        elif msg_type == MSG_GET_PEERS:
            peer_list = [p.to_dict() for p in self.peers.values() if p.is_active]
            self._send_framed(conn, {"type": MSG_PEERS, "data": peer_list})
        elif msg_type == MSG_PING:
            self._send_framed(conn, {"type": MSG_PONG, "node_id": self.node_id})
        elif msg_type == MSG_PBFT and self.on_pbft_message:
            self.on_pbft_message(message["data"])
        elif msg_type == MSG_SYNC_REQUEST:
            self._send_framed(conn, {
                "type": MSG_SYNC_RESPONSE,
                "node_id": self.node_id,
                "height": 0,
            })
        elif msg_type == MSG_BLOCK_REQUEST:
            self._send_framed(conn, {"type": MSG_BLOCK_RESPONSE, "data": None})

    def _handle_handshake(self, message: dict, conn: socket.socket) -> None:
        peer_id = message.get("node_id", "unknown")
        peer_host = message.get("host", "")
        peer_port = message.get("port", 0)
        if peer_host and peer_port:
            peer = Peer(host=peer_host, port=peer_port, node_id=peer_id)
            self.peers[peer.address] = peer
            logger.info(f"Par conectado: {peer_id} @ {peer.address}")
        response = {
            "type": MSG_HANDSHAKE,
            "node_id": self.node_id,
            "host": self.host,
            "port": self.port,
        }
        self._send_framed(conn, response)

    # ── Envío de mensajes ─────────────────────────────────────────────────────

    def _send_message(self, conn: socket.socket, message: dict) -> None:
        """Alias de _send_framed para compatibilidad con código existente."""
        self._send_framed(conn, message)

    def broadcast_block(self, block_dict: dict) -> int:
        msg = {"type": MSG_BLOCK, "data": block_dict, "id": str(uuid.uuid4())}
        return self._broadcast(msg)

    def broadcast_transaction(self, tx_dict: dict) -> int:
        msg = {"type": MSG_TRANSACTION, "data": tx_dict, "id": str(uuid.uuid4())}
        return self._broadcast(msg)

    def broadcast_pbft(self, pbft_dict: dict) -> int:
        msg = {"type": MSG_PBFT, "data": pbft_dict, "id": str(uuid.uuid4())}
        return self._broadcast(msg)

    def connect_to_peer(self, host: str, port: int) -> bool:
        try:
            conn = socket.create_connection((host, port), timeout=5)
            handshake = {
                "type": MSG_HANDSHAKE,
                "node_id": self.node_id,
                "host": self.host,
                "port": self.port,
            }
            self._send_framed(conn, handshake)
            conn.close()
            peer = Peer(host=host, port=port)
            self.peers[peer.address] = peer
            logger.info(f"Conectado a {host}:{port}")
            return True
        except Exception as e:
            logger.warning(f"No se pudo conectar a {host}:{port}: {e}")
            return False

    def _broadcast(self, message: dict) -> int:
        sent = 0
        for peer in list(self.peers.values()):
            if not peer.is_active:
                continue
            try:
                conn = socket.create_connection((peer.host, peer.port), timeout=3)
                self._send_framed(conn, message)
                conn.close()
                sent += 1
            except Exception:
                peer.is_active = False
        return sent

    def broadcast_to_subset(self, message: dict, max_peers: int = 3) -> int:
        """
        Envía *message* únicamente a los *max_peers* peers con menor latencia.
        Reduce la carga en redes grandes respecto a ``_broadcast``.
        Retorna el número de peers a los que se envió exitosamente.
        """
        active = sorted(
            [p for p in self.peers.values() if p.is_active],
            key=lambda p: p.latency_ms if p.latency_ms > 0 else float("inf"),
        )
        sent = 0
        for peer in active[:max_peers]:
            try:
                conn = socket.create_connection((peer.host, peer.port), timeout=3)
                self._send_framed(conn, message)
                conn.close()
                sent += 1
            except Exception as e:
                logger.debug(f"broadcast_to_subset: error con {peer.address}: {e}")
                peer.is_active = False
        return sent

    def request_chain_sync(self, peer_address: str) -> Optional[List[dict]]:
        """
        Solicita la cadena completa al peer indicado en formato ``"host:port"``.
        Envía ``MSG_GET_CHAIN`` y espera una respuesta ``MSG_CHAIN`` con la lista
        de bloques serializada.

        Timeout: 30 segundos.
        Retorna lista de dicts de bloques, o ``None`` si la operación falla.
        """
        try:
            parts = peer_address.rsplit(":", 1)
            if len(parts) != 2:
                raise ValueError(f"Dirección inválida: {peer_address!r}")
            host = parts[0]
            port = int(parts[1])
            conn = socket.create_connection((host, port), timeout=30)
            conn.settimeout(30)
            self._send_framed(conn, {"type": MSG_GET_CHAIN, "node_id": self.node_id})
            response = self._recv_framed(conn)
            conn.close()
            if response.get("type") == MSG_CHAIN:
                return response.get("data", [])
            logger.debug(
                f"request_chain_sync: respuesta inesperada de {peer_address}: "
                f"{response.get('type')}"
            )
            return None
        except Exception as e:
            logger.warning(f"request_chain_sync falló para {peer_address}: {e}")
            return None

    def _gossip(self, message: dict) -> None:
        """Re-propaga mensajes a pares distintos al origen."""
        self._broadcast(message)

    # ── Heartbeat ─────────────────────────────────────────────────────────────

    def _heartbeat_loop(self) -> None:
        """
        Envía PING a cada peer cada 30 s.
        Un peer se marca inactivo solo tras ``_FAILED_PING_THRESHOLD`` pings
        consecutivos fallidos (no en el primero), reduciendo falsos negativos
        por fluctuaciones breves de red.
        """
        while self._running:
            time.sleep(30)
            for peer in list(self.peers.values()):
                try:
                    start = time.perf_counter()
                    conn = socket.create_connection((peer.host, peer.port), timeout=3)
                    self._send_framed(conn, {"type": MSG_PING})
                    conn.close()
                    peer.latency_ms = (time.perf_counter() - start) * 1000
                    peer.last_seen = time.time()
                    peer.is_active = True
                    peer.failed_pings = 0
                except Exception:
                    peer.failed_pings += 1
                    if peer.failed_pings >= self._FAILED_PING_THRESHOLD:
                        peer.is_active = False
                        logger.warning(
                            f"Peer {peer.address} marcado inactivo tras "
                            f"{peer.failed_pings} pings fallidos consecutivos"
                        )

    # ── Estadísticas ──────────────────────────────────────────────────────────

    def get_network_stats(self) -> dict:
        active = [p for p in self.peers.values() if p.is_active]
        latencies = [p.latency_ms for p in active if p.latency_ms > 0]
        with self._stats_lock:
            msgs_sent     = self._messages_sent
            msgs_received = self._messages_received
            bytes_sent    = self._bytes_sent
            bytes_received = self._bytes_received
        return {
            "node_id":          self.node_id,
            "address":          f"{self.host}:{self.port}",
            "total_peers":      len(self.peers),
            "active_peers":     len(active),
            "avg_latency_ms":   sum(latencies) / len(latencies) if latencies else 0,
            "uptime_seconds":   time.time() - self._start_time,
            "messages_sent":    msgs_sent,
            "messages_received": msgs_received,
            "bytes_sent":       bytes_sent,
            "bytes_received":   bytes_received,
        }
