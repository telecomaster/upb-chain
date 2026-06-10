"""
Módulo de descubrimiento de pares para UPB-Chain.

Estrategia de descubrimiento
=============================
1. **Bootstrap** — conectar a los nodos predefinidos en ``BOOTSTRAP_NODES``
   al inicio de la red.
2. **Gossip** — pedir la lista de peers a cada nodo conocido vía
   ``HTTP GET /network/sync`` y agregar los nuevos al registro local.
3. **Persistencia** — guardar los peers conocidos en ``data/peers.json``
   tras cada ciclo de descubrimiento y al detenerse.
4. **Health check** — medir latencia a cada peer registrado periódicamente
   y actualizar ``last_seen`` / ``latency_ms``.

Uso típico
----------
::

    discovery = PeerDiscovery(p2p_node, data_dir="data")
    discovery.bootstrap()
    discovery.start_background_discovery(interval_seconds=60)
    best = discovery.get_best_peers(n=3)
    ...
    discovery.stop()

Dependencias
------------
Solo stdlib: ``http.client``, ``json``, ``logging``, ``os``,
``socket``, ``threading``, ``time``.
"""

import http.client
import json
import logging
import os
import socket
import threading
import time
from typing import Dict, List, Optional, Any

logger = logging.getLogger("upb_chain.discovery")

# ── Nodos de bootstrap de la red UPB (IPs fijas de los RPi5) ─────────────────
BOOTSTRAP_NODES: List[dict] = [
    {"host": "192.168.1.101", "port": 8001, "name": "UPB-Node-1"},
    {"host": "192.168.1.102", "port": 8003, "name": "UPB-Node-2"},
]

# Tiempo máximo sin respuesta para considerar un peer no alcanzable (segundos)
_PEER_STALE_SECONDS = 300


class PeerDiscovery:
    """
    Descubrimiento y mantenimiento de la lista de peers conocidos.

    Estrategia:
    1. Bootstrap: conectar a nodos predefinidos al inicio.
    2. Gossip: pedir lista de peers a cada peer conocido (GET /network/sync).
    3. Persistencia: guardar peers conocidos en disco (data/peers.json).
    4. Health check: validar peers periódicamente midiendo latencia.
    """

    def __init__(self, p2p_node: Any, data_dir: str = "data") -> None:
        """
        Parameters
        ----------
        p2p_node:
            Instancia de ``P2PNode``.
        data_dir:
            Directorio donde se persiste ``peers.json``.
            Se crea automáticamente si no existe.
        """
        self.p2p_node = p2p_node
        self.data_dir = data_dir

        # {host:port → peer_dict}
        self._known_peers: Dict[str, dict] = {}
        self._lock = threading.Lock()

        self._running: bool = False
        self._discovery_thread: Optional[threading.Thread] = None

        # Asegurar que el directorio de datos existe
        os.makedirs(data_dir, exist_ok=True)

        # Cargar peers persistidos del ciclo anterior
        for peer in self.load_known_peers():
            key = f"{peer['host']}:{peer['port']}"
            self._known_peers[key] = peer

    # ── Bootstrap ─────────────────────────────────────────────────────────────

    def bootstrap(self) -> int:
        """
        Intenta conectar a cada nodo en ``BOOTSTRAP_NODES``.
        Para cada conexión exitosa, solicita la lista de peers de ese nodo
        y los agrega al registro local.

        Returns
        -------
        Número de nodos bootstrap a los que se conectó exitosamente.
        """
        successes = 0
        for node in BOOTSTRAP_NODES:
            host, port, name = node["host"], node["port"], node.get("name", "")
            try:
                connected = self.p2p_node.connect_to_peer(host, port)
                if not connected:
                    continue

                latency = self._measure_latency(host, port)
                key = f"{host}:{port}"
                with self._lock:
                    self._known_peers[key] = {
                        "host": host,
                        "port": port,
                        "name": name,
                        "node_id": "",
                        "last_seen": time.time(),
                        "latency_ms": latency if latency is not None else 0.0,
                    }
                successes += 1
                logger.info(f"Bootstrap conectado: {name} ({host}:{port})")

                # Gossip desde el nodo recién conectado
                discovered = self.discover_from_peer(host, port)
                for peer in discovered:
                    peer_key = f"{peer['host']}:{peer['port']}"
                    with self._lock:
                        if peer_key not in self._known_peers:
                            self._known_peers[peer_key] = peer
                    # Intentar conectar al nuevo peer (no crítico si falla)
                    try:
                        self.p2p_node.connect_to_peer(peer["host"], peer["port"])
                    except Exception:
                        pass

            except Exception as exc:
                logger.warning(f"Bootstrap falló para {name} ({host}:{port}): {exc}")

        if successes > 0:
            self.save_known_peers()

        return successes

    # ── Descubrimiento via HTTP ───────────────────────────────────────────────

    def discover_from_peer(self, host: str, port: int) -> List[dict]:
        """
        Pide la lista de peers a un nodo vía ``HTTP GET /network/sync``.
        Normaliza la respuesta a una lista de dicts con ``host``, ``port``,
        ``node_id``, ``last_seen``, ``latency_ms``.

        Returns
        -------
        Lista de peers descubiertos (puede estar vacía si el nodo no responde).
        """
        peers: List[dict] = []
        try:
            conn = http.client.HTTPConnection(host, port, timeout=5)
            conn.request("GET", "/network/sync")
            resp = conn.getresponse()
            if resp.status != 200:
                return peers
            data = json.loads(resp.read().decode())
            raw_peers: List[dict] = (
                data if isinstance(data, list) else data.get("peers", [])
            )
            for p in raw_peers:
                if not isinstance(p, dict):
                    continue
                if "host" not in p or "port" not in p:
                    continue
                peers.append({
                    "host":       p["host"],
                    "port":       int(p["port"]),
                    "node_id":    p.get("node_id", ""),
                    "name":       p.get("name", ""),
                    "last_seen":  time.time(),
                    "latency_ms": 0.0,
                })
        except Exception as exc:
            logger.debug(f"discover_from_peer {host}:{port}: {exc}")
        return peers

    # ── Persistencia ──────────────────────────────────────────────────────────

    def save_known_peers(self) -> None:
        """Serializa los peers conocidos en ``<data_dir>/peers.json``."""
        path = os.path.join(self.data_dir, "peers.json")
        try:
            with self._lock:
                peers_list = list(self._known_peers.values())
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(peers_list, fh, indent=2)
            logger.debug(f"Guardados {len(peers_list)} peers en {path}")
        except Exception as exc:
            logger.warning(f"No se pudo guardar peers en {path}: {exc}")

    def load_known_peers(self) -> List[dict]:
        """
        Carga los peers persistidos desde ``<data_dir>/peers.json``.

        Returns
        -------
        Lista de dicts de peers, o lista vacía si el archivo no existe o
        está corrupto.
        """
        path = os.path.join(self.data_dir, "peers.json")
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                if isinstance(data, list):
                    logger.debug(f"Cargados {len(data)} peers desde {path}")
                    return data
        except Exception as exc:
            logger.warning(f"No se pudo cargar peers desde {path}: {exc}")
        return []

    # ── Medición de latencia ──────────────────────────────────────────────────

    def _measure_latency(self, host: str, port: int) -> Optional[float]:
        """
        Mide la latencia de conexión TCP a ``host:port`` en milisegundos.

        Returns
        -------
        Latencia en ms, o ``None`` si el peer no es alcanzable.
        """
        try:
            start = time.perf_counter()
            conn = socket.create_connection((host, port), timeout=3)
            conn.close()
            return (time.perf_counter() - start) * 1000
        except Exception:
            return None

    # ── Selección de mejores peers ────────────────────────────────────────────

    def get_best_peers(self, n: int = 3) -> List[dict]:
        """
        Mide la latencia actual de todos los peers conocidos y retorna los
        *n* más rápidos y alcanzables, ordenados de menor a mayor latencia.

        Returns
        -------
        Lista de hasta *n* dicts de peers con ``latency_ms`` actualizado.
        """
        with self._lock:
            peers_snapshot = list(self._known_peers.values())

        reachable: List[dict] = []
        for peer in peers_snapshot:
            latency = self._measure_latency(peer["host"], peer["port"])
            if latency is not None:
                peer_copy = dict(peer)
                peer_copy["latency_ms"] = latency
                peer_copy["last_seen"] = time.time()
                reachable.append(peer_copy)

        reachable.sort(key=lambda p: p["latency_ms"])
        return reachable[:n]

    # ── Health check ──────────────────────────────────────────────────────────

    def _health_check(self) -> None:
        """
        Verifica la alcanzabilidad de todos los peers conocidos.
        Actualiza ``latency_ms`` y ``last_seen`` para los alcanzables.
        """
        with self._lock:
            items = list(self._known_peers.items())

        for key, peer in items:
            latency = self._measure_latency(peer["host"], peer["port"])
            with self._lock:
                if key not in self._known_peers:
                    continue
                if latency is not None:
                    self._known_peers[key]["latency_ms"] = latency
                    self._known_peers[key]["last_seen"] = time.time()
                else:
                    logger.debug(f"Peer {key} no alcanzable en health check")

    # ── Background discovery ──────────────────────────────────────────────────

    def start_background_discovery(self, interval_seconds: int = 60) -> None:
        """
        Inicia un hilo daemon que ejecuta periódicamente:
        health check + gossip + persistencia.
        """
        if self._running:
            logger.warning("PeerDiscovery ya está en ejecución; ignora start")
            return
        self._running = True
        self._discovery_thread = threading.Thread(
            target=self._discovery_loop,
            args=(interval_seconds,),
            daemon=True,
            name="PeerDiscoveryThread",
        )
        self._discovery_thread.start()
        logger.info(
            f"Descubrimiento en background iniciado (intervalo: {interval_seconds}s)"
        )

    def _discovery_loop(self, interval_seconds: int) -> None:
        """Bucle interno del hilo de descubrimiento."""
        while self._running:
            try:
                # 1. Health check de peers conocidos
                self._health_check()

                # 2. Gossip: descubrir nuevos peers de los conocidos
                with self._lock:
                    current_peers = list(self._known_peers.values())

                for peer in current_peers:
                    if not self._running:
                        break
                    discovered = self.discover_from_peer(peer["host"], peer["port"])
                    for np in discovered:
                        np_key = f"{np['host']}:{np['port']}"
                        with self._lock:
                            if np_key not in self._known_peers:
                                self._known_peers[np_key] = np
                                logger.info(f"Nuevo peer descubierto via gossip: {np_key}")
                        # Conectar al nuevo peer si aún no está registrado en P2P
                        if np_key not in self.p2p_node.peers:
                            try:
                                self.p2p_node.connect_to_peer(np["host"], np["port"])
                            except Exception:
                                pass

                # 3. Persistir estado actual
                self.save_known_peers()

            except Exception:
                logger.exception("Error inesperado en _discovery_loop")

            # Esperar en fragmentos pequeños para responder rápido a stop()
            deadline = time.time() + interval_seconds
            while self._running and time.time() < deadline:
                time.sleep(1)

    def stop(self) -> None:
        """Detiene el descubrimiento en background, persiste el estado y espera al hilo."""
        self._running = False
        if self._discovery_thread and self._discovery_thread.is_alive():
            self._discovery_thread.join(timeout=10)
        self.save_known_peers()
        logger.info("PeerDiscovery detenido")

    # ── Estadísticas ──────────────────────────────────────────────────────────

    def get_discovery_stats(self) -> dict:
        """
        Retorna estadísticas del módulo.

        Claves: ``total_known_peers``, ``reachable_peers``,
        ``is_running``, ``bootstrap_nodes``.
        """
        with self._lock:
            total = len(self._known_peers)
            reachable = sum(
                1 for p in self._known_peers.values()
                if p.get("latency_ms", 0) > 0
                and (time.time() - p.get("last_seen", 0)) < _PEER_STALE_SECONDS
            )
        return {
            "total_known_peers": total,
            "reachable_peers":   reachable,
            "is_running":        self._running,
            "bootstrap_nodes":   len(BOOTSTRAP_NODES),
        }
