"""
Módulo de sincronización de cadena para UPB-Chain.

Protocolo de sincronización
============================
1. Consultar la altura actual de cada peer activo vía HTTP GET /stats.
2. Si algún peer tiene una cadena más larga → solicitar bloques faltantes
   paginando con GET /blocks?offset=N&limit=50.
3. Validar cada bloque recibido (campos obligatorios + blockchain.is_valid_block
   si existe) antes de añadirlo.
4. En caso de fork: resolver con ``resolve_fork``:
   - Cadena más larga gana.
   - Empate en altura → mayor trabajo acumulado (suma de dificultades).

Uso típico
----------
::

    syncer = ChainSynchronizer(blockchain, p2p_node)
    syncer.start_background_sync(interval_seconds=30)
    ...
    stats = syncer.get_sync_stats()
    syncer.stop()

Dependencias
------------
Solo stdlib: ``http.client``, ``json``, ``logging``, ``threading``, ``time``.
"""

import http.client
import json
import logging
import threading
import time
from typing import List, Optional, Any

logger = logging.getLogger("upb_chain.sync")

# Campos mínimos que todo bloque debe tener para ser considerado válido
_BLOCK_REQUIRED_FIELDS: frozenset = frozenset({"index", "hash", "previous_hash", "timestamp"})


class ChainSynchronizer:
    """
    Gestiona la sincronización de la blockchain entre el nodo local y sus peers.

    Protocolo de sincronización:

    1. Pedir a cada peer su altura actual (GET /stats).
    2. Si algún peer tiene cadena más larga → solicitar bloques faltantes.
    3. Validar cada bloque recibido antes de añadirlo.
    4. En caso de fork: resolver con regla de cadena más larga.
    """

    def __init__(self, blockchain: Any, p2p_node: Any) -> None:
        """
        Parameters
        ----------
        blockchain:
            Objeto blockchain local.  Se esperan los atributos/métodos opcionales:
            ``chain`` (list), ``add_block_from_dict(dict)``, ``is_valid_block(dict)``.
        p2p_node:
            Instancia de ``P2PNode``.  Se accede a ``p2p_node.peers``.
        """
        self.blockchain = blockchain
        self.p2p_node = p2p_node

        self._running: bool = False
        self._sync_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # ── Estadísticas ──────────────────────────────────────────────────────
        self._total_syncs: int = 0
        self._last_sync_time: Optional[float] = None
        self._blocks_received: int = 0
        self._conflicts_resolved: int = 0
        self._errors: int = 0

    # ── Sincronización principal ──────────────────────────────────────────────

    def sync_with_peers(self) -> dict:
        """
        Sincroniza con todos los peers activos.

        Returns
        -------
        dict con claves:
            ``blocks_added``, ``peers_synced``, ``conflicts_resolved``, ``errors``.
        """
        result = {
            "blocks_added": 0,
            "peers_synced": 0,
            "conflicts_resolved": 0,
            "errors": 0,
        }

        # Snapshot thread-safe de peers activos
        active_peers = [
            p for p in self.p2p_node.peers.values() if p.is_active
        ]
        if not active_peers:
            return result

        local_height = self._local_height()

        for peer in active_peers:
            try:
                peer_height = self._get_peer_height(peer.host, peer.port)
                if peer_height is None:
                    result["errors"] += 1
                    continue

                if peer_height > local_height:
                    new_blocks = self.request_blocks_since(
                        peer.host, peer.port, local_height + 1
                    )
                    if new_blocks:
                        added = self._apply_blocks(new_blocks)
                        result["blocks_added"] += added
                        local_height += added

                result["peers_synced"] += 1

            except Exception as exc:
                logger.warning(f"Error sincronizando con {peer.address}: {exc}")
                result["errors"] += 1

        with self._lock:
            self._total_syncs += 1
            self._last_sync_time = time.time()
            self._blocks_received += result["blocks_added"]
            self._errors += result["errors"]
            self._conflicts_resolved += result["conflicts_resolved"]

        return result

    # ── Consultas HTTP a peers ────────────────────────────────────────────────

    def _get_peer_height(self, host: str, port: int) -> Optional[int]:
        """Obtiene la altura de la cadena de un peer vía HTTP GET /stats."""
        try:
            conn = http.client.HTTPConnection(host, port, timeout=5)
            conn.request("GET", "/stats")
            resp = conn.getresponse()
            if resp.status == 200:
                data = json.loads(resp.read().decode())
                # Admite tanto "chain_length" como "height"
                return int(data.get("chain_length", data.get("height", 0)))
        except Exception as exc:
            logger.debug(f"_get_peer_height {host}:{port} → {exc}")
        return None

    def request_blocks_since(
        self, peer_host: str, peer_port: int, from_height: int
    ) -> List[dict]:
        """
        Solicita al peer los bloques desde *from_height* hasta su altura actual.
        Pagina con ``GET /blocks?offset=N&limit=50``.

        Returns
        -------
        Lista de dicts de bloques (puede estar vacía si el peer no responde).
        """
        blocks: List[dict] = []
        page_size = 50
        offset = from_height

        while True:
            try:
                conn = http.client.HTTPConnection(peer_host, peer_port, timeout=10)
                conn.request("GET", f"/blocks?offset={offset}&limit={page_size}")
                resp = conn.getresponse()
                if resp.status != 200:
                    break
                raw = resp.read().decode()
                data = json.loads(raw)
                page: List[dict] = data if isinstance(data, list) else data.get("blocks", [])
                if not page:
                    break
                blocks.extend(page)
                if len(page) < page_size:
                    break
                offset += len(page)
            except Exception as exc:
                logger.warning(
                    f"request_blocks_since {peer_host}:{peer_port} offset={offset}: {exc}"
                )
                break

        return blocks

    # ── Aplicación y validación de bloques ───────────────────────────────────

    def _validate_block(self, block_dict: dict) -> bool:
        """
        Valida un bloque recibido comprobando:
        1. Presencia de campos obligatorios.
        2. ``blockchain.is_valid_block`` si el método existe.
        """
        if not _BLOCK_REQUIRED_FIELDS.issubset(block_dict.keys()):
            return False
        if hasattr(self.blockchain, "is_valid_block"):
            return bool(self.blockchain.is_valid_block(block_dict))
        return True

    def _apply_blocks(self, blocks: List[dict]) -> int:
        """
        Valida y añade cada bloque a la cadena local.
        Se detiene ante el primer bloque inválido para evitar corrupción.

        Returns
        -------
        Número de bloques efectivamente añadidos.
        """
        added = 0
        for block_dict in blocks:
            try:
                if not self._validate_block(block_dict):
                    logger.warning(
                        f"Bloque inválido recibido (index={block_dict.get('index', '?')}), "
                        "deteniendo aplicación de lote"
                    )
                    break
                if hasattr(self.blockchain, "add_block_from_dict"):
                    self.blockchain.add_block_from_dict(block_dict)
                elif hasattr(self.blockchain, "chain"):
                    self.blockchain.chain.append(block_dict)
                else:
                    logger.error("blockchain no tiene interfaz conocida para añadir bloques")
                    break
                added += 1
            except Exception as exc:
                logger.warning(
                    f"Error aplicando bloque index={block_dict.get('index', '?')}: {exc}"
                )
                break
        return added

    def _local_height(self) -> int:
        """Retorna la altura actual de la cadena local (índice del último bloque)."""
        if hasattr(self.blockchain, "chain") and self.blockchain.chain:
            last = self.blockchain.chain[-1]
            if isinstance(last, dict):
                return int(last.get("index", len(self.blockchain.chain) - 1))
            return len(self.blockchain.chain) - 1
        return 0

    # ── Resolución de forks ───────────────────────────────────────────────────

    def resolve_fork(
        self, local_chain: List[dict], candidate_chain: List[dict]
    ) -> List[dict]:
        """
        Elige entre dos cadenas válidas.

        Reglas (en orden):
        1. Cadena más larga gana.
        2. Empate en longitud → mayor trabajo acumulado (suma de ``difficulty``).
        3. Empate total → mantener la cadena local.

        Returns
        -------
        La cadena ganadora (``local_chain`` o ``candidate_chain``).
        """
        if len(candidate_chain) > len(local_chain):
            logger.info(
                f"resolve_fork: candidato gana por altura "
                f"({len(candidate_chain)} > {len(local_chain)})"
            )
            return candidate_chain

        if len(candidate_chain) == len(local_chain):
            local_work = sum(int(b.get("difficulty", 0)) for b in local_chain)
            candidate_work = sum(int(b.get("difficulty", 0)) for b in candidate_chain)
            if candidate_work > local_work:
                logger.info(
                    f"resolve_fork: candidato gana por trabajo acumulado "
                    f"({candidate_work} > {local_work})"
                )
                return candidate_chain

        return local_chain

    # ── Background sync ───────────────────────────────────────────────────────

    def start_background_sync(self, interval_seconds: int = 30) -> None:
        """
        Inicia un hilo daemon que llama a ``sync_with_peers`` periódicamente.
        Llama a ``stop()`` antes de volver a llamar a este método.
        """
        if self._running:
            logger.warning("ChainSynchronizer ya está en ejecución; ignora start")
            return
        self._running = True
        self._sync_thread = threading.Thread(
            target=self._sync_loop,
            args=(interval_seconds,),
            daemon=True,
            name="ChainSyncThread",
        )
        self._sync_thread.start()
        logger.info(
            f"Sincronización en background iniciada (intervalo: {interval_seconds}s)"
        )

    def _sync_loop(self, interval_seconds: int) -> None:
        """Bucle interno del hilo de sincronización."""
        while self._running:
            try:
                stats = self.sync_with_peers()
                if stats["blocks_added"] > 0:
                    logger.info(
                        f"Sync completado: +{stats['blocks_added']} bloques, "
                        f"{stats['peers_synced']} peers, "
                        f"{stats['errors']} errores"
                    )
            except Exception:
                logger.exception("Error inesperado en _sync_loop")
            # Esperar en fragmentos pequeños para responder rápido a stop()
            deadline = time.time() + interval_seconds
            while self._running and time.time() < deadline:
                time.sleep(1)

    def stop(self) -> None:
        """Detiene la sincronización en background y espera que el hilo termine."""
        self._running = False
        if self._sync_thread and self._sync_thread.is_alive():
            self._sync_thread.join(timeout=10)
        logger.info("ChainSynchronizer detenido")

    # ── Estadísticas ──────────────────────────────────────────────────────────

    def get_sync_stats(self) -> dict:
        """
        Retorna un snapshot de las estadísticas del sincronizador.

        Claves: ``total_syncs``, ``last_sync_time``, ``blocks_received``,
        ``conflicts_resolved``, ``errors``, ``is_running``.
        """
        with self._lock:
            return {
                "total_syncs":        self._total_syncs,
                "last_sync_time":     self._last_sync_time,
                "blocks_received":    self._blocks_received,
                "conflicts_resolved": self._conflicts_resolved,
                "errors":             self._errors,
                "is_running":         self._running,
            }
