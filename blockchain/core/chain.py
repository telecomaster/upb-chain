"""
UPB-Chain — Cadena de Bloques Principal
Universidad Privada Boliviana · Carrera de Ingeniería en IA

Implementa la estructura de datos "blockchain" como una lista enlazada
criptográficamente donde cada nodo contiene:
    - hash del bloque anterior    → garantiza orden e inmutabilidad
    - raíz Merkle de TXs          → verifica integridad del contenido
    - hash propio                 → sello del bloque completo

Invariante de clase (mantenida por validate_chain):
    ∀ i ∈ [1, len(chain)): chain[i].header.previous_hash == chain[i-1].hash
    ∀ i ∈ [0, len(chain)): chain[i].compute_hash() == chain[i].hash

Propiedades de seguridad:
    Modificar un bloque en posición i invalida todos los bloques i+1..n,
    porque cada hash incluye el hash anterior (efecto avalancha en la cadena).

Manejo de forks (fork resolution):
    Regla del mayor trabajo acumulado: ante dos cadenas válidas con el mismo
    génesis se acepta la de mayor Σ 2**bits (no la más larga, P2-5); en
    empate se conserva la propia. Es la regla de Nakamoto.
    Ref: Nakamoto (2008), Sección 5.

Modo de consenso (P1-1, ``consensus``):
    "pow" (por defecto): dificultad por bits y regla del mayor trabajo.
    "pbft": los bloques no se minan; cada bloque > 0 lleva dificultad 0 y
        nonce 0 y solo entra con un CERTIFICADO DE COMMIT válido (2f+1 COMMIT
        firmados por réplicas de ``replica_set``), guardado aparte del bloque.
        Al sincronizar se verifican certificados en vez de trabajo; nunca se
        reemplazan bloques ya certificados (dos bloques certificados en la
        misma altura = violación de seguridad, se avisa a
        ``on_certified_conflict``). El génesis es el mismo en ambos modos.

Persistencia (P2-4): ``storage.ChainStore`` en ``<data_dir>/chain.db`` (SQLite).
    Cada bloque es un INSERT en una transacción; un reorg borra e inserta solo
    las alturas que cambian. La lista ``self.chain`` se sigue manteniendo en
    memoria (la usan la validación, la red y la API); el disco ya no se
    reescribe entero y las búsquedas por id/dirección/hash usan los índices.

Arranque (``revalidate_on_start``):
    "fast" (por defecto): verificación barata de TODOS los bloques (enlaces,
        hash, dificultad, PoW y raíz Merkle; sin firmas ni contratos) + estado
        desde la última foto (``snapshots``) + validación completa de los
        bloques posteriores a la foto.
    "full": validación de consenso completa desde el génesis (firmas y
        contratos), como antes de P2-4; además rehace las fotos.

Complejidades:
    add_transaction()  → O(m) donde m = tamaño del mempool (búsqueda de duplicados)
    add_block()        → O(n) donde n = número de TXs en el bloque (+ un INSERT)
    validate_chain()   → O(H * n) donde H = altura, n = TXs por bloque
    get_transaction()  → O(log N) por el índice de TXs de chain.db
    get_credentials_for() → O(log N + k) por el índice de destinatarios
    replace_chain()    → O(S * n) en firmas y contratos, S = bloques nuevos desde la
                         bifurcación (+ O(H') hashes baratos del prefijo común)

Thread safety:
    _lock (threading.Lock) protege chain y mempool de escrituras concurrentes.
    Las lecturas no adquieren el lock (trade-off aceptable para un nodo académico).
"""
import json
import logging
import math
import os
import sqlite3
import time
from pathlib import Path
from threading import Lock
from typing import Callable, Dict, List, Optional, Tuple

from blockchain.contracts import default_contracts
from blockchain.contracts.accounts import AccountContract, Accounts
from blockchain.contracts.base import Contract
from blockchain.contracts.registry import ContractRegistry
from blockchain.core.block import (GENESIS_HASH, Block, BlockHeader, hash_meets_bits,
                                   work_for_bits)
from blockchain.core.limits import (MAX_BLOCK_BYTES, MAX_BLOCK_TXS, check_block_size,
                                    serialized_size)
from blockchain.core.storage import ChainStore, Snapshot
from blockchain.core.transaction import Transaction, TransactionType

logger = logging.getLogger("upb_chain.core")


def retarget_step(expected_ms: int, actual_ms: int, max_step: int) -> int:
    """Cuántos bits sumar a la dificultad: round(log2(esperado / real)), acotado a ±max_step.

    Si la ventana tardó la mitad de lo esperado, el trabajo debe duplicarse: +1 bit;
    si tardó un cuarto, +2; si tardó el doble, -1. Se redondea al entero más
    cercano en escala logarítmica, es decir, el umbral entre k y k+1 bits está
    en razón = 2**(k + 1/2). Para no usar floats ni raíces se compara al cuadrado:

        log2(e/r) >= k + 1/2   ⇔   e² >= r² · 2**(2k + 1)        (k >= 0)
        log2(e/r) <  -(m + 1/2) ⇔   e² · 2**(2m + 1) < r²          (m >= 0)

    Sólo enteros (desplazamientos de bits): misma respuesta en cualquier máquina.
    `actual_ms <= 0` (timestamps iguales o desordenados) cuenta como "muy rápido".
    """
    if actual_ms <= 0:
        return max_step
    e2 = expected_ms * expected_ms
    r2 = actual_ms * actual_ms
    step = 0
    while step < max_step and e2 >= r2 << (2 * step + 1):
        step += 1
    if step == 0:
        while step > -max_step and (e2 << (2 * -step + 1)) < r2:
            step -= 1
    return step


def _ms(timestamp) -> int:
    """Timestamp del encabezado (segundos) a milisegundos enteros."""
    return int(timestamp * 1000)


class Blockchain:
    # Ventana de timestamps para la mediana (estilo Bitcoin) y tolerancia al futuro.
    MEDIAN_WINDOW = 11
    MAX_FUTURE_SECONDS = 2 * 3600
    # Estados de contratos recientes que se guardan en memoria (ver _recent_states).
    RECENT_STATES = 16

    def __init__(
        self,
        node_id: str,
        data_dir: str = "data/chain",
        initial_difficulty: int = 16,
        min_difficulty: int = 1,
        max_difficulty: int = 32,
        target_block_time: float = 10.0,
        difficulty_window: int = 10,
        max_bits_step: int = 2,
        authority_address: Optional[str] = None,
        contracts: Optional[List[Contract]] = None,
        revalidate_on_start: str = "fast",
        snapshot_interval: int = 100,
        consensus: str = "pow",
        replica_set=None,
        mempool_max: int = 5000,
        mempool_max_per_sender: int = 64,
    ):
        if revalidate_on_start not in ("fast", "full"):
            raise ValueError("revalidate_on_start debe ser 'fast' o 'full'")
        if consensus not in ("pow", "pbft"):
            raise ValueError("consensus debe ser 'pow' o 'pbft'")
        if consensus == "pbft" and replica_set is None:
            raise ValueError("el modo pbft necesita el conjunto de réplicas (replica_set)")
        self.node_id = node_id
        # Modo de consenso (P1-1). En pbft, ``replica_set`` (ReplicaSet) verifica
        # los certificados de commit; ``certificates`` = {altura: certificado}.
        self.consensus = consensus
        self.replica_set = replica_set
        self.certificates: Dict[int, dict] = {}
        self.on_certified_conflict: List[Callable[[int, str, str], None]] = []
        # Arranque y fotos de estado (P2-4): ver el docstring del módulo.
        self.revalidate_on_start = revalidate_on_start
        self.snapshot_interval = max(0, int(snapshot_interval))   # 0 = sin fotos
        # Parámetros de la regla de dificultad (parte del consenso: deben ser
        # iguales en todos los nodos de la red). Dificultades en BITS (P2-5).
        self.initial_difficulty = initial_difficulty
        self.min_difficulty = min_difficulty
        self.max_difficulty = max_difficulty
        self.target_block_time = target_block_time
        # Objetivo en milisegundos enteros: la regla de ajuste no usa floats.
        self.target_block_ms = int(round(target_block_time * 1000))
        self.difficulty_window = difficulty_window
        self.max_bits_step = max_bits_step
        self._confirmed_ids: set = set()
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.chain: List[Block] = []
        self.mempool: List[Transaction] = []
        # Tope del mempool (política local, no consenso): total y por remitente.
        self.mempool_max = max(1, int(mempool_max))
        self.mempool_max_per_sender = max(1, int(mempool_max_per_sender))
        # Estado especulativo = confirmado + mempool, mantenido de forma incremental.
        self._spec: Optional[dict] = None
        self._lock = Lock()
        # Contratos (P1-13): reglas de consenso sobre el estado derivado de la
        # cadena. El de cuentas (P0-9: saldo y nonce) va siempre primero; luego
        # los de aplicación (por defecto credenciales y votación). Se fijan al
        # construir la cadena porque la carga desde disco ya los necesita para
        # validar. ``authority_address`` firma TOKEN_MINT e ISSUER_REGISTER.
        if contracts is None:
            contracts = default_contracts(authority_address)
        self.contracts = ContractRegistry([AccountContract(authority_address), *contracts])
        # Avisos de reorganización para red/log (P0-5): ver add_reorg_listener().
        self.on_chain_reorg: List[Callable[[int, List[Block], List[Block]], None]] = []
        # Bloques validados por completo (firmas + contratos) al arrancar (P2-4).
        self.replayed_on_start = 0
        # Anillo de estados recientes (P2-4, reorg desde la bifurcación):
        # {altura: (hash del bloque, estados tras ese bloque)} de los últimos
        # ``recent_states_kept`` bloques. Los estados no se modifican nunca
        # (copia al escribir en ContractRegistry), así que guardar la referencia
        # basta. Permite reorganizar cerca de la punta sin reproducir nada.
        self.recent_states_kept = self.RECENT_STATES
        self._recent_states: Dict[int, Tuple[str, dict]] = {}
        # Bloques que validó por completo el último replace_chain (pruebas y logs).
        self.last_replace_validated = 0

        self._load_or_init()

    # ── Inicialización (P2-4: chain.db) ──────────────────────────────────────

    def _load_or_init(self) -> None:
        self.store = ChainStore(self.data_dir / "chain.db")
        json_file = self.data_dir / "chain.json"
        bak_file = self.data_dir / "chain.json.bak"
        if self.store.tip_height() is not None:
            if json_file.exists():
                logger.warning("Existe chain.json pero los datos están en chain.db; "
                               "chain.json se ignora")
            self._load_from_store()
            return
        if json_file.exists() or bak_file.exists():
            self._migrate_from_json(json_file, bak_file)
            return
        genesis = Block.create_genesis(self.node_id)
        self.store.append_block(genesis)
        self.chain.append(genesis)
        self._confirmed_ids = self._collect_ids(self.chain)
        self.contracts.rebuild(self.chain)
        logger.info("Génesis creado")

    def close(self) -> None:
        """Cierra chain.db (opcional: el recolector de basura también la cierra)."""
        self.store.close()

    # Migración desde chain.json (P1-8 → P2-4) ───────────────────────────────

    def _migrate_from_json(self, json_file: Path, bak_file: Path) -> None:
        """Importa chain.json a chain.db con validación COMPLETA y lo renombra.

        El archivo no se borra: queda como ``chain.json.migrated`` (y el
        respaldo como ``chain.json.bak.migrated``). Si chain.json no se puede
        leer se usa el respaldo, como en P1-8. Si el proceso se corta entre la
        importación y el renombre, al reiniciar manda chain.db y chain.json
        solo se ignora (con un aviso).
        """
        try:
            data = self._read_json(json_file)
            source = json_file
        except (OSError, ValueError) as e:
            if not bak_file.exists():
                raise ValueError(f"{json_file}: no se pudo leer: {e}") from e
            logger.warning(f"chain.json no legible ({e}); se importa el respaldo chain.json.bak")
            data = self._read_json(bak_file)
            source = bak_file
        states = self._install_chain(data, source)
        self.store.import_chain(self.chain, self._make_snapshot(self.last_block, states))
        for f in (json_file, bak_file):
            if f.exists():
                os.replace(f, self._free_name(f.with_name(f.name + ".migrated")))
        logger.info(f"chain.json migrado a chain.db: {len(self.chain)} bloques "
                    f"(original guardado como chain.json.migrated)")

    @staticmethod
    def _free_name(path: Path) -> Path:
        """``path`` o ``path.1``, ``path.2``… el primero que no exista (no pisar datos)."""
        candidate, n = path, 0
        while candidate.exists():
            n += 1
            candidate = path.with_name(f"{path.name}.{n}")
        return candidate

    @staticmethod
    def _read_json(path: Path) -> list:
        """Lee y decodifica el JSON de la cadena. Lanza OSError o ValueError."""
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def _install_chain(self, data: list, path: Path) -> dict:
        """Valida `data` (lista de bloques serializados) por COMPLETO y la adopta.

        Devuelve el estado de los contratos en la punta.
        """
        chain = [Block.from_dict(b) for b in data]
        ok, reason = self._check_genesis(chain)
        if not ok:
            raise ValueError(f"{path}: {reason}")
        if self.consensus == "pbft":
            ok, reason = self._check_certificates(chain, self.certificates)
            if not ok:
                raise ValueError(f"{path}: {reason}")
        # Revalidar TODA la cadena (P0-3): un archivo manipulado se rechaza.
        # La misma pasada deja el estado de los contratos (P1-13).
        ok, reason, states = self._replay_blocks(chain)
        if not ok:
            raise ValueError(f"{path}: cadena inválida en disco: {reason}")
        self.chain = chain
        self._confirmed_ids = self._collect_ids(chain)
        self.contracts.commit(states, len(chain) - 1)
        self.replayed_on_start = len(chain) - 1
        return states

    # Arranque desde chain.db ─────────────────────────────────────────────────

    def _load_from_store(self) -> None:
        path = self.store.path
        try:
            chain = [Block.from_dict(b) for b in self.store.load_blocks()]
        except (KeyError, TypeError, ValueError) as e:
            raise ValueError(f"{path}: bloque ilegible en disco: {e}") from e
        if self.consensus == "pbft":
            self.certificates = self.store.load_certificates()
            ok, reason = self._check_certificates(chain, self.certificates)
            if not ok:
                raise ValueError(f"{path}: cadena inválida en disco para el modo pbft: {reason} "
                                 f"(¿DATA_DIR de una red PoW? usar otro directorio)")
        if self.revalidate_on_start == "full":
            states = self._install_chain([b.to_dict() for b in chain], path)
            # Las fotos viejas se descartan (p. ej. si cambiaron las reglas de
            # un contrato) y se rehace una con el estado recién reproducido.
            self.store.reset_snapshots(self._make_snapshot(self.last_block, states))
            logger.info(f"Cadena cargada con revalidación completa: {len(chain)} bloques")
            return
        self._restore_fast(chain, path)

    def _restore_fast(self, chain: List[Block], path: Path) -> None:
        """Arranque rápido: verificación barata + foto + reproducción de lo posterior.

        Modelo de amenazas: la foto se cree porque la escribió ESTE nodo tras
        validar los bloques que resume; su SHA-256 detecta daños del medio
        (microSD), no a alguien con permiso de escritura en DATA_DIR (ese
        podría cambiar también el código). Ante la duda: REVALIDATE_ON_START=full.
        """
        ok, reason = self._verify_headers(chain)
        if not ok:
            raise ValueError(f"{path}: cadena inválida en disco: {reason} "
                             f"(verificación rápida al arrancar)")
        base, states = self._latest_snapshot(chain)
        seen = self._collect_ids(chain[:base + 1])
        now = time.time()
        for i in range(base + 1, len(chain)):
            ok, reason, states = self._validate_block_at(
                chain[i], chain[:i], seen, now,
                lambda block, st=states: self.contracts.run_block(st, block))
            if not ok:
                raise ValueError(f"{path}: cadena inválida en disco: Bloque {i}: {reason}")
        self.chain = chain
        self._confirmed_ids = self._collect_ids(chain)
        self.contracts.commit(states, len(chain) - 1)
        self.replayed_on_start = self.height - base   # para logs y pruebas
        if self.snapshot_interval and self.replayed_on_start >= self.snapshot_interval:
            snap = self._make_snapshot(self.last_block, states)
            if snap is not None:
                self.store.put_snapshot(snap)
        logger.info(f"Cadena cargada (arranque rápido): {len(chain)} bloques, estado desde "
                    f"la altura {base}, {self.replayed_on_start} bloque(s) reproducido(s)")

    def _verify_headers(self, chain: List[Block]) -> Tuple[bool, str]:
        """Verificación barata de toda la cadena: sin firmas ECDSA ni contratos.

        Por bloque: índice, enlace con el anterior, hash, dificultad exigida,
        PoW y raíz Merkle (que ata las TXs guardadas al encabezado). Son solo
        hashes SHA-256 y enteros; lo caro de validar (firmas y contratos) es lo
        que ahorra la foto de estado.
        """
        ok, reason = self._check_genesis(chain)
        if not ok:
            return False, reason
        for i in range(1, len(chain)):
            block, h = chain[i], chain[i].header
            if h.index != i:
                return False, f"Bloque {i}: índice {h.index} fuera de lugar"
            if h.previous_hash != chain[i - 1].hash:
                return False, f"Bloque {i}: hash previo no coincide"
            if block.compute_hash() != block.hash:
                return False, f"Bloque {i}: hash del bloque inválido"
            if h.difficulty != self.expected_difficulty(chain[:i]):
                return False, f"Bloque {i}: dificultad incorrecta"
            if not hash_meets_bits(block.hash, h.difficulty):
                return False, f"Bloque {i}: Proof of Work insuficiente"
            if Block.compute_merkle_root(block.transactions) != h.merkle_root:
                return False, f"Bloque {i}: Merkle root inválido"
        return True, "OK"

    def _latest_snapshot(self, chain: List[Block],
                         max_height: Optional[int] = None) -> Tuple[int, dict]:
        """``(altura, estados)`` de la foto más alta utilizable, o ``(0, iniciales)``.

        Se descarta una foto si está por encima de la punta (o de ``max_height``),
        si su bloque no es el de la cadena en esa altura, si los contratos no son
        los mismos o si su SHA-256 no coincide (dañada). Sin foto se reproduce
        desde el génesis.
        """
        names = ",".join(self.contracts.names)
        top = len(chain) - 1 if max_height is None else min(max_height, len(chain) - 1)
        for snap in self.store.snapshots():
            if snap.height > top or chain[snap.height].hash != snap.block_hash:
                continue
            if snap.contracts != names:
                logger.info(f"Foto de la altura {snap.height} con otros contratos; se ignora")
                continue
            if not snap.is_intact():
                logger.warning(f"Foto de la altura {snap.height} dañada (SHA-256); se ignora")
                continue
            try:
                return snap.height, self.contracts.load_states(snap.states)
            except (ValueError, KeyError, TypeError) as e:
                logger.warning(f"Foto de la altura {snap.height} ilegible ({e}); se ignora")
        return 0, self.contracts.initial_states()

    def _make_snapshot(self, block: Block, states: dict) -> Optional[Snapshot]:
        """Foto de ``states`` tras ``block`` (None si las fotos están apagadas,
        si es el génesis o si algún estado no se pudo pasar a JSON)."""
        if not self.snapshot_interval or block.header.index <= 0:
            return None
        try:
            text = self.contracts.dump_states(states)
        except (TypeError, ValueError) as e:
            logger.warning(f"No se pudo serializar el estado de los contratos: {e}")
            return None
        return Snapshot.build(block.header.index, block.hash, self.contracts.names, text)

    def _snapshot_due(self, from_height: int, to_height: int) -> bool:
        """¿Hay un múltiplo de ``snapshot_interval`` en (from_height, to_height]?"""
        n = self.snapshot_interval
        return bool(n) and to_height // n > from_height // n

    @staticmethod
    def _collect_ids(chain: List[Block]) -> set:
        return {tx.get("tx_id") for b in chain for tx in b.transactions}

    @staticmethod
    def _check_genesis(chain: List[Block]) -> Tuple[bool, str]:
        """El bloque 0 debe ser exactamente el génesis fijo (P0-1)."""
        if not chain:
            return False, "Cadena vacía"
        if chain[0].hash != GENESIS_HASH or chain[0].compute_hash() != GENESIS_HASH:
            return False, "Génesis distinto al de la red (GENESIS_HASH no coincide)"
        return True, "OK"

    # ── Propiedades ───────────────────────────────────────────────────────────

    @property
    def last_block(self) -> Block:
        return self.chain[-1]

    @property
    def height(self) -> int:
        return len(self.chain) - 1

    # ── Estado de los contratos (P0-6, P1-13) ──────────────────────────────────

    @property
    def accounts(self) -> Accounts:
        """Estado confirmado del contrato de cuentas (P0-9)."""
        return self.contracts.state("accounts")

    def contract_state(self, name: str):
        """Estado confirmado del contrato ``name`` (``ContractRegistry.state``)."""
        return self.contracts.state(name)

    def pending_dicts(self) -> List[dict]:
        """TXs del mempool como dicts, en orden de llegada."""
        with self._lock:
            return [t.to_dict() for t in self.mempool]

    # ── Mempool ───────────────────────────────────────────────────────────────

    def add_transaction(self, tx: Transaction) -> Tuple[bool, str]:
        valid, reason = tx.is_valid()
        if not valid:
            return False, reason
        # Todo bajo el lock: la red (P0-5) admite TXs desde otros hilos.
        with self._lock:
            if tx.tx_id in self._confirmed_ids:
                return False, "Transacción ya confirmada en la cadena"
            if any(t.tx_id == tx.tx_id for t in self.mempool):
                return False, "Transacción duplicada"
            # Tope del mempool (política local): se rechaza la TX nueva y no se
            # desaloja nada; así un atacante no expulsa TXs legítimas ya
            # admitidas. Además un remitente no puede ocupar más de
            # ``mempool_max_per_sender`` plazas (una dirección nueva con nonce 1
            # y fee 0 es admisible, así que el límite por dirección no basta).
            if len(self.mempool) >= self.mempool_max:
                return False, f"Mempool lleno ({self.mempool_max} TX pendientes)"
            spec = self._speculative()
            if spec["per_sender"].get(tx.sender, 0) >= self.mempool_max_per_sender:
                return False, (f"Demasiadas TX pendientes de este remitente "
                               f"(máximo {self.mempool_max_per_sender})")
            # Mismas reglas que en un bloque, contra confirmado + pendientes (P1-13),
            # sobre la copia de trabajo incremental (sin reproducir el mempool).
            valid, reason = self.contracts.speculative_admit(
                spec["working"], spec["copied"], tx.to_dict(), self._next_block_timestamp())
            if not valid:
                return False, reason
            self.mempool.append(tx)
            spec["n"] += 1
            spec["last"] = tx
            spec["per_sender"][tx.sender] = spec["per_sender"].get(tx.sender, 0) + 1
        logger.debug(f"TX {tx.tx_id[:8]}… añadida al mempool")
        return True, "OK"

    def _speculative(self) -> dict:
        """Copia de trabajo confirmado + mempool (llamar con ``_lock``).

        Se reconstruye (una pasada, O(m)) si cambió el estado confirmado o el
        mempool se modificó por otra vía (bloque nuevo, reorg, poda); entre
        cambios, cada admisión solo valida y aplica SU TX.
        """
        spec = self._spec
        if (spec is not None and spec["base"] is self.contracts._states
                and spec["n"] == len(self.mempool)
                and (not self.mempool or spec["last"] is self.mempool[-1])):
            return spec
        working, copied, base = self.contracts.speculative_start()
        ts = self._next_block_timestamp()
        per_sender: Dict[str, int] = {}
        for t in self.mempool:
            # Las pendientes que ya no son válidas se saltan (el minero tampoco las incluye).
            self.contracts.speculative_admit(working, copied, t.to_dict(), ts)
            per_sender[t.sender] = per_sender.get(t.sender, 0) + 1
        self._spec = {"base": base, "working": working, "copied": copied,
                      "n": len(self.mempool), "per_sender": per_sender,
                      "last": self.mempool[-1] if self.mempool else None}
        return self._spec

    def check_batch(self, txs: List[Transaction]) -> List[Tuple[bool, str]]:
        """Simula admitir ``txs`` en orden, sin tocar el mempool (P1-12, carga CSV).

        Cada TX se valida contra confirmado + mempool + las TXs anteriores del
        lote que resultaron válidas. Devuelve ``(ok, motivo)`` por TX.
        """
        results: List[Tuple[bool, str]] = []
        with self._lock:
            pending = [t.to_dict() for t in self.mempool]
            timestamp = self._next_block_timestamp()
            for tx in txs:
                ok, reason = tx.is_valid()
                if ok:
                    ok, reason = self.contracts.check_transaction(
                        tx.to_dict(), pending, timestamp)
                if ok:
                    pending.append(tx.to_dict())
                results.append((ok, reason))
        return results

    def _next_block_timestamp(self) -> float:
        """Hora estimada del próximo bloque (la misma regla que el candidato).

        Política local (no consenso): la usan la admisión al mempool y el
        armado de bloques para reglas que dependen de la hora del bloque,
        como el semestre de los presupuestos de tokens (P1-12).
        """
        return max(time.time(), self.last_block.header.timestamp + 0.001)

    def get_pending_transactions(self, limit: int = 100) -> List[Transaction]:
        return self.mempool[:limit]

    # ── Minado / adición de bloques ───────────────────────────────────────────

    # ── Certificados PBFT (P1-1) ─────────────────────────────────────────────

    def check_certificate(self, block: Block, certificate) -> Tuple[bool, str]:
        """¿``certificate`` prueba que ``block`` se confirmó por PBFT? (siempre True en pow)."""
        if self.consensus != "pbft":
            return True, "OK"
        return self.replica_set.check_commit_certificate(
            certificate, block.hash, block.header.index)

    def _check_certificates(self, chain: List[Block], certificates: Dict[int, dict],
                            ) -> Tuple[bool, str]:
        """Cada bloque > 0 de ``chain`` tiene un certificado válido (modo pbft)."""
        for block in chain[1:]:
            ok, reason = self.check_certificate(block, certificates.get(block.header.index))
            if not ok:
                return False, f"Bloque {block.header.index}: {reason}"
        return True, "OK"

    def add_certified_conflict_listener(self, callback: Callable[[int, str, str], None]) -> None:
        """``callback(altura, hash_propio, hash_ajeno)`` ante dos bloques certificados
        distintos en la misma altura (no debería ocurrir con ≤ f réplicas bizantinas)."""
        self.on_certified_conflict.append(callback)

    def _notify_conflict(self, height: int, ours: str, theirs: str) -> None:
        logger.critical(f"Dos bloques CERTIFICADOS distintos en la altura {height}: "
                        f"{ours[:12]}… y {theirs[:12]}…")
        for callback in list(self.on_certified_conflict):
            try:
                callback(height, ours, theirs)
            except Exception:
                logger.exception("Error en un listener de on_certified_conflict")

    def check_block(self, block: Block) -> Tuple[bool, str]:
        """Validez de consenso de ``block`` como siguiente bloque, sin certificado
        (lo que una réplica PBFT revisa antes de enviar PREPARE)."""
        return self._validate_block(block)

    def add_block(self, block: Block, certificate: Optional[dict] = None) -> Tuple[bool, str]:
        """Agrega ``block`` en la punta. En modo pbft exige su certificado de commit."""
        if self.consensus == "pbft":
            ok, reason = self.check_certificate(block, certificate)
            if not ok:
                return False, reason
        with self._lock:
            valid, reason, states = self._validate_block_at(
                block, self.chain, set(self._confirmed_ids), time.time(),
                self.contracts.check_block)
            if not valid:
                return False, reason
            # Primero el disco (P2-4): una transacción SQLite con el bloque, sus
            # TXs y, cada `snapshot_interval` bloques, la foto del estado. Si
            # falla, la memoria no se toca y el bloque simplemente no entró.
            height = block.header.index
            snapshot = (self._make_snapshot(block, states)
                        if self._snapshot_due(height - 1, height) else None)
            cert = certificate if self.consensus == "pbft" else None
            try:
                self.store.append_block(block, snapshot, cert)
            except sqlite3.Error as e:
                logger.exception("No se pudo guardar el bloque en chain.db")
                return False, f"Error de almacenamiento: {e}"
            self.chain.append(block)
            if cert is not None:
                self.certificates[height] = cert
            self._confirmed_ids.update(tx.get("tx_id") for tx in block.transactions)
            self.contracts.commit(states, block.header.index)
            self._remember_states([(height, block.hash, states)])
            # Remueve del mempool las TXs confirmadas y las que ya no pueden
            # confirmarse: p. ej. otra TX del mismo sender ocupó su nonce (P0-9)
            # o la misma credencial ya se emitió en este bloque (P1-13).
            confirmed_ids = {tx.get("tx_id") for tx in block.transactions}
            self.mempool = self._still_valid(
                [t for t in self.mempool if t.tx_id not in confirmed_ids])
        logger.info(f"Bloque #{block.header.index} añadido (hash={block.hash[:12]}…)")
        return True, "OK"

    def _still_valid(self, txs: List[Transaction],
                     timestamp: Optional[float] = None) -> List[Transaction]:
        """Las TXs de ``txs`` (en orden) que todos los contratos aceptarían una tras otra.

        ``timestamp``: hora del bloque que se arma (por defecto, la estimada).
        """
        dicts = [t.to_dict() for t in txs]
        if timestamp is None:
            timestamp = self._next_block_timestamp()
        keep = {d["tx_id"] for d in self.contracts.filter_valid(dicts, timestamp)}
        return [t for t in txs if t.tx_id in keep]

    def next_nonce(self, address: str) -> int:
        """Nonce que debe firmar la próxima TX de ``address`` (confirmadas + mempool, P0-9)."""
        with self._lock:
            return AccountContract.next_nonce(self.accounts, address,
                                              [t.to_dict() for t in self.mempool])

    def account_info(self, address: str) -> dict:
        """Saldo, nonce confirmado y próximo nonce de ``address`` (P0-9)."""
        with self._lock:
            return self.contracts.contract("accounts").account_info(
                self.accounts, address, self.height, [t.to_dict() for t in self.mempool])

    def create_candidate_block(self, transactions: Optional[List[Transaction]] = None) -> Block:
        # Del mempool solo se toman TXs válidas para los contratos (P0-9, P1-13):
        # si no, una TX caducada (nonce ya usado) haría inválido el bloque entero.
        # La hora del bloque se fija antes de elegir TXs: reglas como el
        # presupuesto semestral de tokens (P1-12) dependen de ella.
        timestamp = self._next_block_timestamp()
        if not transactions:
            with self._lock:   # la red puede estar aplicando un bloque en otro hilo
                transactions = self._fit_block(
                    self._still_valid(list(self.mempool), timestamp)[:50])
        txs = transactions
        tx_dicts = [t.to_dict() for t in txs]
        merkle_root = Block.compute_merkle_root(tx_dicts)
        header = BlockHeader(
            index=self.height + 1,
            timestamp=timestamp,
            previous_hash=self.last_block.hash,
            merkle_root=merkle_root,
            difficulty=self._calculate_difficulty(),
            node_id=self.node_id,
        )
        return Block(header=header, transactions=tx_dicts)

    # Bytes reservados para encabezado, hash y llaves del JSON del bloque (sobra: ~400 B reales).
    _BLOCK_OVERHEAD = 4096

    @classmethod
    def _fit_block(cls, txs: List[Transaction]) -> List[Transaction]:
        """El prefijo más largo de ``txs`` que cabe en un bloque (P0-3).

        Un prefijo de una secuencia válida sigue siendo válido (cada TX solo
        depende de las anteriores), así que cortar no invalida el bloque.
        """
        budget = MAX_BLOCK_BYTES - cls._BLOCK_OVERHEAD
        used = 0
        for i, tx in enumerate(txs[:MAX_BLOCK_TXS]):
            used += serialized_size(tx.to_dict()) + 1     # +1: la coma entre TXs
            if used > budget:
                return txs[:i]
        return txs[:MAX_BLOCK_TXS]

    # ── Validación ────────────────────────────────────────────────────────────

    def _validate_block(self, block: Block, now: Optional[float] = None) -> Tuple[bool, str]:
        """Valida `block` como siguiente bloque de la cadena actual (sin agregarlo)."""
        ok, reason, _ = self._validate_block_at(
            block, self.chain, set(self._confirmed_ids),
            now if now is not None else time.time(), self.contracts.check_block,
        )
        return ok, reason

    def _validate_block_at(
        self, block: Block, prefix: List[Block], seen_ids: set, now: float,
        run_contracts: Callable,
    ) -> Tuple[bool, str, Optional[dict]]:
        """Validez de CONSENSO de `block` dado `prefix` = chain[:h] (h = block.index).

        Determinista: depende sólo de (block, prefix, seen_ids, estado, now).
        `seen_ids` se actualiza con los tx_id del bloque si es válido.
        `run_contracts(block) -> (ok, motivo, estados)` aplica el bloque a los
        contratos (P1-13) sobre el estado tras `prefix`, sin modificarlo; los
        estados resultantes se devuelven para que el llamador los adopte.
        `now` sólo acota el timestamp futuro. La expiración de 1 h del mempool
        NO aplica aquí.
        """
        h = block.header
        prev = prefix[-1]
        # Tipos estrictos: bool/float darían dos hashes válidos al mismo bloque.
        for campo in ("index", "nonce", "difficulty"):
            v = getattr(h, campo)
            if type(v) is not int or v < 0:
                return False, f"Encabezado: {campo} debe ser un entero >= 0", None
        ts = h.timestamp
        if type(ts) not in (int, float) or not math.isfinite(ts):
            return False, "Encabezado: timestamp debe ser un número finito", None
        if h.index != len(prefix):
            return False, f"Índice incorrecto: esperado {len(prefix)}, recibido {h.index}", None
        if h.previous_hash != prev.hash:
            return False, "Hash previo no coincide", None
        if block.compute_hash() != block.hash:
            return False, "Hash del bloque inválido", None
        if self.consensus == "pbft" and h.nonce != 0:
            return False, "En modo PBFT el nonce debe ser 0 (no hay minado)", None
        expected = self.expected_difficulty(prefix)
        if h.difficulty != expected:
            return False, (f"Dificultad incorrecta: esperada {expected}, "
                           f"recibida {h.difficulty}"), None
        if not hash_meets_bits(block.hash, h.difficulty):
            return False, "Proof of Work insuficiente: el hash no cumple la dificultad", None
        # Tamaño (P0-3, consenso): antes de recorrer y verificar las TXs.
        ok, reason = check_block_size(block.to_dict())
        if not ok:
            return False, reason, None
        if Block.compute_merkle_root(block.transactions) != h.merkle_root:
            return False, "Merkle root inválido", None
        # Timestamp: estrictamente mayor que la mediana de los últimos bloques
        # y no más de MAX_FUTURE_SECONDS en el futuro respecto a `now`.
        recent = sorted(b.header.timestamp for b in prefix[-self.MEDIAN_WINDOW:])
        median = recent[len(recent) // 2]
        if h.timestamp <= median:
            return False, "Timestamp no es posterior a la mediana de los bloques previos", None
        if h.timestamp > now + self.MAX_FUTURE_SECONDS:
            return False, "Timestamp demasiado en el futuro", None
        # Transacciones: autenticación (sin expiración) y sin duplicados.
        new_ids = set()
        for raw in block.transactions:
            try:
                tx = Transaction.from_dict(raw)
            except (KeyError, ValueError, TypeError, AttributeError):
                return False, "Transacción malformada en el bloque", None
            ok, reason = tx.is_consensus_valid()
            if not ok:
                return False, f"Transacción {str(raw.get('tx_id'))[:8]}… inválida: {reason}", None
            if tx.tx_id in seen_ids or tx.tx_id in new_ids:
                return False, f"Transacción duplicada {tx.tx_id[:8]}…", None
            new_ids.add(tx.tx_id)
        # Contratos (P1-13): cuentas, credenciales, votación… en el orden del
        # bloque. Una TX inválida para cualquiera invalida el bloque entero.
        ok, reason, states = run_contracts(block)
        if not ok:
            return False, reason, None
        seen_ids.update(new_ids)
        return True, "OK", states

    def _replay_blocks(self, chain: List[Block],
                       now: Optional[float] = None) -> Tuple[bool, str, Optional[dict]]:
        """Valida una cadena completa y devuelve el estado de los contratos al final.

        Génesis fijo + cada bloque 1..n (P0-3), reproduciendo los contratos
        desde su estado inicial (P1-13). No toca el estado de esta cadena.
        """
        ok, reason = self._check_genesis(chain)
        if not ok:
            return False, reason, None
        now = now if now is not None else time.time()
        seen = self._collect_ids(chain[:1])
        states = self.contracts.initial_states()
        for i in range(1, len(chain)):
            ok, reason, states = self._validate_block_at(
                chain[i], chain[:i], seen, now,
                lambda block, st=states: self.contracts.run_block(st, block))
            if not ok:
                return False, f"Bloque {i}: {reason}", None
        return True, "Cadena válida", states

    def _validate_blocks(self, chain: List[Block], now: Optional[float] = None) -> Tuple[bool, str]:
        """Valida una cadena completa: génesis fijo + cada bloque 1..n (P0-3)."""
        ok, reason, _ = self._replay_blocks(chain, now)
        return ok, reason

    def validate_chain(self, now: Optional[float] = None) -> Tuple[bool, str]:
        return self._validate_blocks(self.chain, now)

    # ── Consultas de estado ───────────────────────────────────────────────────

    # Búsquedas por índice (P2-4): chain.db dice DÓNDE está (altura, posición)
    # y el bloque se toma de la lista en memoria. Se comprueba que el bloque de
    # esa altura sigue conteniendo la TX: si un reorg ocurre entre la consulta
    # y la lectura, se responde "no encontrada" en vez de un dato mezclado.

    def _tx_at(self, height: int, position: int, tx_id: Optional[str] = None,
               ) -> Optional[Tuple[Block, dict]]:
        chain = self.chain
        if height >= len(chain) or position >= len(chain[height].transactions):
            return None
        tx = chain[height].transactions[position]
        if tx_id is not None and tx.get("tx_id") != tx_id:
            return None
        return chain[height], tx

    def locate_transaction(self, tx_id: str) -> Optional[Tuple[Block, int]]:
        """``(bloque, posición)`` de la TX confirmada ``tx_id`` (para la prueba Merkle)."""
        loc = self.store.find_tx(tx_id)
        found = self._tx_at(*loc, tx_id=tx_id) if loc is not None else None
        if found is None:
            return None
        return found[0], loc[1]

    def get_transaction(self, tx_id: str) -> Optional[dict]:
        found = self.locate_transaction(tx_id)
        if found is None:
            return None
        block, position = found
        return {**block.transactions[position], "block": block.header.index, "confirmed": True}

    def transactions_of(self, address: str, role: str = "any",
                        tx_type: Optional[str] = None) -> List[dict]:
        """TXs confirmadas donde ``address`` es sender y/o recipient, en orden de cadena.

        ``role``: "sender", "recipient" o "any". Cada TX lleva ``block``.
        """
        out = []
        for height, position in self.store.txs_of_address(address, role, tx_type):
            found = self._tx_at(height, position)
            if found is not None:
                out.append({**found[1], "block": height})
        return out

    def get_credentials_for(self, address: str) -> List[dict]:
        return [{**tx["payload"], "block": tx["block"]}
                for tx in self.transactions_of(address, "recipient",
                                               TransactionType.CREDENTIAL_ISSUE.value)]

    def get_stats(self) -> dict:
        total_tx = self.store.count_txs()
        return {
            "height": self.height,
            "total_blocks": len(self.chain),
            "total_transactions": total_tx,
            "pending_transactions": len(self.mempool),
            "last_block_hash": self.last_block.hash,
            "last_block_time": self.last_block.header.timestamp,
        }

    # ── Nuevos métodos de consulta ────────────────────────────────────────────

    @property
    def total_fees(self) -> int:
        """Fees quemadas en bloques confirmados (enteros, unidad mínima; P0-9)."""
        return self.accounts.burned_fees

    def get_balance(self, address: str) -> int:
        """Saldo confirmado de ``address`` según el estado de cuentas (P0-9)."""
        return self.accounts.balance_of(address)

    def get_block_by_hash(self, block_hash: str) -> Optional[Block]:
        """Busca un bloque por su hash. Retorna None si no se encuentra.

        Complejidad: O(log H) por el índice UNIQUE de ``blocks.hash`` (P2-4).
        """
        height = self.store.height_of_hash(block_hash)
        chain = self.chain
        if height is None or height >= len(chain) or chain[height].hash != block_hash:
            return None
        return chain[height]

    def prune_mempool(self, max_age_seconds: int = 3600) -> int:
        """Elimina TXs del mempool cuya antigüedad supera max_age_seconds.

        Retorna: número de transacciones eliminadas.
        Thread-safe: adquiere _lock durante la escritura.
        """
        now = time.time()
        before = len(self.mempool)
        with self._lock:
            self.mempool = [
                tx for tx in self.mempool
                if (now - tx.timestamp) <= max_age_seconds
            ]
        pruned = before - len(self.mempool)
        if pruned:
            logger.info(f"Mempool podado: {pruned} TX(s) eliminadas (max_age={max_age_seconds}s)")
        return pruned

    # ── Ajuste de dificultad ──────────────────────────────────────────────────

    def expected_difficulty(self, prefix: List[Block]) -> int:
        """Dificultad (en bits) exigida al bloque de altura h = len(prefix), dada chain[:h].

        Función pura de los bloques anteriores y de los parámetros de la cadena
        (P2-5, estilo Bitcoin: reajuste por épocas de `difficulty_window` bloques).
        - Génesis: 0 bits (fija).
        - Primera época (h <= window): `initial_difficulty`.
        - Al empezar cada época nueva (h = window+1, 2·window+1, …) se mide la
          anterior: los últimos `window` bloques (el génesis nunca entra, su
          timestamp es artificial) abarcan window-1 intervalos. Se compara el
          tiempo real con el esperado (target · intervalos) y se suman
          round(log2(esperado/real)) bits, acotado a ±`max_bits_step` por época
          y a [min_difficulty, max_difficulty] (`retarget_step`).
        - Dentro de una época: la misma dificultad del bloque anterior.
        Reajustar sólo por épocas evita la sobrecorrección de una ventana
        deslizante: la época medida se minó entera con la misma dificultad.
        """
        h = len(prefix)
        if h == 0 or self.consensus == "pbft":
            return 0          # génesis, o PBFT: no hay prueba de trabajo (P1-1)
        w = self.difficulty_window
        if h <= w:
            return self.initial_difficulty
        current = prefix[-1].header.difficulty
        if (h - 1) % w != 0:
            return current
        recent = prefix[-w:]
        actual_ms = _ms(recent[-1].header.timestamp) - _ms(recent[0].header.timestamp)
        expected_ms = self.target_block_ms * (w - 1)
        nxt = current + retarget_step(expected_ms, actual_ms, self.max_bits_step)
        return max(self.min_difficulty, min(self.max_difficulty, nxt))

    def _calculate_difficulty(self) -> int:
        """Dificultad esperada del PRÓXIMO bloque (la que debe usar el minado)."""
        return self.expected_difficulty(self.chain)

    # ── Reemplazo de cadena (fork resolution, P0-5) ──────────────────────────

    @staticmethod
    def block_work(block: Block) -> int:
        """Trabajo esperado para minar `block`: 2**bits intentos (entero, P2-5)."""
        return work_for_bits(block.header.difficulty)

    @classmethod
    def cumulative_work(cls, chain: List[Block]) -> int:
        """Trabajo acumulado de una cadena = Σ 2**bits (determinista, sin floats).

        Por eso una cadena más corta pero minada con más bits puede "pesar" más
        que una más larga y fácil: gana la que costó más trabajo producir.
        """
        return sum(cls.block_work(b) for b in chain)

    @property
    def total_work(self) -> int:
        return self.cumulative_work(self.chain)

    def add_reorg_listener(self, callback: Callable[[int, List[Block], List[Block]], None]) -> None:
        """Suscribe `callback(fork_height, dropped, added)` a los reemplazos de cadena.

        Se invoca DESPUÉS de cada `replace_chain` exitoso, fuera del lock, con:
          - fork_height: altura del último bloque común (0 = sólo el génesis).
          - dropped: bloques nuestros que salieron de la cadena (puede estar vacío
            si la cadena nueva sólo extendía la nuestra).
          - added: bloques nuevos que entraron (de fork_height+1 a la punta).
        Al invocarse, `self.chain` ya es la cadena nueva y los estados derivados
        (contratos, P1-13) ya se reconstruyeron: este aviso es
        para la red, métricas o logs, no para mantener estado de contratos.
        Las excepciones del callback se registran en el log y no deshacen el reemplazo.
        """
        self.on_chain_reorg.append(callback)

    def replace_chain(self, new_chain: List[dict],
                      certificates: Optional[dict] = None, *,
                      full_validation: bool = False) -> Tuple[bool, str]:
        """Adopta `new_chain` si es válida y tiene MÁS trabajo acumulado (P0-5).

        Modo pbft (P1-1): ``certificates`` = {altura: certificado} de la cadena
        recibida; cada bloque > 0 debe tener uno válido. Como cada bloque pesa
        2**0 = 1, "más trabajo" = mayor altura. Si la cadena recibida difiere de
        la nuestra en una altura que ambas tienen, hay dos bloques certificados
        distintos: se rechaza y se avisa a ``on_certified_conflict``.

        Reglas:
          1. Mismo génesis y validez de consenso completa. Por defecto se valida
             solo DESDE LA BIFURCACIÓN (``_validate_from_fork``): el prefijo común
             ya lo validó este nodo. ``full_validation=True`` usa el camino
             antiguo (``_replay_blocks`` desde el génesis); ambos dan el mismo
             resultado (prueba diferencial en ``tests/test_reorg_incremental.py``).
          2. Trabajo acumulado estrictamente mayor que el nuestro (no basta con
             ser más larga). Empate: nos quedamos con la nuestra (determinista).
          3. TXs de nuestros bloques descartados que no están en la cadena nueva
             vuelven al mempool si siguen siendo admisibles (``add_transaction``);
             las TXs del mempool ya confirmadas en la cadena nueva se retiran.
          4. Se adopta el estado de los contratos de la cadena nueva (P1-13),
             se persiste y luego se notifica a ``on_chain_reorg``.
        """
        try:
            candidate = [Block.from_dict(b) for b in new_chain]
            certs = {int(k): v for k, v in (certificates or {}).items()}
        except (KeyError, TypeError, ValueError, AttributeError) as e:
            return False, f"Cadena recibida malformada: {e}"
        # Validación costosa fuera del lock: una cadena válida lo sigue siendo.
        if full_validation:
            valid, reason, states, recent = self._validate_full(candidate, certs)
        else:
            valid, reason, states, recent = self._validate_from_fork(candidate, certs)
        if not valid:
            return False, reason
        new_work = self.cumulative_work(candidate)
        if self.consensus == "pbft":
            chain = self.chain
            for i in range(1, min(len(chain), len(candidate))):
                if chain[i].hash != candidate[i].hash:
                    self._notify_conflict(i, chain[i].hash, candidate[i].hash)
                    return False, (f"Conflicto PBFT: otro bloque certificado en la altura {i}; "
                                   f"los bloques certificados nunca se reemplazan")

        with self._lock:
            our_work = self.cumulative_work(self.chain)
            if new_work <= our_work:
                return False, (
                    f"Cadena recibida sin más trabajo acumulado ({new_work} <= {our_work})"
                )
            if states is None:
                # La candidata era un prefijo de nuestra cadena (sin bloques
                # nuevos): no puede tener más trabajo. Defensa por si acaso.
                return False, "Cadena recibida sin bloques nuevos"
            # Último bloque común (el génesis siempre coincide). Se recalcula
            # aquí: la cadena local pudo cambiar mientras se validaba.
            fork = 0
            limit = min(len(self.chain), len(candidate))
            while fork + 1 < limit and self.chain[fork + 1].hash == candidate[fork + 1].hash:
                fork += 1
            dropped = self.chain[fork + 1:]
            added = candidate[fork + 1:]
            # IDs confirmados de la cadena nueva, de forma incremental:
            # los nuestros, menos los de los bloques que salen, más los que entran.
            new_ids = ((self._confirmed_ids - self._collect_ids(dropped))
                       | self._collect_ids(added))

            # Candidatas al mempool: TXs huérfanas (en orden de cadena) y luego
            # las pendientes, salvo las ya confirmadas en la cadena nueva.
            readmit: List[Transaction] = []
            for block in dropped:
                for raw in block.transactions:
                    if raw.get("tx_id") in new_ids:
                        continue
                    try:
                        readmit.append(Transaction.from_dict(raw))
                    except (KeyError, ValueError, TypeError, AttributeError):
                        continue
            readmit.extend(t for t in self.mempool if t.tx_id not in new_ids)

            # Disco primero (P2-4): borrar alturas > fork e insertar las nuevas
            # en UNA transacción; si falla, la cadena en memoria y en disco
            # siguen siendo la vieja. Si el reorg cruza un múltiplo del
            # intervalo, se guarda una foto en la nueva punta.
            tip = len(candidate) - 1
            snapshot = (self._make_snapshot(candidate[-1], states)
                        if self._snapshot_due(fork, tip) else None)
            added_certs = ({b.header.index: certs[b.header.index] for b in added}
                           if self.consensus == "pbft" else None)
            try:
                self.store.replace_from(fork, added, snapshot, added_certs)
                if len(added) > 50:
                    self.store.checkpoint()      # reorganización grande: acota el WAL
            except sqlite3.Error as e:
                logger.exception("No se pudo guardar la reorganización en chain.db")
                return False, f"Error de almacenamiento: {e}"
            self.chain = candidate
            if added_certs is not None:
                self.certificates = {h: c for h, c in self.certificates.items() if h <= fork}
                self.certificates.update(added_certs)
            self._confirmed_ids = new_ids
            self.mempool = []
            self.contracts.commit(states, tip)
            self._remember_states(recent)
        # Re-admisión por la puerta normal (fuera del lock): expiración, duplicados
        # y check_transaction de los contratos ya reconstruidos (P1-13).
        for tx in readmit:
            self.add_transaction(tx)
        logger.info(
            f"Cadena reemplazada: altura {self.height}, bifurcación en {fork}, "
            f"{len(dropped)} bloque(s) descartado(s), {len(added)} nuevo(s)"
        )
        for callback in list(self.on_chain_reorg):
            try:
                callback(fork, dropped, added)
            except Exception:
                logger.exception("Error en un listener de on_chain_reorg")
        return True, "OK"

    # ── Validación de la cadena candidata (completa o desde la bifurcación) ──

    def _validate_full(self, candidate: List[Block], certs: Dict[int, dict],
                       ) -> Tuple[bool, str, Optional[dict], list]:
        """Camino antiguo: certificados y validación completa desde el génesis.

        Se conserva como referencia (prueba diferencial) y para
        ``replace_chain(..., full_validation=True)``. Devuelve
        ``(ok, motivo, estados_en_la_punta, [])``.
        """
        if self.consensus == "pbft":
            ok, reason = self._check_certificates(candidate, certs)
            if not ok:
                return False, f"Cadena recibida sin certificados válidos: {reason}", None, []
        ok, reason, states = self._replay_blocks(candidate)
        if not ok:
            return False, f"Cadena recibida inválida: {reason}", None, []
        self.last_replace_validated = len(candidate) - 1
        return True, "OK", states, []

    def _validate_from_fork(self, candidate: List[Block], certs: Dict[int, dict],
                            ) -> Tuple[bool, str, Optional[dict], list]:
        """Valida ``candidate`` reutilizando el prefijo que comparte con nuestra cadena.

        Mismo veredicto (y mismo motivo) que ``_validate_full``:
          - Prefijo común = bloques 1..f con el MISMO hash que los nuestros y cuyo
            contenido realmente da ese hash (``compute_hash``). Como el hash
            serializa encabezado y TXs (JSON, distingue 1 de 1.0 y de true), un
            bloque así es idéntico al nuestro, que ya pasó la validación de
            consenso: validarlo otra vez daría lo mismo. El primer bloque que
            no cumple se valida entero (y falla con el mismo motivo que antes).
          - Estado en la bifurcación: ``_states_at`` (anillo en memoria, foto de
            chain.db + reproducción de NUESTROS bloques sin firmas, o el génesis).
          - Certificados PBFT: los del prefijo que son idénticos a los nuestros
            ya se verificaron; el resto (y todos los del sufijo) se verifican.
        Devuelve ``(ok, motivo, estados_en_la_punta, recientes)``; ``recientes``
        = ``[(altura, hash, estados)]`` de los últimos bloques del sufijo, para el
        anillo. ``estados`` es None si no hay sufijo (la candidata es un prefijo
        nuestro y no puede tener más trabajo).
        """
        with self._lock:     # foto coherente de cadena, estado, IDs y certificados
            local = list(self.chain)
            tip_states = self.contracts._states
            recent = dict(self._recent_states)
            local_ids = set(self._confirmed_ids)
            local_certs = dict(self.certificates)
        fork = -1
        if self._check_genesis(candidate)[0]:
            fork = 0
            limit = min(len(local), len(candidate))
            while (fork + 1 < limit and candidate[fork + 1].hash == local[fork + 1].hash
                   and candidate[fork + 1].compute_hash() == candidate[fork + 1].hash):
                fork += 1
        if self.consensus == "pbft":
            for block in candidate[1:]:
                h = block.header.index
                if h <= fork and h in local_certs and certs.get(h) == local_certs[h]:
                    continue          # certificado ya verificado al adoptar ese bloque
                ok, reason = self.check_certificate(block, certs.get(h))
                if not ok:
                    return (False, f"Cadena recibida sin certificados válidos: "
                                   f"Bloque {h}: {reason}", None, [])
        if fork < 0:
            ok, reason = self._check_genesis(candidate)
            return False, f"Cadena recibida inválida: {reason}", None, []
        if fork == len(candidate) - 1:
            self.last_replace_validated = 0
            return True, "OK", None, []
        states = self._states_at(local, fork, tip_states, recent)
        if states is None:      # no debería ocurrir: se usa el camino completo
            logger.warning("No se pudo reconstruir el estado en la bifurcación; "
                           "validación completa")
            return self._validate_full(candidate, certs)
        # TXs ya confirmadas en el prefijo común = las nuestras menos las que salen.
        seen = local_ids - self._collect_ids(local[fork + 1:])
        now = time.time()
        out = []
        keep = self.recent_states_kept
        for i in range(fork + 1, len(candidate)):
            ok, reason, states = self._validate_block_at(
                candidate[i], candidate[:i], seen, now,
                lambda block, st=states: self.contracts.run_block(st, block))
            if not ok:
                return False, f"Cadena recibida inválida: Bloque {i}: {reason}", None, []
            if keep and i > len(candidate) - 1 - keep:
                out.append((i, candidate[i].hash, states))
        self.last_replace_validated = len(candidate) - 1 - fork
        return True, "OK", states, out

    def _states_at(self, local: List[Block], fork: int, tip_states: dict,
                   recent: Dict[int, Tuple[str, dict]]) -> Optional[dict]:
        """Estados de los contratos tras ``local[fork]`` (bloques ya validados).

        En orden de costo: punta actual, génesis (estado inicial), anillo de
        estados recientes, y si no, la foto de chain.db más alta en o debajo de
        ``fork`` (o el génesis) + reproducción SOLO de contratos de nuestros
        bloques hasta ``fork`` (sin firmas: ya se verificaron al adoptarlos).
        None si la reproducción falla (no debería: la cadena local es válida).
        """
        if fork == len(local) - 1:
            return tip_states
        if fork == 0:
            return self.contracts.initial_states()
        entry = recent.get(fork)
        if entry is not None and entry[0] == local[fork].hash:
            return entry[1]
        base, states = self._latest_snapshot(local, fork)
        # Un estado del anillo más cercano a la bifurcación que la foto ahorra reproducción.
        for h in sorted(recent, reverse=True):
            if base < h < fork and recent[h][0] == local[h].hash:
                base, states = h, recent[h][1]
                break
        for i in range(base + 1, fork + 1):
            ok, reason, states = self.contracts.run_block(states, local[i])
            if not ok:
                logger.error(f"Bloque local {i} no reproduce: {reason}")
                return None
        return states

    def _remember_states(self, entries) -> None:
        """Guarda ``[(altura, hash, estados)]`` en el anillo y poda lo viejo o huérfano.

        Llamar con ``_lock`` y DESPUÉS de actualizar ``self.chain``.
        """
        keep = self.recent_states_kept
        if not keep:
            self._recent_states = {}
            return
        ring = self._recent_states
        for height, block_hash, states in entries:
            ring[height] = (block_hash, states)
        chain, floor = self.chain, len(self.chain) - keep
        self._recent_states = {h: v for h, v in ring.items()
                               if floor <= h < len(chain) and chain[h].hash == v[0]}
