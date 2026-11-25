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
    génesis se acepta la de mayor Σ 16**dificultad (no la más larga); en
    empate se conserva la propia. Es la regla de Nakamoto.
    Ref: Nakamoto (2008), Sección 5.

Complejidades:
    add_transaction()  → O(m) donde m = tamaño del mempool (búsqueda de duplicados)
    add_block()        → O(n) donde n = número de TXs en el bloque
    validate_chain()   → O(H * n) donde H = altura, n = TXs por bloque
    get_credentials()  → O(H * n) — búsqueda lineal sobre la cadena completa
    replace_chain()    → O(H' * n) donde H' = altura de la cadena candidata

Thread safety:
    _lock (threading.Lock) protege chain y mempool de escrituras concurrentes.
    Las lecturas no adquieren el lock (trade-off aceptable para un nodo académico).
"""
import json
import logging
import os
import shutil
import time
from pathlib import Path
from threading import Lock
from typing import Callable, Dict, List, Optional, Tuple

from blockchain.contracts import default_contracts
from blockchain.contracts.accounts import AccountContract, Accounts
from blockchain.contracts.base import Contract
from blockchain.contracts.registry import ContractRegistry
from blockchain.core.block import GENESIS_HASH, Block, BlockHeader
from blockchain.core.transaction import Transaction, TransactionType

logger = logging.getLogger("upb_chain.core")


class Blockchain:
    # Ventana de timestamps para la mediana (estilo Bitcoin) y tolerancia al futuro.
    MEDIAN_WINDOW = 11
    MAX_FUTURE_SECONDS = 2 * 3600

    def __init__(
        self,
        node_id: str,
        data_dir: str = "data/chain",
        initial_difficulty: int = 4,
        min_difficulty: int = 1,
        max_difficulty: int = 8,
        target_block_time: float = 10.0,
        difficulty_window: int = 10,
        authority_address: Optional[str] = None,
        contracts: Optional[List[Contract]] = None,
    ):
        self.node_id = node_id
        # Parámetros de la regla de dificultad (parte del consenso: deben ser
        # iguales en todos los nodos de la red).
        self.initial_difficulty = initial_difficulty
        self.min_difficulty = min_difficulty
        self.max_difficulty = max_difficulty
        self.target_block_time = target_block_time
        self.difficulty_window = difficulty_window
        self._confirmed_ids: set = set()
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.chain: List[Block] = []
        self.mempool: List[Transaction] = []
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

        self._load_or_init()

    # ── Inicialización ────────────────────────────────────────────────────────

    def _load_or_init(self) -> None:
        chain_file = self.data_dir / "chain.json"
        bak_file = self.data_dir / "chain.json.bak"
        if not chain_file.exists() and not bak_file.exists():
            genesis = Block.create_genesis(self.node_id)
            self.chain.append(genesis)
            self.contracts.rebuild(self.chain)
            self._save_to_disk()
            logger.info("Génesis creado")
            return
        try:
            data = self._read_json(chain_file)
        except (OSError, ValueError) as e:
            # Archivo ausente o JSON truncado (corte de energía): usar el respaldo.
            if not bak_file.exists():
                raise ValueError(f"{chain_file}: no se pudo leer: {e}") from e
            logger.warning(
                f"chain.json no legible ({e}); cargando respaldo chain.json.bak"
            )
            data = self._read_json(bak_file)
            self._install_chain(data, bak_file)
            # Reescribir chain.json sano; el corrupto no debe pisar el respaldo.
            if chain_file.exists():
                chain_file.unlink()
            self._save_to_disk()
            logger.info(f"Cadena restaurada desde respaldo: {len(self.chain)} bloques")
            return
        self._install_chain(data, chain_file)
        logger.info(f"Cadena cargada: {len(self.chain)} bloques")

    @staticmethod
    def _read_json(path: Path) -> list:
        """Lee y decodifica el JSON de la cadena. Lanza OSError o ValueError."""
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def _install_chain(self, data: list, path: Path) -> None:
        """Valida `data` (lista de bloques serializados) y la adopta como cadena."""
        chain = [Block.from_dict(b) for b in data]
        ok, reason = self._check_genesis(chain)
        if not ok:
            raise ValueError(f"{path}: {reason}")
        # Revalidar TODA la cadena al cargar (P0-3): un archivo manipulado se
        # rechaza. La misma pasada deja el estado de los contratos (P1-13).
        ok, reason, states = self._replay_blocks(chain)
        if not ok:
            raise ValueError(f"{path}: cadena inválida en disco: {reason}")
        self.chain = chain
        self._confirmed_ids = self._collect_ids(chain)
        self.contracts.commit(states, len(chain) - 1)

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

    def _save_to_disk(self) -> None:
        """Escritura atómica (P1-8): temporal + fsync + respaldo + reemplazo.

        Si el proceso se corta antes de `os.replace`, chain.json queda intacto.
        Antes del reemplazo, la versión anterior se copia a chain.json.bak.
        """
        chain_file = self.data_dir / "chain.json"
        tmp_file = self.data_dir / "chain.json.tmp"
        bak_file = self.data_dir / "chain.json.bak"
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump([b.to_dict() for b in self.chain], f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            if chain_file.exists():
                shutil.copy2(chain_file, bak_file)
            os.replace(tmp_file, chain_file)
        except BaseException:
            # No dejar un temporal a medio escribir; chain.json sigue como estaba.
            if tmp_file.exists():
                tmp_file.unlink()
            raise

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
            # Mismas reglas que en un bloque, contra confirmado + pendientes (P1-13).
            valid, reason = self.contracts.check_transaction(
                tx.to_dict(), [t.to_dict() for t in self.mempool])
            if not valid:
                return False, reason
            self.mempool.append(tx)
        logger.debug(f"TX {tx.tx_id[:8]}… añadida al mempool")
        return True, "OK"

    def get_pending_transactions(self, limit: int = 100) -> List[Transaction]:
        return self.mempool[:limit]

    # ── Minado / adición de bloques ───────────────────────────────────────────

    def add_block(self, block: Block) -> Tuple[bool, str]:
        with self._lock:
            valid, reason, states = self._validate_block_at(
                block, self.chain, set(self._confirmed_ids), time.time(),
                self.contracts.check_block)
            if not valid:
                return False, reason
            self.chain.append(block)
            self._confirmed_ids.update(tx.get("tx_id") for tx in block.transactions)
            self.contracts.commit(states, block.header.index)
            # Remueve del mempool las TXs confirmadas y las que ya no pueden
            # confirmarse: p. ej. otra TX del mismo sender ocupó su nonce (P0-9)
            # o la misma credencial ya se emitió en este bloque (P1-13).
            confirmed_ids = {tx.get("tx_id") for tx in block.transactions}
            self.mempool = self._still_valid(
                [t for t in self.mempool if t.tx_id not in confirmed_ids])
            self._save_to_disk()
        logger.info(f"Bloque #{block.header.index} añadido (hash={block.hash[:12]}…)")
        return True, "OK"

    def _still_valid(self, txs: List[Transaction]) -> List[Transaction]:
        """Las TXs de ``txs`` (en orden) que todos los contratos aceptarían una tras otra."""
        dicts = [t.to_dict() for t in txs]
        keep = {d["tx_id"] for d in self.contracts.filter_valid(dicts)}
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
        if not transactions:
            with self._lock:   # la red puede estar aplicando un bloque en otro hilo
                transactions = self._still_valid(list(self.mempool))[:50]
        txs = transactions
        tx_dicts = [t.to_dict() for t in txs]
        merkle_root = Block.compute_merkle_root(tx_dicts)
        header = BlockHeader(
            index=self.height + 1,
            timestamp=max(time.time(), self.last_block.header.timestamp + 0.001),
            previous_hash=self.last_block.hash,
            merkle_root=merkle_root,
            difficulty=self._calculate_difficulty(),
            node_id=self.node_id,
        )
        return Block(header=header, transactions=tx_dicts)

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
        if h.index != len(prefix):
            return False, f"Índice incorrecto: esperado {len(prefix)}, recibido {h.index}", None
        if h.previous_hash != prev.hash:
            return False, "Hash previo no coincide", None
        if block.compute_hash() != block.hash:
            return False, "Hash del bloque inválido", None
        expected = self.expected_difficulty(prefix)
        if h.difficulty != expected:
            return False, (f"Dificultad incorrecta: esperada {expected}, "
                           f"recibida {h.difficulty}"), None
        if not block.hash.startswith("0" * h.difficulty):
            return False, "Proof of Work insuficiente: el hash no cumple la dificultad", None
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

    def get_credentials_for(self, address: str) -> List[dict]:
        credentials = []
        for block in self.chain:
            for tx in block.transactions:
                if (
                    tx.get("type") == TransactionType.CREDENTIAL_ISSUE
                    and tx.get("recipient") == address
                ):
                    credentials.append({**tx["payload"], "block": block.header.index})
        return credentials

    def get_transaction(self, tx_id: str) -> Optional[dict]:
        for block in self.chain:
            for tx in block.transactions:
                if tx.get("tx_id") == tx_id:
                    return {**tx, "block": block.header.index, "confirmed": True}
        return None

    def get_stats(self) -> dict:
        total_tx = sum(len(b.transactions) for b in self.chain)
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

        Complejidad: O(H) donde H = altura de la cadena.
        """
        for block in self.chain:
            if block.hash == block_hash:
                return block
        return None

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
        """Dificultad exigida al bloque de altura h = len(prefix), dada chain[:h].

        Función pura de los bloques anteriores y de los parámetros de la cadena.
        - Génesis: dificultad 0 (fija).
        - Mientras no haya `difficulty_window` bloques posteriores al génesis
          (h <= window): `initial_difficulty`.
        - Después: se miden los últimos `window` bloques (sin incluir el génesis,
          cuyo timestamp es artificial). tiempo medio < target/2 -> +1;
          > target*2 -> -1; si no, igual. Siempre acotada a [min, max].
        """
        h = len(prefix)
        if h == 0:
            return 0
        w = self.difficulty_window
        if h <= w:
            return self.initial_difficulty
        recent = prefix[-w:]
        elapsed = recent[-1].header.timestamp - recent[0].header.timestamp
        intervals = w - 1
        current = prefix[-1].header.difficulty
        # avg = elapsed / intervals, comparado sin dividir.
        if elapsed < self.target_block_time * 0.5 * intervals:
            nxt = current + 1
        elif elapsed > self.target_block_time * 2.0 * intervals:
            nxt = current - 1
        else:
            nxt = current
        return max(self.min_difficulty, min(self.max_difficulty, nxt))

    def _calculate_difficulty(self) -> int:
        """Dificultad esperada del PRÓXIMO bloque (la que debe usar el minado)."""
        return self.expected_difficulty(self.chain)

    # ── Reemplazo de cadena (fork resolution, P0-5) ──────────────────────────

    @staticmethod
    def block_work(block: Block) -> int:
        """Trabajo esperado para minar `block`: 16**dificultad intentos (entero)."""
        return 16 ** block.header.difficulty

    @classmethod
    def cumulative_work(cls, chain: List[Block]) -> int:
        """Trabajo acumulado de una cadena = Σ 16**dificultad (determinista, sin floats)."""
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

    def replace_chain(self, new_chain: List[dict]) -> Tuple[bool, str]:
        """Adopta `new_chain` si es válida y tiene MÁS trabajo acumulado (P0-5).

        Reglas:
          1. Mismo génesis y validez de consenso completa (`_validate_blocks`).
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
        except (KeyError, TypeError, ValueError, AttributeError) as e:
            return False, f"Cadena recibida malformada: {e}"
        # Validación costosa fuera del lock: una cadena válida lo sigue siendo.
        valid, reason, states = self._replay_blocks(candidate)
        if not valid:
            return False, f"Cadena recibida inválida: {reason}"
        new_work = self.cumulative_work(candidate)

        with self._lock:
            our_work = self.cumulative_work(self.chain)
            if new_work <= our_work:
                return False, (
                    f"Cadena recibida sin más trabajo acumulado ({new_work} <= {our_work})"
                )
            # Último bloque común (el génesis siempre coincide).
            fork = 0
            limit = min(len(self.chain), len(candidate))
            while fork + 1 < limit and self.chain[fork + 1].hash == candidate[fork + 1].hash:
                fork += 1
            dropped = self.chain[fork + 1:]
            added = candidate[fork + 1:]
            new_ids = self._collect_ids(candidate)

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

            self.chain = candidate
            self._confirmed_ids = new_ids
            self.mempool = []
            self.contracts.commit(states, len(candidate) - 1)
            self._save_to_disk()
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
