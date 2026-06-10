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
    Regla de la cadena más larga: ante dos cadenas válidas, se acepta la
    de mayor altura (mayor trabajo acumulado). Es la regla de Nakamoto.
    Ref: Nakamoto (2008), Sección 5 — Longest chain rule.

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
import time
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional, Tuple

from blockchain.core.block import Block, BlockHeader
from blockchain.core.transaction import Transaction, TransactionType

logger = logging.getLogger("upb_chain.core")


class Blockchain:
    def __init__(self, node_id: str, data_dir: str = "data/chain"):
        self.node_id = node_id
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.chain: List[Block] = []
        self.mempool: List[Transaction] = []
        self._lock = Lock()

        self._load_or_init()

    # ── Inicialización ────────────────────────────────────────────────────────

    def _load_or_init(self) -> None:
        chain_file = self.data_dir / "chain.json"
        if chain_file.exists():
            self._load_from_disk(chain_file)
            logger.info(f"Cadena cargada: {len(self.chain)} bloques")
        else:
            genesis = Block.create_genesis(self.node_id)
            self.chain.append(genesis)
            self._save_to_disk()
            logger.info("Génesis creado")

    def _load_from_disk(self, path: Path) -> None:
        with open(path) as f:
            data = json.load(f)
        self.chain = [Block.from_dict(b) for b in data]

    def _save_to_disk(self) -> None:
        chain_file = self.data_dir / "chain.json"
        with open(chain_file, "w") as f:
            json.dump([b.to_dict() for b in self.chain], f, indent=2)

    # ── Propiedades ───────────────────────────────────────────────────────────

    @property
    def last_block(self) -> Block:
        return self.chain[-1]

    @property
    def height(self) -> int:
        return len(self.chain) - 1

    # ── Mempool ───────────────────────────────────────────────────────────────

    def add_transaction(self, tx: Transaction) -> Tuple[bool, str]:
        valid, reason = tx.is_valid()
        if not valid:
            return False, reason
        if any(t.tx_id == tx.tx_id for t in self.mempool):
            return False, "Transacción duplicada"
        with self._lock:
            self.mempool.append(tx)
        logger.debug(f"TX {tx.tx_id[:8]}… añadida al mempool")
        return True, "OK"

    def get_pending_transactions(self, limit: int = 100) -> List[Transaction]:
        return self.mempool[:limit]

    # ── Minado / adición de bloques ───────────────────────────────────────────

    def add_block(self, block: Block) -> Tuple[bool, str]:
        with self._lock:
            valid, reason = self._validate_block(block)
            if not valid:
                return False, reason
            self.chain.append(block)
            # Remueve transacciones confirmadas del mempool
            confirmed_ids = {tx.get("tx_id") for tx in block.transactions}
            self.mempool = [t for t in self.mempool if t.tx_id not in confirmed_ids]
            self._save_to_disk()
        logger.info(f"Bloque #{block.header.index} añadido (hash={block.hash[:12]}…)")
        return True, "OK"

    def create_candidate_block(self, transactions: Optional[List[Transaction]] = None) -> Block:
        txs = transactions or self.get_pending_transactions(50)
        tx_dicts = [t.to_dict() for t in txs]
        merkle_root = Block.compute_merkle_root(tx_dicts)
        header = BlockHeader(
            index=self.height + 1,
            timestamp=time.time(),
            previous_hash=self.last_block.hash,
            merkle_root=merkle_root,
            difficulty=self._calculate_difficulty(),
            node_id=self.node_id,
        )
        return Block(header=header, transactions=tx_dicts)

    # ── Validación ────────────────────────────────────────────────────────────

    def _validate_block(self, block: Block) -> Tuple[bool, str]:
        if block.header.index != self.height + 1:
            return False, f"Índice incorrecto: esperado {self.height + 1}, recibido {block.header.index}"
        if block.header.previous_hash != self.last_block.hash:
            return False, "Hash previo no coincide"
        if block.compute_hash() != block.hash:
            return False, "Hash del bloque inválido"
        merkle = Block.compute_merkle_root(block.transactions)
        if merkle != block.header.merkle_root:
            return False, "Merkle root inválido"
        return True, "OK"

    def validate_chain(self) -> Tuple[bool, str]:
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]
            if current.header.previous_hash != previous.hash:
                return False, f"Bloque {i}: hash previo roto"
            if current.compute_hash() != current.hash:
                return False, f"Bloque {i}: hash inválido"
            merkle = Block.compute_merkle_root(current.transactions)
            if merkle != current.header.merkle_root:
                return False, f"Bloque {i}: Merkle root inválido"
        return True, "Cadena válida"

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
    def total_fees(self) -> float:
        """Suma todas las fees de transacciones en bloques confirmados."""
        return round(
            sum(
                tx.get("fee", 0.0)
                for block in self.chain
                for tx in block.transactions
            ),
            8,
        )

    def get_balance(self, address: str) -> float:
        """Retorna el balance neto de fees para una dirección.

        balance = Σ fees recibidas (recipient == address)
                − Σ fees pagadas   (sender    == address)

        Complejidad: O(H * n) donde H = altura, n = TXs por bloque.
        """
        balance = 0.0
        for block in self.chain:
            for tx in block.transactions:
                fee = float(tx.get("fee", 0.0))
                if tx.get("sender") == address:
                    balance -= fee
                if tx.get("recipient") == address:
                    balance += fee
        return round(balance, 8)

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

    def _calculate_difficulty(self, target_time: float = 10.0, window: int = 10) -> int:
        if len(self.chain) < window:
            return 4
        recent = self.chain[-window:]
        elapsed = recent[-1].header.timestamp - recent[0].header.timestamp
        avg_time = elapsed / (window - 1) if elapsed > 0 else target_time
        current_diff = self.last_block.header.difficulty
        if avg_time < target_time * 0.5:
            return min(current_diff + 1, 8)
        if avg_time > target_time * 2.0:
            return max(current_diff - 1, 1)
        return current_diff

    # ── Reemplazo de cadena (fork resolution) ────────────────────────────────

    def replace_chain(self, new_chain: List[dict]) -> Tuple[bool, str]:
        candidate = [Block.from_dict(b) for b in new_chain]
        if len(candidate) <= len(self.chain):
            return False, "Cadena recibida no es más larga"
        temp = Blockchain.__new__(Blockchain)
        temp.chain = candidate
        temp.mempool = []
        temp._lock = Lock()
        valid, reason = temp.validate_chain()
        if not valid:
            return False, f"Cadena recibida inválida: {reason}"
        with self._lock:
            self.chain = candidate
            self._save_to_disk()
        logger.info(f"Cadena reemplazada: ahora altura {self.height}")
        return True, "OK"
