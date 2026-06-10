"""
UPB-Chain — Estructura de Bloque
Universidad Privada Boliviana · Carrera de Ingeniería en IA

Implementa la estructura de datos fundamental de la blockchain:
cada bloque enlaza criptográficamente con el anterior mediante SHA-256,
formando una cadena inmutable (hash chain).

Referencias:
    Nakamoto, S. (2008). Bitcoin: A Peer-to-Peer Electronic Cash System.
    Merkle, R. C. (1988). A Digital Signature Based on a Conventional Encryption Function.

Complejidades algorítmicas:
    compute_hash()      → O(|transactions|) en serialización JSON
    compute_merkle_root → O(n log n) donde n = número de transacciones
    from_dict()         → O(n) donde n = número de transacciones
"""
import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from typing import List, Optional


@dataclass
class BlockHeader:
    index: int
    timestamp: float
    previous_hash: str
    merkle_root: str
    nonce: int = 0
    difficulty: int = 4
    version: str = "1.0.0"
    node_id: str = ""


@dataclass
class Block:
    header: BlockHeader
    transactions: List[dict] = field(default_factory=list)
    hash: str = ""

    def __post_init__(self):
        if not self.hash:
            self.hash = self.compute_hash()

    def compute_hash(self) -> str:
        block_dict = {
            "index": self.header.index,
            "timestamp": self.header.timestamp,
            "previous_hash": self.header.previous_hash,
            "merkle_root": self.header.merkle_root,
            "nonce": self.header.nonce,
            "difficulty": self.header.difficulty,
            "version": self.header.version,
            "node_id": self.header.node_id,
            "transactions": self.transactions,
        }
        block_string = json.dumps(block_dict, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "header": asdict(self.header),
            "transactions": self.transactions,
            "hash": self.hash,
        }

    @staticmethod
    def compute_merkle_root(transactions: List[dict]) -> str:
        """
        Árbol de Merkle binario sobre las transacciones del bloque.

        Invariante: si cualquier TX cambia, la raíz cambia → detección O(log n).
        Complejidad: O(n log n) tiempo, O(n) espacio.
        Ref: Merkle (1988) — permite pruebas de inclusión en O(log n).
        """
        if not transactions:
            return hashlib.sha256(b"").hexdigest()

        tx_hashes = [
            hashlib.sha256(json.dumps(tx, sort_keys=True).encode()).hexdigest()
            for tx in transactions
        ]

        while len(tx_hashes) > 1:
            if len(tx_hashes) % 2 != 0:
                tx_hashes.append(tx_hashes[-1])
            tx_hashes = [
                hashlib.sha256((tx_hashes[i] + tx_hashes[i + 1]).encode()).hexdigest()
                for i in range(0, len(tx_hashes), 2)
            ]

        return tx_hashes[0]

    @classmethod
    def create_genesis(cls, node_id: str = "genesis") -> "Block":
        genesis_tx = {
            "type": "GENESIS",
            "data": "UPB-Chain Genesis Block — Universidad Privada Boliviana",
            "timestamp": time.time(),
        }
        merkle_root = cls.compute_merkle_root([genesis_tx])
        header = BlockHeader(
            index=0,
            timestamp=time.time(),
            previous_hash="0" * 64,
            merkle_root=merkle_root,
            nonce=0,
            difficulty=0,
            node_id=node_id,
        )
        return cls(header=header, transactions=[genesis_tx])

    @classmethod
    def from_dict(cls, data: dict) -> "Block":
        header = BlockHeader(**data["header"])
        block = cls(header=header, transactions=data["transactions"])
        block.hash = data["hash"]
        return block
