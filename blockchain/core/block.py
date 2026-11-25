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

from blockchain.core.merkle import leaf_hash, merkle_root_from_leaves

# ── Constantes del génesis (P0-1) ─────────────────────────────────────────────
# Cambiar CUALQUIERA de estas constantes cambia GENESIS_HASH y vuelve
# incompatibles las cadenas existentes (es una nueva red).
GENESIS_TIMESTAMP = 1767225600.0  # 2026-01-01T00:00:00Z, fijo
GENESIS_DATA = "UPB-Chain Genesis Block — Universidad Privada Boliviana"
# Dirección de la autoridad UPB (P0-6): la única que puede firmar TXs
# ISSUER_REGISTER (alta de emisores de credenciales). La llave privada NUNCA se
# versiona: vive en data/keys/authority.json (ver scripts/crear_llave_autoridad.py).
GENESIS_AUTHORITY_ADDRESS = "UPB780F80F6D68015E955B60BD6BEAB9F22"
# Hash esperado del bloque 0. Fijado a mano para detectar cambios accidentales
# (un test verifica que create_genesis() lo reproduce).
GENESIS_HASH = "5aaf08e12cacfc76329174fe7ac6d8348e2665df3e6fef2037aae5fa5dfb262f"


# ── Dificultad en bits (P2-5) ─────────────────────────────────────────────────
# `header.difficulty` = número de BITS iniciales en cero que debe tener el hash
# SHA-256 del bloque, leído como entero de 256 bits. Equivale a pedir
#
#     int(hash, 16) < objetivo,   con   objetivo = 2**(256 - bits)
#
# La probabilidad de que un intento cumpla es 2**-bits, así que el trabajo
# esperado (intentos promedio) de un bloque es 2**bits. Cada bit más duplica el
# trabajo (antes, con ceros hexadecimales, cada paso lo multiplicaba por 16).
# Ejemplo: 4 bits ⇔ el primer carácter hex es "0"; 8 bits ⇔ empieza con "00";
# 6 bits ⇔ empieza con "0" y el segundo carácter hex es 0, 1, 2 o 3.
# El génesis usa 0 bits (objetivo 2**256: cualquier hash cumple).
# Todo es aritmética entera: determinista en cualquier máquina.
HASH_BITS = 256


def target_for_bits(bits: int) -> int:
    """Objetivo entero: un hash cumple `bits` si su valor es MENOR que esto."""
    return 1 << (HASH_BITS - bits)


def hash_meets_bits(block_hash: str, bits: int) -> bool:
    """True si el hash (hex de 64 caracteres) tiene al menos `bits` bits iniciales en cero."""
    if not isinstance(bits, int) or isinstance(bits, bool) or not 0 <= bits <= HASH_BITS:
        return False
    if len(block_hash) != HASH_BITS // 4:
        return False
    try:
        value = int(block_hash, 16)
    except ValueError:
        return False
    return value < target_for_bits(bits)


def work_for_bits(bits: int) -> int:
    """Trabajo esperado de un bloque con `bits` de dificultad: 2**bits intentos (entero)."""
    return 1 << bits


@dataclass
class BlockHeader:
    index: int
    timestamp: float
    previous_hash: str
    merkle_root: str
    nonce: int = 0
    difficulty: int = 4  # bits iniciales en cero exigidos al hash (P2-5)
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
        return merkle_root_from_leaves([leaf_hash(tx) for tx in transactions])

    @classmethod
    def create_genesis(cls, node_id: str = "genesis") -> "Block":
        """Bloque génesis fijo y determinista (idéntico en todos los nodos).

        El parámetro ``node_id`` se conserva por compatibilidad pero se ignora:
        el génesis no depende del nodo que lo crea, de lo contrario dos nodos
        tendrían bloques 0 distintos y nunca podrían sincronizar (P0-1).
        """
        genesis_tx = {
            "type": "GENESIS",
            "data": GENESIS_DATA,
            "authority_address": GENESIS_AUTHORITY_ADDRESS,
            "timestamp": GENESIS_TIMESTAMP,
        }
        merkle_root = cls.compute_merkle_root([genesis_tx])
        header = BlockHeader(
            index=0,
            timestamp=GENESIS_TIMESTAMP,
            previous_hash="0" * 64,
            merkle_root=merkle_root,
            nonce=0,
            difficulty=0,
            node_id="genesis",
        )
        return cls(header=header, transactions=[genesis_tx])

    @classmethod
    def from_dict(cls, data: dict) -> "Block":
        header = BlockHeader(**data["header"])
        block = cls(header=header, transactions=data["transactions"])
        block.hash = data["hash"]
        return block
