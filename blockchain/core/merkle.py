"""Pruebas de inclusión Merkle (P2-2): funciones puras, sin estado.

Reproduce EXACTAMENTE la construcción de ``Block.compute_merkle_root``:

* hoja  = sha256(json.dumps(tx, sort_keys=True)) en hexadecimal;
* nodo  = sha256((hijo_izq + hijo_der).encode()) donde los hijos son las
  cadenas hex concatenadas (no los bytes);
* si un nivel tiene cantidad impar de nodos se DUPLICA el último;
* sin transacciones la raíz es sha256(b"").

Debilidades conocidas de esta construcción (consenso: NO se corrigen aquí,
cambiarlas altera GENESIS_HASH y todos los hashes de bloque):

1. Sin separación de dominio entre hojas y nodos internos (no hay prefijo
   distinto para hoja y nodo): abre la puerta a ataques de segunda preimagen
   en el árbol. Se mitiga en parte porque la hoja es sha256 de un JSON.
2. Duplicar el último nodo hace que [a, b, c] y [a, b, c, c] den la MISMA raíz
   (ambigüedad tipo CVE-2012-2459). La unicidad de tx_id en la validación del
   bloque impide aprovecharlo con transacciones repetidas.
3. La prueba no fija el índice ni la cantidad de hojas: ``verify_proof`` no
   puede saber en qué posición del bloque está la hoja.
"""
import hashlib
import json
from typing import List


def _sha256_hex(texto: str) -> str:
    return hashlib.sha256(texto.encode()).hexdigest()


def leaf_hash(tx: dict) -> str:
    """Hash de hoja de una transacción (idéntico al de Block)."""
    return _sha256_hex(json.dumps(tx, sort_keys=True))


def _par(izq: str, der: str) -> str:
    return _sha256_hex(izq + der)


def merkle_root_from_leaves(leaves: List[str]) -> str:
    """Raíz a partir de hojas ya hasheadas (lista vacía → sha256 de b"")."""
    if not leaves:
        return hashlib.sha256(b"").hexdigest()
    nivel = list(leaves)
    while len(nivel) > 1:
        if len(nivel) % 2 != 0:
            nivel.append(nivel[-1])
        nivel = [_par(nivel[i], nivel[i + 1]) for i in range(0, len(nivel), 2)]
    return nivel[0]


def build_proof(leaves: List[str], index: int) -> List[dict]:
    """Camino de hermanos desde la hoja ``index`` hasta la raíz.

    Cada paso es {"hash": hermano, "position": "left"|"right"}, donde
    ``position`` indica de qué lado está el HERMANO. Complejidad O(n).
    """
    if not 0 <= index < len(leaves):
        raise IndexError("índice de hoja fuera de rango")
    nivel = list(leaves)
    prueba: List[dict] = []
    while len(nivel) > 1:
        if len(nivel) % 2 != 0:
            nivel.append(nivel[-1])
        if index % 2 == 0:
            prueba.append({"hash": nivel[index + 1], "position": "right"})
        else:
            prueba.append({"hash": nivel[index - 1], "position": "left"})
        nivel = [_par(nivel[i], nivel[i + 1]) for i in range(0, len(nivel), 2)]
        index //= 2
    return prueba


def verify_proof(leaf: str, proof: List[dict], root: str) -> bool:
    """Recalcula la raíz desde ``leaf`` y el camino; True si coincide con ``root``."""
    actual = leaf
    for paso in proof:
        if paso.get("position") == "left":
            actual = _par(paso["hash"], actual)
        elif paso.get("position") == "right":
            actual = _par(actual, paso["hash"])
        else:
            return False
    return actual == root
