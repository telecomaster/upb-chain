"""Verificador liviano de inclusión Merkle (P2-2).

Sólo usa hashlib/json (+ httpx para descargar). No importa el paquete del
nodo: la verificación es independiente de él.

Uso:  python scripts/verificar_prueba.py <tx_id> --base-url http://127.0.0.1:8000

Comprueba: (1) la prueba Merkle lleva la hoja a la raíz del encabezado;
(2) el hash del bloque se recalcula desde el bloque completo (en esta cadena
el hash cubre también las transacciones, por eso se descarga el bloque entero);
(3) el hash cumple la dificultad del encabezado, medida en bits (P2-5):
    int(hash, 16) < 2**(256 - bits).
"""
import argparse
import hashlib
import json
import sys


def _h(texto: str) -> str:
    return hashlib.sha256(texto.encode()).hexdigest()


def verificar_prueba(hoja: str, prueba: list, raiz: str) -> bool:
    actual = hoja
    for paso in prueba:
        if paso["position"] == "left":
            actual = _h(paso["hash"] + actual)
        elif paso["position"] == "right":
            actual = _h(actual + paso["hash"])
        else:
            return False
    return actual == raiz


def hash_bloque(bloque: dict) -> str:
    h = bloque["header"]
    d = {
        "index": h["index"], "timestamp": h["timestamp"],
        "previous_hash": h["previous_hash"], "merkle_root": h["merkle_root"],
        "nonce": h["nonce"], "difficulty": h["difficulty"],
        "version": h["version"], "node_id": h["node_id"],
        "transactions": bloque["transactions"],
    }
    return _h(json.dumps(d, sort_keys=True, ensure_ascii=False))


def cumple_bits(hash_hex: str, bits) -> bool:
    """Prueba de trabajo en bits: el hash como entero debe ser < 2**(256 - bits)."""
    if not isinstance(bits, int) or isinstance(bits, bool) or not 0 <= bits <= 256:
        return False
    try:
        return len(hash_hex) == 64 and int(hash_hex, 16) < (1 << (256 - bits))
    except ValueError:
        return False


def verificar(p: dict, bloque: dict) -> list:
    """Devuelve la lista de fallos (vacía = todo correcto)."""
    fallos = []
    tx = next((t for t in bloque["transactions"] if t.get("tx_id") == p["tx_id"]), None)
    if tx is None:
        fallos.append("la transacción no está en el bloque descargado")
    elif _h(json.dumps(tx, sort_keys=True)) != p["leaf"]:
        fallos.append("la hoja no corresponde al contenido de la transacción")
    if p["merkle_root"] != bloque["header"]["merkle_root"]:
        fallos.append("la raíz de la prueba no coincide con el encabezado")
    if not verificar_prueba(p["leaf"], p["proof"], bloque["header"]["merkle_root"]):
        fallos.append("la prueba Merkle no llega a la raíz del encabezado")
    if hash_bloque(bloque) != bloque["hash"] or bloque["hash"] != p["block_hash"]:
        fallos.append("el hash del bloque no se recalcula correctamente")
    if not cumple_bits(bloque["hash"], bloque["header"]["difficulty"]):
        fallos.append("el hash del bloque no cumple la prueba de trabajo")
    return fallos


def main() -> int:
    ap = argparse.ArgumentParser(description="Verificador liviano de inclusión Merkle")
    ap.add_argument("tx_id")
    ap.add_argument("--base-url", default="http://127.0.0.1:8000")
    a = ap.parse_args()
    import httpx
    base = a.base_url.rstrip("/")
    r = httpx.get(f"{base}/tx/{a.tx_id}/proof", timeout=15)
    if r.status_code != 200:
        print(f"SIN PRUEBA: {r.json().get('detail', r.text)}")
        return 2
    p = r.json()
    bloque = httpx.get(f"{base}/blocks/{p['block_index']}", timeout=15).json()
    fallos = verificar(p, bloque)
    if fallos:
        print("INVÁLIDA: " + "; ".join(fallos))
        return 1
    print(f"VÁLIDA: la transacción {p['tx_id']} está incluida en el bloque "
          f"{p['block_index']} (hash {p['block_hash'][:16]}…), con prueba de "
          f"{len(p['proof'])} pasos y prueba de trabajo correcta.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
