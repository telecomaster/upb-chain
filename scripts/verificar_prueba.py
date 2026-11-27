"""Verificador liviano de inclusión Merkle (P2-2).

Sólo usa hashlib/json (+ httpx para descargar). No importa el paquete del
nodo: la verificación es independiente de él.

Uso:  python scripts/verificar_prueba.py <tx_id> --base-url http://127.0.0.1:8000

Comprueba: (1) la prueba Merkle lleva la hoja a la raíz del encabezado;
(2) el hash del bloque se recalcula desde el bloque completo (en esta cadena
el hash cubre también las transacciones, por eso se descarga el bloque entero);
(3) en PoW, el hash cumple la dificultad del encabezado, medida en bits (P2-5):
    int(hash, 16) < 2**(256 - bits);
(4) en PBFT (dificultad 0, el nodo informa consenso pbft) NO hay prueba de trabajo:
    se descarga el certificado de commit y se verifican las firmas ECDSA de >= 2f+1
    réplicas distintas sobre el hash del bloque.

Las llaves de las réplicas se toman del propio nodo (``/consensus``) salvo que se
pase ``--replicas`` con la lista de réplicas conocida por otra vía: en el primer caso
la verificación depende de confiar en el conjunto que informa el nodo.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path


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


def _payload_firma(msg: dict) -> str:
    """Texto que firma una réplica PBFT (como blockchain.consensus.pbft.signing_payload)."""
    cuerpo = {k: v for k, v in msg.items() if k not in ("signature", "block")}
    return json.dumps(cuerpo, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _firma_valida(mensaje: str, firma_b64: str, pub_hex: str) -> bool:
    """ECDSA secp256k1 sobre SHA-256; llave pública DER (SPKI) en hex, firma DER en base64."""
    import base64
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        pub = serialization.load_der_public_key(bytes.fromhex(pub_hex))
        pub.verify(base64.b64decode(firma_b64), mensaje.encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def verificar_certificado(cert, bloque: dict, replicas: list) -> tuple:
    """Devuelve (ok, motivo). ``replicas``: [{"id", "public_key"}, ...].

    Exige 2f+1 COMMIT (f = (n-1)//3) de réplicas distintas, de la misma vista y del mismo
    bloque (altura y hash), todos con firma válida contra la llave de su réplica."""
    n = len(replicas)
    cuorum = 2 * ((n - 1) // 3) + 1 if n else 1
    if not isinstance(cert, dict) or not isinstance(cert.get("commits"), list):
        return False, "no hay certificado de commit"
    llaves = {r["id"]: r["public_key"] for r in replicas}
    idx, h = bloque["header"]["index"], bloque["hash"]
    if cert.get("seq") != idx or cert.get("digest") != h:
        return False, "el certificado es de otro bloque"
    firmantes = set()
    for m in cert["commits"]:
        if not isinstance(m, dict) or m.get("type") != "COMMIT":
            return False, "el certificado contiene un mensaje que no es COMMIT"
        if m.get("view") != cert.get("view") or m.get("seq") != idx or m.get("digest") != h:
            return False, "un COMMIT es de otra vista o de otro bloque"
        rid = m.get("replica")
        if rid in firmantes:
            return False, f"firmante repetido: {rid}"
        if rid not in llaves or not isinstance(m.get("signature"), str) or \
                not _firma_valida(_payload_firma(m), m["signature"], llaves[rid]):
            return False, f"firma inválida o réplica desconocida: {rid}"
        firmantes.add(rid)
    if len(firmantes) < cuorum:
        return False, f"{len(firmantes)} firmas; se necesitan {cuorum} (2f+1 con n={n})"
    return True, f"{len(firmantes)} firmas válidas de réplicas distintas (cuórum {cuorum}, n={n})"


def verificar(p: dict, bloque: dict, pbft: bool = False) -> list:
    """Devuelve la lista de fallos (vacía = todo correcto). En PBFT no se exige trabajo
    (el certificado se comprueba aparte con ``verificar_certificado``)."""
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
    if not pbft and not cumple_bits(bloque["hash"], bloque["header"]["difficulty"]):
        fallos.append("el hash del bloque no cumple la prueba de trabajo")
    return fallos


def main() -> int:
    ap = argparse.ArgumentParser(description="Verificador liviano de inclusión Merkle")
    ap.add_argument("tx_id")
    ap.add_argument("--base-url", default="http://127.0.0.1:8000")
    ap.add_argument("--replicas", help="JSON con la lista de réplicas PBFT "
                    '({"replicas": [{"id", "public_key"}, ...]}) obtenida por otra vía; '
                    "si falta se usa la que informa el nodo")
    a = ap.parse_args()
    import httpx
    base = a.base_url.rstrip("/")
    r = httpx.get(f"{base}/tx/{a.tx_id}/proof", timeout=15)
    if r.status_code != 200:
        print(f"SIN PRUEBA: {r.json().get('detail', r.text)}")
        return 2
    p = r.json()
    bloque = httpx.get(f"{base}/blocks/{p['block_index']}", timeout=15).json()
    cons = httpx.get(f"{base}/consensus", timeout=15).json()
    pbft = cons.get("mode") == "pbft" or bloque["header"]["difficulty"] == 0
    fallos = verificar(p, bloque, pbft=pbft)
    cert_txt = ""
    if pbft:
        if a.replicas:
            with open(a.replicas, encoding="utf-8") as f:
                replicas, origen = json.load(f)["replicas"], f"del archivo {Path(a.replicas).name}"
        else:
            replicas, origen = cons.get("replicas") or [], "informado por el propio nodo (no verificado de forma independiente)"
        rc = httpx.get(f"{base}/blocks/{p['block_index']}/certificate", timeout=15)
        ok, motivo = verificar_certificado(rc.json() if rc.status_code == 200 else None, bloque, replicas)
        if not ok:
            fallos.append(f"certificado PBFT inválido: {motivo}")
        cert_txt = f"certificado PBFT: {motivo}; conjunto de réplicas {origen}; prueba de trabajo: no aplica (PBFT)"
    if fallos:
        print("INVÁLIDA: " + "; ".join(fallos))
        return 1
    cierre = cert_txt if pbft else "prueba de trabajo correcta"
    print(f"VÁLIDA: la transacción {p['tx_id']} está incluida en el bloque "
          f"{p['block_index']} (hash {p['block_hash'][:16]}…), con prueba de "
          f"{len(p['proof'])} pasos y {cierre}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
