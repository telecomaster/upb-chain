"""
Verifica una Verifiable Credential exportada por UPB-Chain (P2-3).

Uso:
    venv\\Scripts\\python.exe scripts\\verificar_vc.py credencial.json http://127.0.0.1:8000

Independiente del nodo: solo usa la biblioteca estándar y NO importa el paquete
``blockchain``; repite aquí el hash de bloque, el árbol Merkle y el compromiso de campos.
Comprueba (contra el nodo indicado, que es la fuente de confianza):

1. did.json: la llave del emisor (fragmento de ``issuer.id``) está en
   ``/.well-known/did.json`` y coincide con la llave pública que firmó la TX.
2. Ancla: la TX está en el bloque, el hash del bloque se recalcula, la prueba Merkle
   enlaza la TX con la raíz y el payload en cadena coincide con la VC.
3. Estado: la credencial no está revocada ni expirada.
4. Divulgación (si la VC la trae): cada campo revelado pertenece a ``fields_root``.

No verifica la firma ECDSA de la TX (se confía en que el nodo ya la validó al admitir
el bloque) ni el contexto JSON-LD. Código de salida 0 = todo correcto.
"""
import argparse
import base64
import hashlib
import json
import sys
import urllib.error
import urllib.request
from typing import Callable, List, Optional, Tuple

Chequeo = Tuple[str, bool, str]


def _sha(texto: str) -> str:
    return hashlib.sha256(texto.encode()).hexdigest()


def _b64url(datos: bytes) -> str:
    return base64.urlsafe_b64encode(datos).rstrip(b"=").decode("ascii")


def merkle_verify(leaf: str, proof: list, root: str) -> bool:
    actual = leaf
    for paso in proof:
        if paso.get("position") == "left":
            actual = _sha(paso["hash"] + actual)
        elif paso.get("position") == "right":
            actual = _sha(actual + paso["hash"])
        else:
            return False
    return actual == root


def hash_bloque(bloque: dict) -> str:
    h = bloque["header"]
    campos = {k: h[k] for k in ("index", "timestamp", "previous_hash", "merkle_root", "nonce",
                                "difficulty", "version", "node_id")}
    campos["transactions"] = bloque["transactions"]
    return _sha(json.dumps(campos, sort_keys=True, ensure_ascii=False))


def hoja_campo(item: dict) -> str:
    valor = json.dumps(item["value"], sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(bytes.fromhex(item["salt"]) + item["name"].encode("utf-8") + valor).hexdigest()


def campo_pertenece(raiz: str, item: dict) -> bool:
    try:
        return merkle_verify(hoja_campo(item), item["proof"], raiz)
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def jwk_de_spki(public_key_hex: str) -> dict:
    """JWK secp256k1 desde DER SPKI: los últimos 65 bytes son 04 || x || y."""
    punto = bytes.fromhex(public_key_hex)[-65:]
    if punto[0] != 4:
        raise ValueError("Llave no es un punto sin comprimir")
    return {"x": _b64url(punto[1:33]), "y": _b64url(punto[33:])}


def fetch_http(base_url: str) -> Callable[[str], dict]:
    def fetch(path: str) -> dict:
        with urllib.request.urlopen(base_url.rstrip("/") + path, timeout=15) as r:
            return json.loads(r.read().decode("utf-8"))
    return fetch


def verify_vc(vc: dict, fetch: Callable[[str], dict]) -> List[Chequeo]:
    """Devuelve la lista de chequeos (nombre, ok, detalle). ``fetch(ruta)`` → JSON del nodo."""
    res: List[Chequeo] = []

    def chk(nombre: str, ok: bool, detalle: str = "") -> bool:
        res.append((nombre, bool(ok), detalle))
        return bool(ok)

    try:
        ev = vc["evidence"][0]
        issuer_id = vc["issuer"]["id"]
        did, _, direccion = issuer_id.partition("#")
        cid = vc["credentialSubject"]["achievement"]["id"].rsplit(":", 1)[-1]
        sujeto = vc["credentialSubject"]
    except (KeyError, IndexError, TypeError, AttributeError) as e:
        chk("estructura", False, f"VC incompleta: {e!r}")
        return res
    chk("estructura", "VerifiableCredential" in vc.get("type", []) and ev.get("type") == ["UPBChainAnchor"])

    # 1) did.json y llave de la TX
    try:
        bloque = fetch(f"/blocks/{ev['blockIndex']}")
        doc = fetch("/.well-known/did.json")
        tx = next((t for t in bloque["transactions"] if t.get("tx_id") == ev["txId"]), None)
    except (urllib.error.URLError, OSError, KeyError, ValueError) as e:
        chk("consulta al nodo", False, repr(e))
        return res
    chk("TX dentro del bloque", tx is not None)
    if tx is None:
        return res
    metodo = next((m for m in doc.get("verificationMethod", []) if m.get("id") == issuer_id), None)
    chk("did.json: llave del emisor", metodo is not None and doc.get("id") == did,
        f"{issuer_id} en {doc.get('id')}")
    try:
        jwk_tx = jwk_de_spki(tx["public_key"])
        chk("llave de did.json = llave que firmó la TX",
            metodo is not None and metodo["publicKeyJwk"].get("x") == jwk_tx["x"]
            and metodo["publicKeyJwk"].get("y") == jwk_tx["y"] and tx.get("sender") == direccion)
    except (KeyError, ValueError, TypeError):
        chk("llave de did.json = llave que firmó la TX", False, "TX sin llave pública válida")

    # 2) ancla: bloque, hash, Merkle y payload
    try:
        hash_ok = hash_bloque(bloque) == ev["blockHash"] == bloque.get("hash")
        chk("hash del bloque recalculado", hash_ok)
        hoja = _sha(json.dumps(tx, sort_keys=True))
        chk("hoja = hash de la TX", hoja == ev["leaf"])
        chk("prueba Merkle de la TX",
            merkle_verify(hoja, ev["merkleProof"], ev["merkleRoot"])
            and ev["merkleRoot"] == bloque["header"]["merkle_root"])
    except (KeyError, TypeError, ValueError, urllib.error.URLError, OSError) as e:
        chk("ancla en cadena", False, repr(e))
    payload = tx.get("payload") or {}
    ach = sujeto["achievement"]
    chk("payload en cadena = VC",
        payload.get("fields_root") == ev.get("fieldsRoot")
        and payload.get("degree") == ach.get("name") and payload.get("program") == ach.get("program")
        and tx.get("recipient") == sujeto.get("id", "").rsplit(":", 1)[-1])

    # 3) estado vigente
    try:
        st = fetch(f"/credentials/verify/{cid}")
        chk("estado vigente", st.get("valid") is True, st.get("status", "?"))
    except (urllib.error.URLError, OSError, ValueError) as e:
        chk("estado vigente", False, repr(e))

    # 4) divulgación selectiva
    div = sujeto.get("upbDisclosure")
    if div is not None:
        raiz = payload.get("fields_root")
        chk("divulgación: raíz = fields_root en cadena", div.get("fieldsRoot") == raiz)
        for item in div.get("revealed", []):
            chk(f"divulgación: campo {item.get('name')}", campo_pertenece(raiz, item))
        chk("divulgación: hay campos", bool(div.get("revealed")))
    return res


def construir_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Verifica una Verifiable Credential exportada por UPB-Chain (P2-3).",
        epilog="Código de salida: 0 = VC válida, 1 = VC no válida o archivo ilegible, 2 = uso incorrecto.",
    )
    ap.add_argument("credencial", help="Archivo JSON con la Verifiable Credential")
    ap.add_argument("base_url", help="URL del nodo de confianza, p. ej. http://127.0.0.1:8000")
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    a = construir_parser().parse_args(argv)
    try:
        with open(a.credencial, encoding="utf-8") as f:
            vc = json.load(f)
    except FileNotFoundError:
        print(f"Error: no existe el archivo '{a.credencial}'.", file=sys.stderr)
        return 1
    except (OSError, ValueError) as e:
        print(f"Error: no se pudo leer '{a.credencial}' como JSON ({e}).", file=sys.stderr)
        return 1
    resultados = verify_vc(vc, fetch_http(a.base_url))
    for nombre, ok, detalle in resultados:
        print(f"[{'OK' if ok else 'FALLA'}] {nombre}" + (f" ({detalle})" if detalle else ""))
    todo = bool(resultados) and all(ok for _, ok, _ in resultados)
    print("VC VÁLIDA" if todo else "VC NO VÁLIDA")
    return 0 if todo else 1


if __name__ == "__main__":
    sys.exit(main())
