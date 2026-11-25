"""
Exportación de credenciales como Verifiable Credentials y documento did:web (P2-3).

Capa de interoperabilidad: no cambia el consenso ni lo que se guarda en la cadena.
Funciones puras que construyen JSON a partir de datos ya confirmados. Está "alineado
con" W3C VC Data Model 2.0, Open Badges 3.0 y did:web; NO está validado contra los
esquemas oficiales ni certificado (ver docs/credenciales_vc.md).

Decisión de firma: la VC se entrega SIN ``proof`` propio. El nodo no guarda la llave
del emisor (firma en el cliente, P1-2) y no se inventa una suite de firma. La prueba
de emisión es el ancla en cadena (``evidence`` tipo ``UPBChainAnchor``): la TX
firmada por el emisor (ECDSA secp256k1 sobre el mensaje de la TX), su bloque y la
prueba Merkle de inclusión.
"""
import base64
from typing import Dict, List, Optional
from urllib.parse import urlparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

CONTEXTO_VC = "https://www.w3.org/ns/credentials/v2"
CONTEXTO_OB3 = "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"
CONTEXTO_DID = "https://www.w3.org/ns/did/v1"
CONTEXTO_JWK = "https://w3id.org/security/suites/jws-2020/v1"

# Tipos de credencial UPB → achievementType de Open Badges 3.0 (los que existen en su lista).
ACHIEVEMENT_TYPE = {
    "DEGREE": "Degree",
    "POSTGRADE": "MasterDegree",
    "CERTIFICATION": "Certificate",
    "TRANSCRIPT": "Diploma",
    "AWARD": "Achievement",
}


def _b64url(datos: bytes) -> str:
    return base64.urlsafe_b64encode(datos).rstrip(b"=").decode("ascii")


def jwk_from_public_key_hex(public_key_hex: str) -> dict:
    """JWK (kty EC, crv secp256k1) desde la llave pública DER SubjectPublicKeyInfo en hex."""
    pub = serialization.load_der_public_key(bytes.fromhex(public_key_hex))
    nums = pub.public_numbers()
    if not isinstance(nums.curve, ec.SECP256K1):
        raise ValueError("La llave no es secp256k1")
    return {"kty": "EC", "crv": "secp256k1",
            "x": _b64url(nums.x.to_bytes(32, "big")),
            "y": _b64url(nums.y.to_bytes(32, "big"))}


def did_domain(did_web_domain: str, public_base_url: str, request_base_url: str = "") -> str:
    """Dominio del did:web: ``DID_WEB_DOMAIN``, si no el host de PUBLIC_BASE_URL o del request.

    did:web codifica el puerto como ``%3A`` (``localhost%3A8000``).
    """
    if did_web_domain:
        return did_web_domain.replace(":", "%3A")
    base = public_base_url or request_base_url
    netloc = urlparse(base).netloc or "localhost"
    return netloc.replace(":", "%3A")


def did_of(domain: str) -> str:
    return f"did:web:{domain}"


def build_did_document(domain: str, keys: Dict[str, str],
                       authority_address: Optional[str], issuers: Dict[str, str]) -> dict:
    """Documento DID. ``keys``: dirección → llave pública DER hex (las que la cadena conoce).

    Cada llave es un verificationMethod ``{did}#{dirección}`` (JsonWebKey). La autoridad y
    los emisores registrados con llave conocida aparecen en ``assertionMethod``; un emisor
    registrado que aún no firmó ninguna TX no tiene llave pública en la cadena y se omite.
    """
    did = did_of(domain)
    metodos, asercion = [], []
    direcciones = ([authority_address] if authority_address else []) + [
        a for a in sorted(issuers) if a != authority_address]
    for addr in direcciones:
        if addr not in keys:
            continue
        vid = f"{did}#{addr}"
        metodos.append({"id": vid, "type": "JsonWebKey", "controller": did,
                        "publicKeyJwk": jwk_from_public_key_hex(keys[addr])})
        asercion.append(vid)
    return {"@context": [CONTEXTO_DID, CONTEXTO_JWK], "id": did,
            "verificationMethod": metodos, "authentication": [], "assertionMethod": asercion}


def _contexto(domain: str) -> list:
    # Términos propios (UPBChainAnchor, fieldsRoot...) bajo un @vocab de la UPB: sin publicar.
    return [CONTEXTO_VC, CONTEXTO_OB3, {"@vocab": f"https://{domain.replace('%3A', ':')}/ns/upb-chain#"}]


def _fecha(valor: Optional[str]) -> Optional[str]:
    """Fecha ISO de solo día → dateTime a medianoche UTC (validFrom/validUntil lo exigen)."""
    if not valor:
        return None
    return valor + "T00:00:00Z" if len(valor) == 10 else valor


def build_vc(domain: str, base_url: str, cred: dict, status: dict, anchor: dict,
             disclosure: Optional[dict] = None) -> dict:
    """VC sin ``proof`` propio con el ancla en cadena como ``evidence``.

    ``cred``: ``AcademicCredential.to_dict()``; ``status``: ``credential_status(...)``;
    ``anchor``: {tx_id, block_index, block_hash, merkle_root, leaf, proof}.
    ``disclosure``: paquete de P1-2 ya comprobado ({fields_root, revealed}), opcional.
    """
    base = base_url.rstrip("/")
    did = did_of(domain)
    cid = cred["credential_id"]
    tipo = cred["credential_type"]
    tipo = getattr(tipo, "value", tipo)
    sujeto = {
        "id": f"urn:upb-chain:address:{cred['student_address']}",
        "type": ["AchievementSubject"],
        "achievement": {
            "id": f"urn:upb-chain:credential:{cid}",
            "type": ["Achievement"],
            "achievementType": ACHIEVEMENT_TYPE.get(tipo, "Achievement"),
            "name": cred["degree"],
            "description": f"{cred['program']} ({cred['institution']})",
            "criteria": {"narrative": "Credencial emitida y confirmada en la cadena UPB-Chain."},
            "program": cred["program"],
        },
    }
    if disclosure is not None:
        sujeto["type"].append("UPBSaltedFieldDisclosure")
        sujeto["upbDisclosure"] = {
            "type": "UPBSaltedFieldDisclosure",
            "fieldsRoot": disclosure["fields_root"],
            "revealed": disclosure["revealed"],
        }
    estado = status["status"]
    vc = {
        "@context": _contexto(domain),
        "id": f"{base}/credentials/{cid}/vc",
        "type": ["VerifiableCredential", "OpenBadgeCredential"],
        "issuer": {"id": f"{did}#{cred['issuer_address']}", "type": ["Profile"],
                   "name": cred["institution"]},
        "validFrom": _fecha(cred["issue_date"]),
        "credentialSubject": sujeto,
        "credentialStatus": {
            "id": f"{base}/credentials/verify/{cid}",
            "type": "UPBChainStatus",
            "statusPurpose": "revocation",
            "status": estado,
            "statusReason": status.get("reason"),
            "note": "Instantánea al generar la VC; el estado vigente es el del endpoint id.",
        },
        "evidence": [{
            "type": ["UPBChainAnchor"],
            "id": f"{base}/transactions/{anchor['tx_id']}",
            "txId": anchor["tx_id"],
            "blockIndex": anchor["block_index"],
            "blockHash": anchor["block_hash"],
            "merkleRoot": anchor["merkle_root"],
            "leaf": anchor["leaf"],
            "merkleProof": anchor["proof"],
            "proofEndpoint": f"{base}/tx/{anchor['tx_id']}/proof",
            "fieldsRoot": cred["fields_root"],
            "issuerAddress": cred["issuer_address"],
        }],
    }
    if cred.get("expiry_date"):
        vc["validUntil"] = _fecha(cred["expiry_date"])
    return vc


def public_keys_from_blocks(blocks) -> Dict[str, str]:
    """dirección → llave pública DER hex, tomada de las TXs firmadas ya confirmadas."""
    keys: Dict[str, str] = {}
    for block in blocks:
        for tx in block.transactions:
            sender, pk = tx.get("sender"), tx.get("public_key")
            if sender and pk and sender not in keys:
                keys[sender] = pk
    return keys
