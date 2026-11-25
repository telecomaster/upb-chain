"""
Compromiso Merkle con sal sobre los datos personales de una credencial (P1-2).

En la cadena solo va ``fields_root``; los campos privados (nombre, nota,
metadatos...) y sus sales las guarda el estudiante. Funciones puras.

Codificación EXACTA (cualquier verificador externo debe reproducirla):

* ``valor_canonico(v)``  = ``json.dumps(v, sort_keys=True, separators=(",", ":"),
  ensure_ascii=False).encode("utf-8")``
* sal por campo: 16 bytes aleatorios (``secrets.token_bytes``), en hex (32 caracteres)
* hoja del campo ``n`` con valor ``v`` y sal ``s``:
  ``sha256( bytes.fromhex(s) || n.encode("utf-8") || valor_canonico(v) )`` en hex
* las hojas se ordenan por nombre de campo (orden de cadenas Python) y el árbol es
  el de ``blockchain/core/merkle.py`` (nodo = sha256(hex_izq + hex_der), se duplica
  el último nodo si el nivel es impar; sin separación de dominio, ver ese módulo)
* ``fields_root`` = raíz de ese árbol (hex de 64 caracteres)

La aleatoriedad de las sales se usa solo al emitir (lado API/cliente, antes de firmar);
la validación del contrato solo comprueba el formato de ``fields_root``.
"""
import hashlib
import json
import re
import secrets
from typing import Dict, List, Tuple

from blockchain.core import merkle

# Campos públicos: viajan en claro en la TX. Todo lo demás de ``credential_data`` es privado.
PUBLIC_FIELDS = frozenset({"program", "degree", "issue_date", "credential_type", "expiry_date"})
# Claves personales que NUNCA pueden aparecer en el payload en cadena.
FORBIDDEN_ONCHAIN = frozenset({"student_name", "grade", "metadata"})
SALT_BYTES = 16
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def is_hex64(valor) -> bool:
    return isinstance(valor, str) and bool(_HEX64.match(valor))


def canonical_value(valor) -> bytes:
    return json.dumps(valor, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def field_leaf(name: str, value, salt_hex: str) -> str:
    """Hoja = sha256(sal || nombre || json canónico del valor), en hex."""
    return hashlib.sha256(bytes.fromhex(salt_hex) + name.encode("utf-8")
                          + canonical_value(value)).hexdigest()


def split_credential_data(credential_data: dict) -> Tuple[dict, dict]:
    """Separa (públicos, privados) según ``PUBLIC_FIELDS``."""
    publicos = {k: v for k, v in credential_data.items() if k in PUBLIC_FIELDS}
    privados = {k: v for k, v in credential_data.items()
                if k not in PUBLIC_FIELDS and k != "fields_root"}
    return publicos, privados


def _sorted_leaves(fields: Dict[str, object], salts: Dict[str, str]) -> Tuple[List[str], List[str]]:
    nombres = sorted(fields)
    return nombres, [field_leaf(n, fields[n], salts[n]) for n in nombres]


def build_private_record(fields: Dict[str, object]) -> dict:
    """Genera sales y raíz. Devuelve el registro privado {fields, salts, fields_root}."""
    if not fields:
        raise ValueError("No hay campos privados que comprometer")
    salts = {n: secrets.token_bytes(SALT_BYTES).hex() for n in fields}
    _, hojas = _sorted_leaves(fields, salts)
    return {"fields": dict(fields), "salts": salts,
            "fields_root": merkle.merkle_root_from_leaves(hojas)}


def record_root(record: dict) -> str:
    """Recalcula la raíz de un registro privado (para comprobarlo)."""
    _, hojas = _sorted_leaves(record["fields"], record["salts"])
    return merkle.merkle_root_from_leaves(hojas)


def build_disclosure(record: dict, names: List[str]) -> dict:
    """Paquete de divulgación selectiva: campo, valor, sal y prueba Merkle por cada nombre."""
    nombres, hojas = _sorted_leaves(record["fields"], record["salts"])
    reveladas = []
    for n in names:
        if n not in record["fields"]:
            raise ValueError(f"Campo inexistente en el registro: {n}")
        reveladas.append({"name": n, "value": record["fields"][n], "salt": record["salts"][n],
                          "proof": merkle.build_proof(hojas, nombres.index(n))})
    return {"fields_root": record_root(record), "revealed": reveladas}


def verify_field(root: str, item: dict) -> bool:
    """True si el campo revelado (name, value, salt, proof) pertenece a ``root``."""
    try:
        hoja = field_leaf(item["name"], item["value"], item["salt"])
        return merkle.verify_proof(hoja, item["proof"], root)
    except (KeyError, TypeError, ValueError, AttributeError):
        return False
