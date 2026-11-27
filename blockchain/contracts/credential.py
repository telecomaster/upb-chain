"""
Contrato inteligente de credenciales académicas para UPB-Chain.
Gestiona emisión, verificación y revocación de títulos, certificados y notas.

Su estado es la reproducción de las TXs confirmadas en la cadena (P0-6).
Desde P1-13 sigue la interfaz única de contratos (``blockchain/contracts/base.py``):
``CredentialContract`` son las reglas y ``CredentialState`` el estado y sus consultas.
"""
import hashlib
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, List, Optional, Tuple

from blockchain.contracts.base import Contract, TxContext, tx_type_of
from blockchain.core.block import GENESIS_AUTHORITY_ADDRESS
from blockchain.core.commitment import FORBIDDEN_ONCHAIN, PUBLIC_FIELDS, is_hex64
from blockchain.core.transaction import TransactionType

logger = logging.getLogger("upb_chain.contracts.credential")


class CredentialType(str, Enum):
    DEGREE          = "DEGREE"           # Título de grado
    POSTGRADE       = "POSTGRADE"        # Posgrado / maestría
    CERTIFICATION   = "CERTIFICATION"    # Certificación de curso
    TRANSCRIPT      = "TRANSCRIPT"       # Historial académico
    AWARD           = "AWARD"            # Reconocimiento / premio


class CredentialStatus(str, Enum):
    ACTIVE  = "ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


@dataclass
class AcademicCredential:
    credential_id: str
    credential_type: CredentialType
    institution: str
    issuer_address: str
    student_address: str
    program: str
    degree: str
    issue_date: str
    expiry_date: Optional[str]
    fields_root: str = ""   # compromiso Merkle de los datos personales (P1-2)
    status: CredentialStatus = CredentialStatus.ACTIVE
    revocation_reason: Optional[str] = None
    tx_hash: str = ""
    block_number: int = 0
    revocation_tx: str = ""
    revocation_block: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "credential_id": self.credential_id,
            "credential_type": self.credential_type,
            "institution": self.institution,
            "issuer_address": self.issuer_address,
            "student_address": self.student_address,
            "program": self.program,
            "degree": self.degree,
            "issue_date": self.issue_date,
            "expiry_date": self.expiry_date,
            "fields_root": self.fields_root,
            "status": self.status,
            "revocation_reason": self.revocation_reason,
            "tx_hash": self.tx_hash,
            "block_number": self.block_number,
            "revocation_tx": self.revocation_tx,
            "revocation_block": self.revocation_block,
        }

    @property
    def is_valid(self) -> bool:
        if self.status != CredentialStatus.ACTIVE:
            return False
        if self.expiry_date:
            from datetime import datetime
            try:
                expiry = datetime.fromisoformat(self.expiry_date)
                if expiry < datetime.now():
                    return False
            except ValueError:
                pass
        return True


def generate_credential_id(issuer: str, student: str, data: dict) -> str:
    """ID determinista de una credencial: hash de emisor, estudiante, grado y fecha."""
    content = f"{issuer}{student}{data['degree']}{data['issue_date']}"
    return hashlib.sha256(content.encode()).hexdigest()[:32]


def credential_id_of_tx(tx: dict) -> Optional[str]:
    """ID de la credencial que crearía una TX CREDENTIAL_ISSUE (None si no lo es)."""
    payload = tx.get("payload") or {}
    if tx_type_of(tx) != TransactionType.CREDENTIAL_ISSUE.value:
        return None
    if not isinstance(payload, dict) or "degree" not in payload or "issue_date" not in payload:
        return None
    return generate_credential_id(tx.get("sender", ""), tx.get("recipient", ""), payload)


def _status(status: str, verdict: str, valid: bool, reason: str, **extra) -> dict:
    out = {"valid": valid, "status": status, "verdict": verdict, "reason": reason,
           "credential": None, "block_index": None, "confirmations": 0}
    out.update(extra)
    return out


class CredentialState:
    """Estado del contrato de credenciales: emisores, credenciales e índice por estudiante.

    Solo datos y consultas; las reglas que lo modifican están en ``CredentialContract``.
    Las consultas que dan confirmaciones reciben la altura actual de la cadena.
    """

    def __init__(self) -> None:
        self._credentials: Dict[str, AcademicCredential] = {}
        self._issuer_registry: Dict[str, str] = {}  # address → institution_code
        self._student_index: Dict[str, List[str]] = {}  # student_address → [cred_ids]

    def get(self, credential_id: str) -> Optional[AcademicCredential]:
        return self._credentials.get(credential_id)

    # ── Verificación ─────────────────────────────────────────────────────────

    def verify_credential(self, credential_id: str) -> tuple[bool, str, Optional[dict]]:
        credential = self._credentials.get(credential_id)
        if not credential:
            return False, "Credencial no encontrada", None
        if not credential.is_valid:
            return False, f"Credencial inválida: estado={credential.status}", None
        return True, "Credencial válida y activa", credential.to_dict()

    def credential_status(self, credential_id: str, height: int,
                          pending: Iterable[dict] = ()) -> dict:
        """Estado de una credencial para un verificador (empleador).

        ``height`` es la altura actual de la cadena y ``pending`` las TXs del
        mempool (dicts). Estados posibles:
            PENDING    (PENDIENTE)     emitida pero aún no minada
            CONFIRMED  (VÁLIDA)        en un bloque y activa; con bloque y confirmaciones
            REVOKED    (REVOCADA)      revocada por una TX confirmada
            EXPIRED    (EXPIRADA)      confirmada pero con fecha de expiración vencida
            NOT_FOUND  (NO ENCONTRADA)
        Confirmaciones = altura - bloque + 1 (el bloque que la incluye cuenta 1).
        """
        pending = list(pending)
        credential = self._credentials.get(credential_id)
        if credential is None:
            for tx in pending:
                if credential_id_of_tx(tx) == credential_id:
                    return _status("PENDING", "PENDIENTE", False,
                                   "Emitida, pendiente de minado (en el mempool)",
                                   tx_id=tx.get("tx_id"))
            return _status("NOT_FOUND", "NO ENCONTRADA", False, "Credencial no encontrada")

        common = {
            "credential": credential.to_dict(),
            "block_index": credential.block_number,
            "confirmations": max(height - credential.block_number + 1, 0),
            "tx_id": credential.tx_hash,
        }
        if credential.status == CredentialStatus.REVOKED:
            return _status("REVOKED", "REVOCADA", False,
                           f"Revocada: {credential.revocation_reason}", **common)
        if not credential.is_valid:
            return _status("EXPIRED", "EXPIRADA", False, "Credencial expirada", **common)
        revoke_pending = any(
            tx_type_of(tx) == TransactionType.CREDENTIAL_REVOKE.value
            and (tx.get("payload") or {}).get("credential_id") == credential_id
            for tx in pending
        )
        return _status("CONFIRMED", "VÁLIDA", True, "Credencial válida y activa",
                       pending_revocation=revoke_pending, **common)

    def credential_summary(self, credential_id: str, height: int,
                           pending: Iterable[dict] = ()) -> dict:
        """Resumen público de una credencial (sin datos personales; con la raíz del compromiso).

        Deriva de ``credential_status``: estado, bloque, confirmaciones y, si
        fue revocada, bloque y TX de revocación.
        """
        st = self.credential_status(credential_id, height, pending=pending)
        cred = st.get("credential") or {}
        return {
            "credential_id": credential_id,
            "status": st["status"], "verdict": st["verdict"], "valid": st["valid"],
            "issuer_address": cred.get("issuer_address"),
            "student_address": cred.get("student_address"),
            "credential_type": cred.get("credential_type"),
            "fields_root": cred.get("fields_root"),
            "degree": cred.get("degree"), "issue_date": cred.get("issue_date"),
            "block_index": st["block_index"], "confirmations": st["confirmations"],
            "tx_id": st.get("tx_id"),
            "revocation_block": cred.get("revocation_block"),
            "revocation_tx": cred.get("revocation_tx") or None,
            "revocation_reason": cred.get("revocation_reason"),
            "pending_revocation": st.get("pending_revocation", False),
        }

    def issuer_credential_ids(self, issuer_address: str, pending: Iterable[dict] = ()) -> List[str]:
        """IDs de las credenciales de un emisor: confirmadas y pendientes (mempool)."""
        ids = [i for i, c in self._credentials.items() if c.issuer_address == issuer_address]
        for tx in pending:
            cid = credential_id_of_tx(tx)
            if cid and tx.get("sender") == issuer_address and cid not in ids:
                ids.append(cid)
        return ids

    def issuers(self) -> Dict[str, str]:
        """Copia del registro de emisores: dirección → código de institución."""
        return dict(self._issuer_registry)

    def is_registered_issuer(self, address: str) -> bool:
        return address in self._issuer_registry

    def get_student_credentials(self, student_address: str) -> List[dict]:
        ids = self._student_index.get(student_address, [])
        return [self._credentials[i].to_dict() for i in ids if i in self._credentials]

    def get_stats(self) -> dict:
        active = sum(1 for c in self._credentials.values() if c.status == CredentialStatus.ACTIVE)
        revoked = sum(1 for c in self._credentials.values() if c.status == CredentialStatus.REVOKED)
        return {
            "total_credentials": len(self._credentials),
            "active": active,
            "revoked": revoked,
            "registered_issuers": len(self._issuer_registry),
            "students_with_credentials": len(self._student_index),
        }

    def search_credentials(self, query: str) -> List[dict]:
        """Busca credenciales por título o programa (case-insensitive).

        Desde P1-2 el nombre del estudiante no está en la cadena: solo `degree` y `program`.

        Args:
            query: Cadena de búsqueda. Se normaliza a minúsculas internamente.

        Returns:
            Lista de credenciales que contienen la query en título o programa.
        """
        if not query:
            return []
        q = query.lower().strip()
        results: List[dict] = []
        for credential in self._credentials.values():
            try:
                if q in credential.program.lower() or q in credential.degree.lower():
                    results.append(credential.to_dict())
            except AttributeError:
                continue
        return results

    def get_all_credentials(self, status_filter: Optional[str] = None) -> List[dict]:
        """Retorna todas las credenciales, opcionalmente filtradas por estado.

        Args:
            status_filter: Uno de "ACTIVE", "REVOKED", "EXPIRED" (insensible a
                           mayúsculas). Si es None, retorna todas.

        Returns:
            Lista de dicts. Lista vacía si status_filter no es válido.
        """
        if status_filter is not None:
            try:
                status = CredentialStatus(status_filter.upper())
            except ValueError:
                logger.warning(f"get_all_credentials: estado inválido '{status_filter}'")
                return []
            return [
                c.to_dict()
                for c in self._credentials.values()
                if c.status == status
            ]
        return [c.to_dict() for c in self._credentials.values()]


class CredentialContract(Contract):
    """
    Reglas del contrato de credenciales (P0-6, interfaz P1-13).

    Tipos de TX que maneja:

        ISSUER_REGISTER    sender = autoridad del génesis; payload
                           {issuer_address, institution_code}
        CREDENTIAL_ISSUE   sender = emisor registrado; recipient = estudiante;
                           payload = datos de la credencial
        CREDENTIAL_REVOKE  sender = emisor original o autoridad; payload
                           {credential_id, reason}

    La API no modifica el estado: construye una TX firmada y la pone en el
    mempool; ``apply`` la ejecuta cuando un bloque válido la incluye. Una TX
    inválida (emisor no registrado, credencial duplicada, revocación ajena…)
    invalida el bloque entero, como en todos los contratos (P1-13).

    ``authority_address`` es por defecto la dirección fijada en el génesis; los
    tests pasan la de una wallet propia para poder firmar como autoridad.
    """

    NAME = "credentials"
    HANDLED_TYPES = frozenset({
        TransactionType.ISSUER_REGISTER.value,
        TransactionType.CREDENTIAL_ISSUE.value,
        TransactionType.CREDENTIAL_REVOKE.value,
    })

    AUTHORIZED_INSTITUTIONS = {
        "UPB": "Universidad Privada Boliviana",
        "UMSS": "Universidad Mayor de San Simón",
        "UMSA": "Universidad Mayor de San Andrés",
    }

    # P1-2: el payload lleva solo campos públicos + ``fields_root``. Cambio de consenso:
    # las cadenas con credenciales en formato antiguo (student_name/grade/metadata en claro)
    # ya no validan; hay que borrar data/ y actualizar todos los nodos a la vez.
    REQUIRED_FIELDS = {"program", "degree", "issue_date", "credential_type", "fields_root"}
    ALLOWED_FIELDS = frozenset(PUBLIC_FIELDS | {"fields_root"})

    def __init__(self, authority_address: Optional[str] = None):
        self.authority_address = authority_address or GENESIS_AUTHORITY_ADDRESS

    def initial_state(self) -> CredentialState:
        return CredentialState()

    # ── Fotos de estado (P2-4): CredentialState no es dataclass ──────────────

    def state_to_json(self, state: CredentialState) -> dict:
        creds = {}
        for cid, c in state._credentials.items():
            d = c.to_dict()
            d["credential_type"] = CredentialType(c.credential_type).value
            d["status"] = CredentialStatus(c.status).value
            creds[cid] = d
        return {
            "credentials": creds,
            "issuers": dict(state._issuer_registry),
            "students": {k: list(v) for k, v in state._student_index.items()},
        }

    def state_from_json(self, data: dict) -> CredentialState:
        state = CredentialState()
        for cid, d in data["credentials"].items():
            d = dict(d)
            d["credential_type"] = CredentialType(d["credential_type"])
            d["status"] = CredentialStatus(d["status"])
            state._credentials[cid] = AcademicCredential(**d)
        state._issuer_registry = dict(data["issuers"])
        state._student_index = {k: list(v) for k, v in data["students"].items()}
        return state

    @staticmethod
    def credential_id_of_tx(tx: dict) -> Optional[str]:
        return credential_id_of_tx(tx)

    # ── Reglas de validez (puras: no modifican el estado) ─────────────────────

    def validate(self, state: CredentialState, tx: dict, ctx: TxContext) -> Tuple[bool, str]:
        tx_type = tx_type_of(tx)
        sender = tx.get("sender", "")
        payload = tx.get("payload")
        if not isinstance(payload, dict):
            return False, "payload debe ser un objeto"
        if tx_type == TransactionType.ISSUER_REGISTER.value:
            if sender != self.authority_address:
                return False, "Solo la autoridad del génesis puede registrar emisores"
            return self._check_register(state, payload.get("issuer_address"),
                                        payload.get("institution_code"))
        if tx_type == TransactionType.CREDENTIAL_ISSUE.value:
            return self._check_issue(state, sender, tx.get("recipient", ""), payload)
        if tx_type == TransactionType.CREDENTIAL_REVOKE.value:
            return self._check_revoke(state, sender, payload.get("credential_id"))
        return False, f"Tipo no soportado por el contrato: {tx_type}"

    def _check_register(self, state: CredentialState, issuer_address,
                        institution_code) -> Tuple[bool, str]:
        if not issuer_address or not isinstance(issuer_address, str):
            return False, "Falta issuer_address"
        if (not isinstance(institution_code, str)
                or institution_code not in self.AUTHORIZED_INSTITUTIONS):
            return False, f"Institución no autorizada: {institution_code}"
        if issuer_address in state._issuer_registry:
            return False, "Emisor ya registrado"
        return True, "OK"

    def _check_issue(self, state: CredentialState, issuer_address: str,
                     student_address: str, data: dict) -> Tuple[bool, str]:
        if issuer_address not in state._issuer_registry:
            return False, "Emisor no registrado"
        if not student_address:
            return False, "Falta la dirección del estudiante"
        prohibidos = FORBIDDEN_ONCHAIN & set(data.keys())
        if prohibidos:
            return False, f"Datos personales no permitidos en la cadena: {sorted(prohibidos)}"
        extra = set(data.keys()) - self.ALLOWED_FIELDS
        if extra:
            return False, f"Campos no permitidos en el payload: {sorted(extra)}"
        missing = self.REQUIRED_FIELDS - set(data.keys())
        if missing:
            return False, f"Campos faltantes: {sorted(missing)}"
        if not is_hex64(data["fields_root"]):
            return False, "fields_root debe ser hex de 64 caracteres"
        try:
            CredentialType(data["credential_type"])
        except (ValueError, TypeError):
            return False, f"Tipo de credencial inválido: {data['credential_type']}"
        credential_id = generate_credential_id(issuer_address, student_address, data)
        if credential_id in state._credentials:
            return False, "Credencial ya existe"
        return True, "OK"

    def _check_revoke(self, state: CredentialState, revoker_address: str,
                      credential_id) -> Tuple[bool, str]:
        credential = state._credentials.get(credential_id) if isinstance(credential_id, str) else None
        if not credential:
            return False, "Credencial no encontrada"
        if revoker_address not in (credential.issuer_address, self.authority_address):
            return False, "Solo el emisor original o la autoridad pueden revocar"
        if credential.status == CredentialStatus.REVOKED:
            return False, "Ya revocada"
        return True, "OK"

    # ── Transición de estado (solo tras validate OK) ──────────────────────────

    def apply(self, state: CredentialState, tx: dict, ctx: TxContext) -> CredentialState:
        tx_type = tx_type_of(tx)
        payload = tx["payload"]
        tx_id = tx.get("tx_id", "")
        block_number = ctx.block_index or 0
        if tx_type == TransactionType.ISSUER_REGISTER.value:
            state._issuer_registry[payload["issuer_address"]] = payload["institution_code"]
            logger.debug(f"Emisor registrado: {payload['issuer_address']}")
        elif tx_type == TransactionType.CREDENTIAL_ISSUE.value:
            issuer, student = tx["sender"], tx["recipient"]
            credential_id = generate_credential_id(issuer, student, payload)
            state._credentials[credential_id] = AcademicCredential(
                credential_id=credential_id,
                credential_type=CredentialType(payload["credential_type"]),
                institution=self.AUTHORIZED_INSTITUTIONS[state._issuer_registry[issuer]],
                issuer_address=issuer,
                student_address=student,
                program=payload["program"],
                degree=payload["degree"],
                issue_date=payload["issue_date"],
                expiry_date=payload.get("expiry_date"),
                fields_root=payload["fields_root"],
                tx_hash=tx_id,
                block_number=block_number,
            )
            state._student_index.setdefault(student, []).append(credential_id)
        elif tx_type == TransactionType.CREDENTIAL_REVOKE.value:
            credential = state._credentials[payload["credential_id"]]
            credential.status = CredentialStatus.REVOKED
            credential.revocation_reason = payload.get("reason", "")
            credential.revocation_tx = tx_id
            credential.revocation_block = block_number
        return state
