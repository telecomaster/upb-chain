"""
Contrato inteligente de credenciales académicas para UPB-Chain.
Gestiona emisión, verificación y revocación de títulos, certificados y notas.

Su estado es la reproducción de las TXs confirmadas en la cadena (P0-6,
ver ``blockchain/core/state.py``).
"""
import hashlib
import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, List, Optional

from blockchain.core.block import GENESIS_AUTHORITY_ADDRESS
from blockchain.core.state import ReplayState
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
    student_name: str
    program: str
    degree: str
    issue_date: str
    expiry_date: Optional[str]
    grade: Optional[float]
    metadata: dict = field(default_factory=dict)
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
            "student_name": self.student_name,
            "program": self.program,
            "degree": self.degree,
            "issue_date": self.issue_date,
            "expiry_date": self.expiry_date,
            "grade": self.grade,
            "metadata": self.metadata,
            "status": self.status,
            "revocation_reason": self.revocation_reason,
            "tx_hash": self.tx_hash,
            "block_number": self.block_number,
            "revocation_tx": self.revocation_tx,
            "revocation_block": self.revocation_block,
        }

    def generate_qr_data(self) -> str:
        """Datos para código QR de verificación."""
        return json.dumps({
            "id": self.credential_id,
            "student": self.student_name,
            "degree": self.degree,
            "institution": self.institution,
            "date": self.issue_date,
            "verify_url": f"upbchain://verify/{self.credential_id}",
        })

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


def _type_of(tx: dict) -> str:
    """Tipo de una TX en dict como str (puede venir como TransactionType o como texto)."""
    tx_type = tx.get("type")
    return getattr(tx_type, "value", tx_type)


def _status(status: str, verdict: str, valid: bool, reason: str, **extra) -> dict:
    out = {"valid": valid, "status": status, "verdict": verdict, "reason": reason,
           "credential": None, "block_index": None, "confirmations": 0}
    out.update(extra)
    return out


class CredentialContract(ReplayState):
    """
    Contrato de credenciales cuyo estado se DERIVA de la cadena (P0-6).

    El estado (emisores, credenciales, revocaciones) es la reproducción en orden
    de las TXs confirmadas de tres tipos:

        ISSUER_REGISTER    sender = autoridad del génesis; payload
                           {issuer_address, institution_code}
        CREDENTIAL_ISSUE   sender = emisor registrado; recipient = estudiante;
                           payload = datos de la credencial
        CREDENTIAL_REVOKE  sender = emisor original o autoridad; payload
                           {credential_id, reason}

    La API no llama a ``register_issuer``/``issue_credential``/``revoke_credential``:
    construye una TX firmada y la pone en el mempool. Esas funciones son las
    transiciones de estado que ``apply_tx`` ejecuta al reproducir un bloque
    (y siguen disponibles para tests unitarios del contrato aislado).

    ``authority_address`` es por defecto la dirección fijada en el génesis; los
    tests pasan la de una wallet propia para poder firmar como autoridad.
    """

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

    REQUIRED_FIELDS = {"student_name", "program", "degree", "issue_date", "credential_type"}

    def __init__(self, contract_address: str = "CREDENTIAL_CONTRACT",
                 authority_address: Optional[str] = None):
        self.address = contract_address
        self.authority_address = authority_address or GENESIS_AUTHORITY_ADDRESS
        super().__init__()

    def reset(self) -> None:
        self._credentials: Dict[str, AcademicCredential] = {}
        self._issuer_registry: Dict[str, str] = {}  # address → institution_code
        self._student_index: Dict[str, List[str]] = {}  # student_address → [cred_ids]

    # ── Reglas de validez (puras: no mutan el estado) ─────────────────────────

    def validate_tx(self, tx: dict) -> tuple[bool, str]:
        tx_type = _type_of(tx)
        sender = tx.get("sender", "")
        payload = tx.get("payload") or {}
        if tx_type == TransactionType.ISSUER_REGISTER.value:
            if sender != self.authority_address:
                return False, "Solo la autoridad del génesis puede registrar emisores"
            return self._check_register(payload.get("issuer_address"),
                                        payload.get("institution_code"))
        if tx_type == TransactionType.CREDENTIAL_ISSUE.value:
            return self._check_issue(sender, tx.get("recipient", ""), payload)
        if tx_type == TransactionType.CREDENTIAL_REVOKE.value:
            return self._check_revoke(sender, payload.get("credential_id"))
        return False, f"Tipo no soportado por el contrato: {tx_type}"

    def _check_register(self, issuer_address, institution_code) -> tuple[bool, str]:
        if not issuer_address or not isinstance(issuer_address, str):
            return False, "Falta issuer_address"
        if institution_code not in self.AUTHORIZED_INSTITUTIONS:
            return False, f"Institución no autorizada: {institution_code}"
        if issuer_address in self._issuer_registry:
            return False, "Emisor ya registrado"
        return True, "OK"

    def _check_issue(self, issuer_address: str, student_address: str,
                     data: dict) -> tuple[bool, str]:
        if issuer_address not in self._issuer_registry:
            return False, "Emisor no registrado"
        if not student_address:
            return False, "Falta la dirección del estudiante"
        missing = self.REQUIRED_FIELDS - set(data.keys())
        if missing:
            return False, f"Campos faltantes: {missing}"
        try:
            CredentialType(data["credential_type"])
        except ValueError:
            return False, f"Tipo de credencial inválido: {data['credential_type']}"
        credential_id = self._generate_id(issuer_address, student_address, data)
        if credential_id in self._credentials:
            return False, "Credencial ya existe"
        return True, "OK"

    def _check_revoke(self, revoker_address: str, credential_id) -> tuple[bool, str]:
        credential = self._credentials.get(credential_id)
        if not credential:
            return False, "Credencial no encontrada"
        if revoker_address not in (credential.issuer_address, self.authority_address):
            return False, "Solo el emisor original o la autoridad pueden revocar"
        if credential.status == CredentialStatus.REVOKED:
            return False, "Ya revocada"
        return True, "OK"

    # ── Transiciones de estado ────────────────────────────────────────────────

    def _apply_valid_tx(self, tx: dict, block_index: Optional[int],
                        block_timestamp: Optional[float]) -> None:
        tx_type = _type_of(tx)
        payload = tx.get("payload") or {}
        tx_id = tx.get("tx_id", "")
        index = block_index or 0
        if tx_type == TransactionType.ISSUER_REGISTER.value:
            self.register_issuer(payload["issuer_address"], payload["institution_code"])
        elif tx_type == TransactionType.CREDENTIAL_ISSUE.value:
            self.issue_credential(tx["sender"], tx["recipient"], payload,
                                  tx_hash=tx_id, block_number=index)
        elif tx_type == TransactionType.CREDENTIAL_REVOKE.value:
            self.revoke_credential(tx["sender"], payload["credential_id"],
                                   payload.get("reason", ""), tx_hash=tx_id,
                                   block_number=index)

    def register_issuer(self, issuer_address: str, institution_code: str) -> tuple[bool, str]:
        ok, reason = self._check_register(issuer_address, institution_code)
        if not ok:
            return False, reason
        self._issuer_registry[issuer_address] = institution_code
        logger.debug(f"Emisor registrado: {issuer_address} → {institution_code}")
        return True, "OK"

    def issue_credential(
        self,
        issuer_address: str,
        student_address: str,
        data: dict,
        tx_hash: str = "",
        block_number: int = 0,
    ) -> tuple[bool, str, Optional[AcademicCredential]]:
        ok, reason = self._check_issue(issuer_address, student_address, data)
        if not ok:
            return False, reason, None

        institution_code = self._issuer_registry[issuer_address]
        credential_id = self._generate_id(issuer_address, student_address, data)
        credential = AcademicCredential(
            credential_id=credential_id,
            credential_type=CredentialType(data["credential_type"]),
            institution=self.AUTHORIZED_INSTITUTIONS[institution_code],
            issuer_address=issuer_address,
            student_address=student_address,
            student_name=data["student_name"],
            program=data["program"],
            degree=data["degree"],
            issue_date=data["issue_date"],
            expiry_date=data.get("expiry_date"),
            grade=data.get("grade"),
            metadata=data.get("metadata", {}),
            tx_hash=tx_hash,
            block_number=block_number,
        )

        self._credentials[credential_id] = credential
        self._student_index.setdefault(student_address, []).append(credential_id)

        logger.debug(f"Credencial emitida: {credential_id} para {student_address}")
        return True, "OK", credential

    def revoke_credential(
        self,
        issuer_address: str,
        credential_id: str,
        reason: str,
        tx_hash: str = "",
        block_number: int = 0,
    ) -> tuple[bool, str]:
        ok, why = self._check_revoke(issuer_address, credential_id)
        if not ok:
            return False, why
        credential = self._credentials[credential_id]
        credential.status = CredentialStatus.REVOKED
        credential.revocation_reason = reason
        credential.revocation_tx = tx_hash
        credential.revocation_block = block_number
        logger.debug(f"Credencial revocada: {credential_id} — {reason}")
        return True, "OK"

    # ── Verificación ─────────────────────────────────────────────────────────

    def verify_credential(self, credential_id: str) -> tuple[bool, str, Optional[dict]]:
        credential = self._credentials.get(credential_id)
        if not credential:
            return False, "Credencial no encontrada", None
        if not credential.is_valid:
            return False, f"Credencial inválida: estado={credential.status}", None
        return True, "Credencial válida y activa", credential.to_dict()

    def credential_status(self, credential_id: str, pending: Iterable[dict] = ()) -> dict:
        """Estado de una credencial para un verificador (empleador).

        ``pending`` son las TXs del mempool (dicts). Estados posibles:
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
                if self.credential_id_of_tx(tx) == credential_id:
                    return _status("PENDING", "PENDIENTE", False,
                                   "Emitida, pendiente de minado (en el mempool)",
                                   tx_id=tx.get("tx_id"))
            return _status("NOT_FOUND", "NO ENCONTRADA", False, "Credencial no encontrada")

        common = {
            "credential": credential.to_dict(),
            "block_index": credential.block_number,
            "confirmations": max(self.height - credential.block_number + 1, 0),
            "tx_id": credential.tx_hash,
        }
        if credential.status == CredentialStatus.REVOKED:
            return _status("REVOKED", "REVOCADA", False,
                           f"Revocada: {credential.revocation_reason}", **common)
        if not credential.is_valid:
            return _status("EXPIRED", "EXPIRADA", False, "Credencial expirada", **common)
        revoke_pending = any(
            _type_of(tx) == TransactionType.CREDENTIAL_REVOKE.value
            and (tx.get("payload") or {}).get("credential_id") == credential_id
            for tx in pending
        )
        return _status("CONFIRMED", "VÁLIDA", True, "Credencial válida y activa",
                       pending_revocation=revoke_pending, **common)

    def credential_id_of_tx(self, tx: dict) -> Optional[str]:
        """ID de la credencial que crearía una TX CREDENTIAL_ISSUE (None si no lo es)."""
        payload = tx.get("payload") or {}
        if _type_of(tx) != TransactionType.CREDENTIAL_ISSUE.value:
            return None
        if "degree" not in payload or "issue_date" not in payload:
            return None
        return self._generate_id(tx.get("sender", ""), tx.get("recipient", ""), payload)

    def credential_summary(self, credential_id: str, pending: Iterable[dict] = ()) -> dict:
        """Resumen público de una credencial (sin nota, nombre ni metadatos).

        Deriva de ``credential_status``: estado, bloque, confirmaciones y, si
        fue revocada, bloque y TX de revocación.
        """
        st = self.credential_status(credential_id, pending=pending)
        cred = st.get("credential") or {}
        return {
            "credential_id": credential_id,
            "status": st["status"], "verdict": st["verdict"], "valid": st["valid"],
            "issuer_address": cred.get("issuer_address"),
            "student_address": cred.get("student_address"),
            "credential_type": cred.get("credential_type"),
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
            cid = self.credential_id_of_tx(tx)
            if cid and tx.get("sender") == issuer_address and cid not in ids:
                ids.append(cid)
        return ids

    def is_registered_issuer(self, address: str) -> bool:
        return address in self._issuer_registry

    def get_student_credentials(self, student_address: str) -> List[dict]:
        ids = self._student_index.get(student_address, [])
        return [self._credentials[i].to_dict() for i in ids if i in self._credentials]

    # ── Utilidades ────────────────────────────────────────────────────────────

    @staticmethod
    def _generate_id(issuer: str, student: str, data: dict) -> str:
        content = f"{issuer}{student}{data['degree']}{data['issue_date']}"
        return hashlib.sha256(content.encode()).hexdigest()[:32]

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

    def get_stats_by_program(self, program: str) -> dict:
        """Retorna estadísticas de credenciales para un programa académico específico.

        Incluye conteos por estado y estadísticas de notas (si las credenciales
        tienen el campo `grade` completo).

        Args:
            program: Nombre exacto del programa (ej. "Ingeniería en IA").

        Returns:
            Dict con total, active, revoked, avg_grade, min_grade, max_grade.
        """
        program_creds = [
            c for c in self._credentials.values() if c.program == program
        ]
        active  = sum(1 for c in program_creds if c.status == CredentialStatus.ACTIVE)
        revoked = sum(1 for c in program_creds if c.status == CredentialStatus.REVOKED)
        grades  = [c.grade for c in program_creds if c.grade is not None]
        return {
            "program": program,
            "total": len(program_creds),
            "active": active,
            "revoked": revoked,
            "avg_grade": round(sum(grades) / len(grades), 2) if grades else None,
            "min_grade": min(grades) if grades else None,
            "max_grade": max(grades) if grades else None,
        }

    def search_credentials(self, query: str) -> List[dict]:
        """Busca credenciales por nombre de estudiante o grado (case-insensitive).

        Realiza búsqueda de subcadena en `student_name` y `degree`.

        Args:
            query: Cadena de búsqueda. Se normaliza a minúsculas internamente.

        Returns:
            Lista de credenciales que contienen la query en nombre o grado.
        """
        if not query:
            return []
        q = query.lower().strip()
        results: List[dict] = []
        for credential in self._credentials.values():
            try:
                if q in credential.student_name.lower() or q in credential.degree.lower():
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
