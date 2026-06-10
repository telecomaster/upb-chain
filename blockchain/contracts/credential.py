"""
Contrato inteligente de credenciales académicas para UPB-Chain.
Gestiona emisión, verificación y revocación de títulos, certificados y notas.
"""
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

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


class CredentialContract:
    """
    Contrato que mantiene el registro de credenciales en memoria;
    la persistencia real está en la blockchain.
    """

    AUTHORIZED_INSTITUTIONS = {
        "UPB": "Universidad Privada Boliviana",
        "UMSS": "Universidad Mayor de San Simón",
        "UMSA": "Universidad Mayor de San Andrés",
    }

    def __init__(self, contract_address: str = "CREDENTIAL_CONTRACT"):
        self.address = contract_address
        self._credentials: Dict[str, AcademicCredential] = {}
        self._issuer_registry: Dict[str, str] = {}  # address → institution_code
        self._student_index: Dict[str, List[str]] = {}  # student_address → [cred_ids]

    # ── Registro de emisores ──────────────────────────────────────────────────

    def register_issuer(self, issuer_address: str, institution_code: str) -> tuple[bool, str]:
        if institution_code not in self.AUTHORIZED_INSTITUTIONS:
            return False, f"Institución no autorizada: {institution_code}"
        self._issuer_registry[issuer_address] = institution_code
        logger.info(f"Emisor registrado: {issuer_address} → {institution_code}")
        return True, "OK"

    # ── Emisión ───────────────────────────────────────────────────────────────

    def issue_credential(
        self,
        issuer_address: str,
        student_address: str,
        data: dict,
    ) -> tuple[bool, str, Optional[AcademicCredential]]:
        if issuer_address not in self._issuer_registry:
            return False, "Emisor no registrado", None

        required = {"student_name", "program", "degree", "issue_date", "credential_type"}
        missing = required - set(data.keys())
        if missing:
            return False, f"Campos faltantes: {missing}", None

        institution_code = self._issuer_registry[issuer_address]
        credential_id = self._generate_id(issuer_address, student_address, data)

        if credential_id in self._credentials:
            return False, "Credencial ya existe", None

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
        )

        self._credentials[credential_id] = credential
        self._student_index.setdefault(student_address, []).append(credential_id)

        logger.info(f"Credencial emitida: {credential_id} para {student_address}")
        return True, "OK", credential

    # ── Verificación ─────────────────────────────────────────────────────────

    def verify_credential(self, credential_id: str) -> tuple[bool, str, Optional[dict]]:
        credential = self._credentials.get(credential_id)
        if not credential:
            return False, "Credencial no encontrada", None
        if not credential.is_valid:
            return False, f"Credencial inválida: estado={credential.status}", None
        return True, "Credencial válida y activa", credential.to_dict()

    def get_student_credentials(self, student_address: str) -> List[dict]:
        ids = self._student_index.get(student_address, [])
        return [self._credentials[i].to_dict() for i in ids if i in self._credentials]

    # ── Revocación ────────────────────────────────────────────────────────────

    def revoke_credential(
        self,
        issuer_address: str,
        credential_id: str,
        reason: str,
    ) -> tuple[bool, str]:
        credential = self._credentials.get(credential_id)
        if not credential:
            return False, "Credencial no encontrada"
        if credential.issuer_address != issuer_address:
            return False, "Solo el emisor puede revocar"
        if credential.status == CredentialStatus.REVOKED:
            return False, "Ya revocada"

        credential.status = CredentialStatus.REVOKED
        credential.revocation_reason = reason
        logger.warning(f"Credencial revocada: {credential_id} — {reason}")
        return True, "OK"

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
