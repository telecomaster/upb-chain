"""
Modelo de transacción para UPB-Chain.
Soporta múltiples tipos: credenciales académicas, transferencias, votaciones y datos generales.
"""
import hashlib
import json
import time
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Any
import base64


class TransactionType(str, Enum):
    CREDENTIAL_ISSUE    = "CREDENTIAL_ISSUE"
    CREDENTIAL_REVOKE   = "CREDENTIAL_REVOKE"
    CREDENTIAL_VERIFY   = "CREDENTIAL_VERIFY"
    ISSUER_REGISTER     = "ISSUER_REGISTER"     # admin: alta de emisor, firmada por la autoridad (P0-6)
    VOTE                = "VOTE"
    DATA_RECORD         = "DATA_RECORD"
    TOKEN_TRANSFER      = "TOKEN_TRANSFER"
    SMART_CONTRACT      = "SMART_CONTRACT"


@dataclass
class Transaction:
    type: TransactionType
    sender: str
    recipient: str
    payload: dict
    timestamp: float = field(default_factory=time.time)
    signature: str = ""
    tx_id: str = ""
    fee: float = 0.0
    public_key: str = ""

    def __post_init__(self):
        if not self.tx_id:
            self.tx_id = self._compute_id()

    def _compute_id(self) -> str:
        content = json.dumps({
            "type": self.type,
            "sender": self.sender,
            "recipient": self.recipient,
            "payload": self.payload,
            "timestamp": self.timestamp,
            "fee": self.fee,
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

    def sign(self, private_key_hex: str) -> None:
        """Firma la TX: adjunta la llave pública derivada de la privada y firma el payload canónico."""
        from security.crypto_utils import sign_data
        from blockchain.core.wallet import public_key_from_private
        self.public_key = public_key_from_private(private_key_hex)
        message = self._get_signing_message()
        self.signature = sign_data(message, private_key_hex)

    def verify_signature(self, public_key_hex: str) -> bool:
        from security.crypto_utils import verify_signature
        message = self._get_signing_message()
        return verify_signature(message, self.signature, public_key_hex)

    def _get_signing_message(self) -> str:
        return json.dumps({
            "tx_id": self.tx_id,
            "type": self.type,
            "sender": self.sender,
            "recipient": self.recipient,
            "payload": self.payload,
            "timestamp": self.timestamp,
            "fee": self.fee,
            "public_key": self.public_key,
        }, sort_keys=True)

    def to_dict(self) -> dict:
        return {
            "tx_id": self.tx_id,
            "type": self.type,
            "sender": self.sender,
            "recipient": self.recipient,
            "payload": self.payload,
            "timestamp": self.timestamp,
            "signature": self.signature,
            "fee": self.fee,
            "public_key": self.public_key,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Transaction":
        tx = cls(
            type=TransactionType(data["type"]),
            sender=data["sender"],
            recipient=data["recipient"],
            payload=data["payload"],
            timestamp=data["timestamp"],
            signature=data.get("signature", ""),
            fee=data.get("fee", 0.0),
            public_key=data.get("public_key", ""),
        )
        tx.tx_id = data["tx_id"]
        return tx

    def age_seconds(self) -> float:
        """Retorna los segundos transcurridos desde que se creó la transacción."""
        return time.time() - self.timestamp

    def is_valid(self) -> tuple[bool, str]:
        """ADMISIÓN AL MEMPOOL: validez de consenso + frescura (no futura, no expirada).

        La expiración de 1 h es política local del mempool; NO es regla de consenso
        (si lo fuera, resincronizar bloques viejos fallaría). Ver is_consensus_valid().
        """
        if self.timestamp > time.time() + 60:
            return False, "Timestamp en el futuro"
        if self.age_seconds() > 3600:
            return False, "Transacción expirada (antigüedad > 3600 s)"
        return self.is_consensus_valid()

    def is_consensus_valid(self) -> tuple[bool, str]:
        """VALIDEZ DE CONSENSO (TX dentro de un bloque): sin dependencia del reloj.

        Campos obligatorios + autenticación (firma, llave, sender, tx_id).
        """
        if not self.sender:
            return False, "Sender vacío"
        if not self.recipient:
            return False, "Recipient vacío"
        if not self.payload:
            return False, "Payload vacío"
        return self._check_authentication()

    def _check_authentication(self) -> tuple[bool, str]:
        """Autenticación: firma presente, sender == dirección de la llave y firma ECDSA válida.

        No hay excepción para remitentes "SYSTEM": ninguna TX sin firma entra por
        el mempool/API. Las recompensas de minado (hoy inexistentes) deberán ir
        como campo del bloque, no como Transaction.
        """
        from blockchain.core.wallet import derive_address
        if not self.signature:
            return False, "Transacción sin firma"
        if not self.public_key:
            return False, "Transacción sin llave pública"
        try:
            if derive_address(self.public_key) != self.sender:
                return False, "El sender no corresponde a la llave pública"
        except ValueError:
            return False, "Llave pública malformada"
        if self.tx_id != self._compute_id():
            return False, "tx_id no coincide con el contenido"
        try:
            if not self.verify_signature(self.public_key):
                return False, "Firma inválida"
        except Exception:
            return False, "Firma inválida"
        return True, "OK"


# ── Constructores de alto nivel ───────────────────────────────────────────────

def create_credential_transaction(
    issuer_address: str,
    student_address: str,
    credential_data: dict,
    private_key_hex: str,
) -> Transaction:
    required = {"student_name", "degree", "issue_date"}
    missing = required - set(credential_data.keys())
    if missing:
        raise ValueError(f"Campos faltantes en credential_data: {missing}")

    tx = Transaction(
        type=TransactionType.CREDENTIAL_ISSUE,
        sender=issuer_address,
        recipient=student_address,
        payload={
            **credential_data,
            "credential_hash": hashlib.sha256(
                json.dumps(credential_data, sort_keys=True).encode()
            ).hexdigest(),
        },
    )
    tx.sign(private_key_hex)
    return tx


def create_revoke_transaction(
    revoker_address: str,
    credential_id: str,
    reason: str,
    private_key_hex: str,
) -> Transaction:
    """TX CREDENTIAL_REVOKE firmada (P0-6): solo vale si la firma el emisor o la autoridad."""
    tx = Transaction(
        type=TransactionType.CREDENTIAL_REVOKE,
        sender=revoker_address,
        recipient="CREDENTIAL_CONTRACT",
        payload={"credential_id": credential_id, "reason": reason},
    )
    tx.sign(private_key_hex)
    return tx


def create_issuer_register_transaction(
    authority_address: str,
    issuer_address: str,
    institution_code: str,
    private_key_hex: str,
) -> Transaction:
    """TX de administración ISSUER_REGISTER (P0-6), firmada por la autoridad del génesis."""
    tx = Transaction(
        type=TransactionType.ISSUER_REGISTER,
        sender=authority_address,
        recipient=issuer_address,
        payload={"issuer_address": issuer_address, "institution_code": institution_code},
    )
    tx.sign(private_key_hex)
    return tx


def create_data_record_transaction(
    sender: str,
    recipient: str,
    data_dict: dict,
    private_key_hex: str,
) -> Transaction:
    """Crea una transacción de tipo DATA_RECORD con hash de integridad del payload.

    Análoga a create_credential_transaction pero para registros de datos genéricos.
    No impone campos obligatorios en data_dict — la validación semántica queda a
    cargo del contrato o aplicación que llame esta función.

    Args:
        sender:          Dirección del remitente.
        recipient:       Dirección del destinatario (puede ser un contrato).
        data_dict:       Datos arbitrarios a registrar en la blockchain.
        private_key_hex: Llave privada del remitente (hex) para firmar.

    Returns:
        Transaction firmada de tipo DATA_RECORD.
    """
    tx = Transaction(
        type=TransactionType.DATA_RECORD,
        sender=sender,
        recipient=recipient,
        payload={
            **data_dict,
            "data_hash": hashlib.sha256(
                json.dumps(data_dict, sort_keys=True).encode()
            ).hexdigest(),
        },
    )
    tx.sign(private_key_hex)
    return tx


def create_vote_transaction(
    voter_address: str,
    proposal_id: str,
    vote: bool,
    private_key_hex: str,
) -> Transaction:
    tx = Transaction(
        type=TransactionType.VOTE,
        sender=voter_address,
        recipient="VOTING_CONTRACT",
        payload={"proposal_id": proposal_id, "vote": vote},
    )
    tx.sign(private_key_hex)
    return tx
