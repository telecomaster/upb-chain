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
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

    def sign(self, private_key_hex: str) -> None:
        from security.crypto_utils import sign_data
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
        )
        tx.tx_id = data["tx_id"]
        return tx

    def age_seconds(self) -> float:
        """Retorna los segundos transcurridos desde que se creó la transacción."""
        return time.time() - self.timestamp

    def is_valid(self) -> tuple[bool, str]:
        if not self.sender:
            return False, "Sender vacío"
        if not self.recipient:
            return False, "Recipient vacío"
        if not self.payload:
            return False, "Payload vacío"
        if self.timestamp > time.time() + 60:
            return False, "Timestamp en el futuro"
        if self.age_seconds() > 3600:
            return False, "Transacción expirada (antigüedad > 3600 s)"
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
