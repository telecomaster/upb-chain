"""
Modelo de transacción para UPB-Chain.
Soporta múltiples tipos: credenciales académicas, transferencias, votaciones y datos generales.
"""
import hashlib
import json
import math
import time
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Any
import base64

from blockchain.core.limits import check_tx_size


class TransactionType(str, Enum):
    CREDENTIAL_ISSUE    = "CREDENTIAL_ISSUE"
    CREDENTIAL_REVOKE   = "CREDENTIAL_REVOKE"
    ISSUER_REGISTER     = "ISSUER_REGISTER"     # admin: alta de emisor, firmada por la autoridad (P0-6)
    VOTE                = "VOTE"
    DATA_RECORD         = "DATA_RECORD"
    TOKEN_TRANSFER      = "TOKEN_TRANSFER"      # payload {"amount": int}; mueve saldo (P0-9)
    TOKEN_MINT          = "TOKEN_MINT"          # emisión: autoridad (P0-9) o emisor con presupuesto (P1-12)
    TOKEN_REDEEM        = "TOKEN_REDEEM"        # canje: quema saldo en una dirección de canje (P1-12)
    ISSUER_BUDGET       = "ISSUER_BUDGET"       # admin: presupuesto semestral de un emisor (P1-12)
    REDEEM_ADDRESS_REGISTER = "REDEEM_ADDRESS_REGISTER"  # admin: alta de dirección de canje (P1-12)
    BADGE_AWARD         = "BADGE_AWARD"         # insignia intransferible, la otorga un emisor (P1-12)
    CATALOG_ITEM        = "CATALOG_ITEM"        # admin: ítem canjeable con precio y stock (P2-12)
    AWARD_RULE          = "AWARD_RULE"          # admin: premio automático al emitir una credencial (P2-12)
    EVENT_CODE_CREATE   = "EVENT_CODE_CREATE"   # emisor: código QR de evento, un reclamo por dirección (P1-12)
    EVENT_CODE_CLAIM    = "EVENT_CODE_CLAIM"    # estudiante: reclama puntos con la firma de la llave del evento (P1-12)
    ELECTION_CREATE     = "ELECTION_CREATE"     # configuración de una elección ponderada (P2-12)
    CONTRACT_DEPLOY     = "CONTRACT_DEPLOY"     # despliega bytecode de la VM de pila (P2-11)
    CONTRACT_CALL       = "CONTRACT_CALL"       # llama a un contrato desplegado con gas en PUPB (P2-11)


@dataclass
class Transaction:
    type: TransactionType
    sender: str
    recipient: str
    payload: dict
    timestamp: float = field(default_factory=time.time)
    signature: str = ""
    tx_id: str = ""
    fee: int = 0            # en unidad mínima (entero, P0-9); se quema al confirmarse
    public_key: str = ""
    nonce: int = 0          # n.º de TX del sender: debe ser nonce_confirmado + 1 (P0-9)

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
            "nonce": self.nonce,
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
            "nonce": self.nonce,
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
            "nonce": self.nonce,
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
            fee=data.get("fee", 0),
            public_key=data.get("public_key", ""),
            nonce=data.get("nonce", 0),
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
        if type(self.timestamp) not in (int, float) or not math.isfinite(self.timestamp):
            return False, "timestamp debe ser un número finito"
        if not isinstance(self.sender, str) or not isinstance(self.recipient, str):
            return False, "sender y recipient deben ser texto"
        if not isinstance(self.payload, dict):
            return False, "payload debe ser un objeto"
        if not self.sender:
            return False, "Sender vacío"
        if not self.recipient:
            return False, "Recipient vacío"
        if not self.payload:
            return False, "Payload vacío"
        # Montos enteros (P0-9): bool es subclase de int en Python, se excluye.
        if not _is_int(self.fee) or self.fee < 0:
            return False, "fee debe ser un entero >= 0 (unidad mínima)"
        if not _is_int(self.nonce) or self.nonce < 0:
            return False, "nonce debe ser un entero >= 0"
        # Tope de tamaño (P0-3, consenso): antes de la firma, que es lo caro.
        ok, reason = check_tx_size(self.to_dict())
        if not ok:
            return False, reason
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


def _is_int(value) -> bool:
    """Entero de verdad: ``True``/``1.0`` no cuentan (consenso sin floats, P0-9)."""
    return isinstance(value, int) and not isinstance(value, bool)


# ── Constructores de alto nivel ───────────────────────────────────────────────
# Todos reciben ``nonce`` (P0-9): el siguiente nonce del firmante. La API lo
# obtiene con ``Blockchain.next_nonce(address)`` (confirmadas + mempool).

def create_credential_transaction_with_record(
    issuer_address: str,
    student_address: str,
    credential_data: dict,
    private_key_hex: str,
    nonce: int = 0,
):
    """TX CREDENTIAL_ISSUE con datos personales fuera de la cadena (P1-2).

    ``credential_data`` trae campos públicos (``commitment.PUBLIC_FIELDS``) y privados
    (nombre, nota, metadatos...). En la TX solo van los públicos y ``fields_root``.
    Devuelve ``(tx, registro_privado)``; el registro (campos + sales) no se guarda aquí.
    """
    from blockchain.core.commitment import build_private_record, split_credential_data
    publicos, privados = split_credential_data(credential_data)
    missing = {"degree", "issue_date"} - set(publicos.keys())
    if "student_name" not in privados:
        missing.add("student_name")
    if missing:
        raise ValueError(f"Campos faltantes en credential_data: {missing}")
    registro = build_private_record(privados)
    tx = Transaction(
        type=TransactionType.CREDENTIAL_ISSUE,
        sender=issuer_address,
        recipient=student_address,
        payload={**publicos, "fields_root": registro["fields_root"]},
        nonce=nonce,
    )
    tx.sign(private_key_hex)
    return tx, registro


def create_credential_transaction(
    issuer_address: str,
    student_address: str,
    credential_data: dict,
    private_key_hex: str,
    nonce: int = 0,
) -> Transaction:
    """Como ``create_credential_transaction_with_record`` pero descarta el registro privado."""
    tx, _ = create_credential_transaction_with_record(
        issuer_address, student_address, credential_data, private_key_hex, nonce)
    return tx


def create_revoke_transaction(
    revoker_address: str,
    credential_id: str,
    reason: str,
    private_key_hex: str,
    nonce: int = 0,
) -> Transaction:
    """TX CREDENTIAL_REVOKE firmada (P0-6): solo vale si la firma el emisor o la autoridad."""
    tx = Transaction(
        type=TransactionType.CREDENTIAL_REVOKE,
        sender=revoker_address,
        recipient="CREDENTIAL_CONTRACT",
        payload={"credential_id": credential_id, "reason": reason},
        nonce=nonce,
    )
    tx.sign(private_key_hex)
    return tx


def create_issuer_register_transaction(
    authority_address: str,
    issuer_address: str,
    institution_code: str,
    private_key_hex: str,
    nonce: int = 0,
) -> Transaction:
    """TX de administración ISSUER_REGISTER (P0-6), firmada por la autoridad del génesis."""
    tx = Transaction(
        type=TransactionType.ISSUER_REGISTER,
        sender=authority_address,
        recipient=issuer_address,
        payload={"issuer_address": issuer_address, "institution_code": institution_code},
        nonce=nonce,
    )
    tx.sign(private_key_hex)
    return tx


def create_data_record_transaction(
    sender: str,
    recipient: str,
    data_dict: dict,
    private_key_hex: str,
    nonce: int = 0,
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
        nonce=nonce,
    )
    tx.sign(private_key_hex)
    return tx


def create_vote_transaction(
    voter_address: str,
    election_id: str,
    choice: str,
    private_key_hex: str,
    nonce: int = 0,
) -> Transaction:
    """TX VOTE (P1-13): un voto por dirección y elección (ver ``VotingContract``)."""
    tx = Transaction(
        type=TransactionType.VOTE,
        sender=voter_address,
        recipient="VOTING_CONTRACT",
        payload={"election_id": election_id, "choice": choice},
        nonce=nonce,
    )
    tx.sign(private_key_hex)
    return tx


def create_mint_transaction(
    authority_address: str,
    recipient: str,
    amount: int,
    private_key_hex: str,
    nonce: int = 0,
    reason: Optional[str] = None,
) -> Transaction:
    """TX TOKEN_MINT (P0-9, P1-12): crea ``amount`` unidades para ``recipient``.

    La firma la autoridad del génesis (sin límite) o un emisor registrado
    dentro de su presupuesto semestral; el emisor debe dar ``reason`` (ver
    ``TokenContract``). ``authority_address`` es quien firma.
    """
    payload: dict = {"amount": amount}
    if reason is not None:
        payload["reason"] = reason
    tx = Transaction(
        type=TransactionType.TOKEN_MINT,
        sender=authority_address,
        recipient=recipient,
        payload=payload,
        nonce=nonce,
    )
    tx.sign(private_key_hex)
    return tx


def create_transfer_transaction(
    sender: str,
    recipient: str,
    amount: int,
    private_key_hex: str,
    nonce: int = 0,
    fee: int = 0,
) -> Transaction:
    """TX TOKEN_TRANSFER (P0-9): mueve ``amount`` de ``sender`` a ``recipient``.

    Válida si ``amount > 0`` y el saldo del sender cubre ``amount + fee``.
    """
    tx = Transaction(
        type=TransactionType.TOKEN_TRANSFER,
        sender=sender,
        recipient=recipient,
        payload={"amount": amount},
        fee=fee,
        nonce=nonce,
    )
    tx.sign(private_key_hex)
    return tx


# ── Tokens e insignias para estudiantes (P1-12) ──────────────────────────────

def create_issuer_budget_transaction(
    authority_address: str,
    issuer_address: str,
    semester: str,
    amount: int,
    private_key_hex: str,
    nonce: int = 0,
) -> Transaction:
    """TX ISSUER_BUDGET: fija el presupuesto de emisión de un emisor en un semestre."""
    tx = Transaction(
        type=TransactionType.ISSUER_BUDGET,
        sender=authority_address,
        recipient=issuer_address,
        payload={"issuer_address": issuer_address, "semester": semester, "amount": amount},
        nonce=nonce,
    )
    tx.sign(private_key_hex)
    return tx


def create_redeem_address_transaction(
    authority_address: str,
    redeem_address: str,
    label: str,
    private_key_hex: str,
    nonce: int = 0,
) -> Transaction:
    """TX REDEEM_ADDRESS_REGISTER: la autoridad da de alta una dirección de canje."""
    tx = Transaction(
        type=TransactionType.REDEEM_ADDRESS_REGISTER,
        sender=authority_address,
        recipient=redeem_address,
        payload={"redeem_address": redeem_address, "label": label},
        nonce=nonce,
    )
    tx.sign(private_key_hex)
    return tx


def create_redeem_transaction(
    sender: str,
    redeem_address: str,
    amount: int,
    private_key_hex: str,
    nonce: int = 0,
    item: str = "",
    item_id: str = "",
) -> Transaction:
    """TX TOKEN_REDEEM: quema ``amount`` del saldo de ``sender`` en una dirección de canje.

    Con ``item_id`` (P2-12) compra un ítem del catálogo: ``amount`` debe ser su precio.
    """
    payload: dict = {"amount": amount}
    if item:
        payload["item"] = item
    if item_id:
        payload["item_id"] = item_id
    tx = Transaction(
        type=TransactionType.TOKEN_REDEEM,
        sender=sender,
        recipient=redeem_address,
        payload=payload,
        nonce=nonce,
    )
    tx.sign(private_key_hex)
    return tx


def create_catalog_item_transaction(
    authority_address: str,
    item_id: str,
    title: str,
    price: int,
    stock: int,
    redeem_address: str,
    private_key_hex: str,
    nonce: int = 0,
) -> Transaction:
    """TX CATALOG_ITEM (P2-12): la autoridad publica un ítem canjeable en una dirección de canje."""
    tx = Transaction(
        type=TransactionType.CATALOG_ITEM,
        sender=authority_address,
        recipient=redeem_address,
        payload={"item_id": item_id, "title": title, "price": price, "stock": stock,
                 "redeem_address": redeem_address},
        nonce=nonce,
    )
    tx.sign(private_key_hex)
    return tx


def create_award_rule_transaction(
    authority_address: str,
    rule_id: str,
    credential_type: str,
    issuer_address: str,
    amount: int,
    private_key_hex: str,
    nonce: int = 0,
) -> Transaction:
    """TX AWARD_RULE (P2-12): premio automático al emitir una credencial de cierto tipo."""
    tx = Transaction(
        type=TransactionType.AWARD_RULE,
        sender=authority_address,
        recipient=issuer_address,
        payload={"rule_id": rule_id, "credential_type": credential_type,
                 "issuer_address": issuer_address, "amount": amount},
        nonce=nonce,
    )
    tx.sign(private_key_hex)
    return tx


def create_election_transaction(
    creator_address: str,
    election_id: str,
    options: list,
    weight_rule: str,
    start_height: int,
    end_height: int,
    private_key_hex: str,
    nonce: int = 0,
    badge_weights: Optional[dict] = None,
    cap: Optional[int] = None,
    title: Optional[str] = None,
    eligible_credential_type: Optional[str] = None,
    eligible_program: Optional[str] = None,
) -> Transaction:
    """TX ELECTION_CREATE (P2-12; título y elegibilidad por credencial: Idea 8): elección con ventana por altura de bloque y regla de peso."""
    payload: dict = {"election_id": election_id, "options": options, "weight_rule": weight_rule,
                     "start_height": start_height, "end_height": end_height}
    if badge_weights is not None:
        payload["badge_weights"] = badge_weights
    if cap is not None:
        payload["cap"] = cap
    for clave, valor in (("title", title), ("eligible_credential_type", eligible_credential_type),
                         ("eligible_program", eligible_program)):
        if valor is not None:
            payload[clave] = valor
    tx = Transaction(
        type=TransactionType.ELECTION_CREATE,
        sender=creator_address,
        recipient="VOTING_CONTRACT",
        payload=payload,
        nonce=nonce,
    )
    tx.sign(private_key_hex)
    return tx


EVENT_CODE_RECIPIENT = "TOKENS_CONTRACT"   # las TX de códigos de evento no tienen destinatario real


def create_event_code_transaction(
    issuer_address: str,
    code_id: str,
    event_pubkey: str,
    amount: int,
    max_claims: int,
    expires_height: int,
    reason: str,
    private_key_hex: str,
    nonce: int = 0,
) -> Transaction:
    """TX EVENT_CODE_CREATE (P1-12): un emisor registrado publica un código de evento."""
    tx = Transaction(
        type=TransactionType.EVENT_CODE_CREATE,
        sender=issuer_address,
        recipient=EVENT_CODE_RECIPIENT,
        payload={"code_id": code_id, "event_pubkey": event_pubkey, "amount": amount,
                 "max_claims": max_claims, "expires_height": expires_height, "reason": reason},
        nonce=nonce,
    )
    tx.sign(private_key_hex)
    return tx


def create_event_claim_transaction(
    student_address: str,
    code_id: str,
    claim_sig: str,
    private_key_hex: str,
    nonce: int = 0,
) -> Transaction:
    """TX EVENT_CODE_CLAIM (P1-12): el estudiante reclama; ``claim_sig`` la firma la llave del evento."""
    tx = Transaction(
        type=TransactionType.EVENT_CODE_CLAIM,
        sender=student_address,
        recipient=EVENT_CODE_RECIPIENT,
        payload={"code_id": code_id, "claim_sig": claim_sig},
        nonce=nonce,
    )
    tx.sign(private_key_hex)
    return tx


def create_badge_award_transaction(
    issuer_address: str,
    student_address: str,
    badge_id: str,
    name: str,
    reason: str,
    private_key_hex: str,
    nonce: int = 0,
) -> Transaction:
    """TX BADGE_AWARD: un emisor registrado otorga la insignia ``badge_id`` a un estudiante."""
    tx = Transaction(
        type=TransactionType.BADGE_AWARD,
        sender=issuer_address,
        recipient=student_address,
        payload={"badge_id": badge_id, "name": name, "reason": reason},
        nonce=nonce,
    )
    tx.sign(private_key_hex)
    return tx
