"""
Contrato de insignias (P1-12): reconocimientos INTRANSFERIBLES para estudiantes.

Reglas:
    - TX ``BADGE_AWARD``: sender = emisor registrado (contrato de credenciales,
      leído con ``ctx.view``); recipient = estudiante (distinto del emisor);
      payload ``{"badge_id": str, "name": str, "reason": str}``
      (badge_id y name de 1 a 64 caracteres; reason de 1 a 140).
    - Cada dirección recibe una misma ``badge_id`` UNA sola vez.
    - Intransferibles por construcción: no existe TX para moverlas ni
      quemarlas; una insignia queda ligada a la dirección que la recibió.
"""
from dataclasses import dataclass, field
from typing import Dict, Tuple

from blockchain.contracts.base import Contract, TxContext
from blockchain.contracts.tokens import MAX_LABEL, MAX_REASON, is_registered_issuer, text_or_none


@dataclass
class BadgeState:
    """estudiante → {badge_id → datos}, en el orden en que se confirmaron."""
    holders: Dict[str, Dict[str, dict]] = field(default_factory=dict)

    def badges_of(self, address: str) -> Dict[str, dict]:
        return self.holders.get(address, {})

    def has_badge(self, address: str, badge_id: str) -> bool:
        return badge_id in self.holders.get(address, {})


class BadgeContract(Contract):
    NAME = "badges"
    HANDLED_TYPES = frozenset({"BADGE_AWARD"})

    def initial_state(self) -> BadgeState:
        return BadgeState()

    def validate(self, state: BadgeState, tx: dict, ctx: TxContext) -> Tuple[bool, str]:
        payload = tx.get("payload")
        if not isinstance(payload, dict):
            return False, "payload debe ser un objeto"
        sender, recipient = tx.get("sender", ""), tx.get("recipient", "")
        if not is_registered_issuer(ctx, sender):
            return False, "Solo un emisor registrado puede otorgar insignias"
        if not isinstance(recipient, str) or not recipient or recipient == sender:
            return False, "El destinatario debe ser otra dirección"
        badge_id = text_or_none(payload.get("badge_id"), MAX_LABEL)
        if badge_id is None:
            return False, f"badge_id debe ser texto de 1 a {MAX_LABEL} caracteres"
        if text_or_none(payload.get("name"), MAX_LABEL) is None:
            return False, f"name debe ser texto de 1 a {MAX_LABEL} caracteres"
        if text_or_none(payload.get("reason"), MAX_REASON) is None:
            return False, f"reason debe ser texto de 1 a {MAX_REASON} caracteres"
        if state.has_badge(recipient, badge_id):
            return False, f"La dirección ya tiene la insignia {badge_id}"
        return True, "OK"

    def apply(self, state: BadgeState, tx: dict, ctx: TxContext) -> BadgeState:
        payload = tx["payload"]
        state.holders.setdefault(tx["recipient"], {})[payload["badge_id"]] = {
            "badge_id": payload["badge_id"],
            "name": payload["name"],
            "reason": payload["reason"],
            "issuer": tx["sender"],
            "block_index": ctx.block_index,
            "tx_id": tx.get("tx_id", ""),
        }
        return state
