"""
Contrato de votación (P1-13): el contrato de REFERENCIA para copiar.

Es el más chico posible que sigue la interfaz única (``base.py``). Para
escribir uno nuevo, copiar este archivo y cambiar las cuatro piezas:
estado, ``HANDLED_TYPES``, ``validate`` y ``apply`` (ver ``docs/contratos.md``).

Reglas:
    - TX ``VOTE`` con payload ``{"election_id": str, "choice": str}``
      (1 a 64 caracteres cada uno).
    - Cada dirección vota UNA vez por elección (el ``sender`` es quien firmó).
    - Cualquiera puede votar en cualquier elección: no hay padrón ni cierre.
      La votación ponderada y con padrón queda para P2-12.

Una segunda votación de la misma dirección en la misma elección es inválida:
la API responde 400 y un bloque que la incluya se rechaza entero.
"""
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from blockchain.contracts.base import Contract, TxContext

MAX_LEN = 64


@dataclass
class VotingState:
    """elección → {votante → opción}, en el orden en que se confirmaron los votos."""
    elections: Dict[str, Dict[str, str]] = field(default_factory=dict)

    def has_voted(self, election_id: str, voter: str) -> bool:
        return voter in self.elections.get(election_id, {})

    def tally(self, election_id: str) -> Dict[str, int]:
        """Votos por opción (ordenado por opción para que la salida sea estable)."""
        counts: Dict[str, int] = {}
        for choice in self.elections.get(election_id, {}).values():
            counts[choice] = counts.get(choice, 0) + 1
        return dict(sorted(counts.items()))


def _text(value) -> Optional[str]:
    """``value`` si es un str de 1..MAX_LEN caracteres; si no, None."""
    if isinstance(value, str) and 0 < len(value) <= MAX_LEN:
        return value
    return None


class VotingContract(Contract):
    NAME = "voting"
    HANDLED_TYPES = frozenset({"VOTE"})

    def initial_state(self) -> VotingState:
        return VotingState()

    def validate(self, state: VotingState, tx: dict, ctx: TxContext) -> Tuple[bool, str]:
        payload = tx.get("payload")
        if not isinstance(payload, dict):
            return False, "payload debe ser un objeto"
        election_id = _text(payload.get("election_id"))
        if election_id is None:
            return False, f"election_id debe ser texto de 1 a {MAX_LEN} caracteres"
        if _text(payload.get("choice")) is None:
            return False, f"choice debe ser texto de 1 a {MAX_LEN} caracteres"
        if state.has_voted(election_id, tx.get("sender", "")):
            return False, f"Ya votó en la elección {election_id}"
        return True, "OK"

    def apply(self, state: VotingState, tx: dict, ctx: TxContext) -> VotingState:
        payload = tx["payload"]
        votes = state.elections.setdefault(payload["election_id"], {})
        votes[tx["sender"]] = payload["choice"]
        return state
