"""
Contrato de cuentas (P0-9, portado a la interfaz única en P1-13): saldo y
nonce por dirección, derivados de la cadena.

Montos: enteros en la unidad mínima (como los satoshis de Bitcoin o el wei de
Ethereum). Nunca floats: 0.1 + 0.2 != 0.3 y dos nodos podrían discrepar.

Reglas (aplican a TODAS las TXs firmadas, de cualquier tipo: ``HANDLED_TYPES = None``):

    nonce   La TX número k de una dirección lleva ``nonce = k`` (la primera,
            1). Válida solo si ``nonce == nonce_confirmado(sender) + 1``.
            Así una TX firmada no se puede "reproducir" (replay) ni
            reordenar: la misma firma con el mismo nonce ya no es válida.
    fee     Entero >= 0. Se descuenta del sender y se QUEMA (sale de la
            oferta total). No hay recompensa de minado (ver P1-12), así que
            no hay a quién acreditarla sin inventar una regla nueva. Con
            fee 0 (por defecto) las credenciales funcionan sin saldo.
    saldo   ``saldo(sender) >= fee + amount`` (amount solo en transferencias).

Tipos con efecto sobre saldos:

    TOKEN_MINT      payload {"amount": int > 0}. Crea ``amount`` unidades
                    para ``recipient``. Es la fuente de la oferta sin cambiar
                    el génesis (GENESIS_HASH). Quién puede emitir lo decide el
                    contrato ``tokens`` (P1-12: autoridad o emisor dentro de su
                    presupuesto); sin ese contrato, solo la autoridad.
    TOKEN_TRANSFER  payload {"amount": int > 0}; mueve saldo sender → recipient.
    TOKEN_REDEEM    payload {"amount": int > 0}; descuenta ``amount`` del sender
                    y lo QUEMA (sale de la oferta). Que el recipient sea una
                    dirección de canje registrada lo exige el contrato ``tokens``.

Los demás tipos (credenciales, DATA_RECORD, VOTE, …) solo consumen nonce y fee.
Este contrato es siempre el primero del registro: lo posee la cadena
(``Blockchain.accounts``) porque el nonce ordena las TXs de cada firmante.
"""
from dataclasses import dataclass, field
from typing import Dict, Iterable, Optional, Tuple

from blockchain.contracts.base import Contract, TxContext, is_int, tx_type_of


@dataclass
class Accounts:
    """Estado del contrato de cuentas."""
    balances: Dict[str, int] = field(default_factory=dict)
    nonces: Dict[str, int] = field(default_factory=dict)
    total_supply: int = 0   # Σ minado − Σ fees quemadas
    burned_fees: int = 0

    def balance_of(self, address: str) -> int:
        return self.balances.get(address, 0)

    def nonce_of(self, address: str) -> int:
        """Nonce de la última TX confirmada de ``address`` (0 si no tiene)."""
        return self.nonces.get(address, 0)


_MOVES_BALANCE = ("TOKEN_TRANSFER", "TOKEN_MINT", "TOKEN_REDEEM")


class AccountContract(Contract):
    NAME = "accounts"
    HANDLED_TYPES = None   # toda TX consume nonce y paga fee

    def __init__(self, authority_address: Optional[str] = None) -> None:
        from blockchain.core.block import GENESIS_AUTHORITY_ADDRESS
        self.authority_address = authority_address or GENESIS_AUTHORITY_ADDRESS

    def initial_state(self) -> Accounts:
        return Accounts()

    @staticmethod
    def _amount(tx: dict):
        """Monto que mueve la TX (0 si el tipo no mueve saldo; None si falta)."""
        if tx_type_of(tx) in _MOVES_BALANCE:
            payload = tx.get("payload")
            return payload.get("amount") if isinstance(payload, dict) else None
        return 0

    def validate(self, state: Accounts, tx: dict, ctx: TxContext) -> Tuple[bool, str]:
        sender = tx.get("sender", "")
        tx_type = tx_type_of(tx)
        nonce, fee = tx.get("nonce"), tx.get("fee", 0)
        if not is_int(nonce):
            return False, "nonce debe ser un entero"
        expected = state.nonce_of(sender) + 1
        if nonce != expected:
            return False, f"Nonce inválido: esperado {expected}, recibido {nonce}"
        if not is_int(fee) or fee < 0:
            return False, "fee debe ser un entero >= 0"
        amount = self._amount(tx)
        if tx_type in _MOVES_BALANCE and (not is_int(amount) or amount <= 0):
            return False, "amount debe ser un entero > 0 (unidad mínima)"
        if tx_type == "TOKEN_MINT":
            # Con el contrato de tokens registrado, él autoriza (P1-12).
            if sender != self.authority_address and ctx.view("tokens") is None:
                return False, "Solo la autoridad del génesis puede emitir tokens"
            amount = 0  # el monto minado no sale del saldo del sender
        if state.balance_of(sender) < fee + amount:
            return False, (f"Saldo insuficiente: tiene {state.balance_of(sender)}, "
                           f"necesita {fee + amount}")
        return True, "OK"

    def apply(self, state: Accounts, tx: dict, ctx: TxContext) -> Accounts:
        sender, recipient = tx["sender"], tx["recipient"]
        tx_type = tx_type_of(tx)
        fee = tx.get("fee", 0)
        state.nonces[sender] = tx["nonce"]
        state.balances[sender] = state.balance_of(sender) - fee
        state.total_supply -= fee
        state.burned_fees += fee
        amount = tx["payload"]["amount"] if tx_type in _MOVES_BALANCE else 0
        if tx_type == "TOKEN_MINT":
            state.total_supply += amount
        elif tx_type == "TOKEN_TRANSFER":
            state.balances[sender] -= amount
        elif tx_type == "TOKEN_REDEEM":
            state.balances[sender] -= amount
            state.total_supply -= amount
            return state   # quemado: el recipient (dirección de canje) no recibe saldo
        if amount:
            state.balances[recipient] = state.balance_of(recipient) + amount
        return state

    # ── Vistas para la API (no son reglas de consenso) ────────────────────────

    @staticmethod
    def next_nonce(state: Accounts, address: str, pending: Iterable[dict] = ()) -> int:
        """Nonce que debe llevar la próxima TX de ``address`` (confirmadas + mempool)."""
        nonce = state.nonce_of(address)
        for p in pending:
            if p.get("sender") == address and p.get("nonce") == nonce + 1:
                nonce += 1
        return nonce + 1

    def account_info(self, state: Accounts, address: str, height: int,
                     pending: Iterable[dict] = ()) -> dict:
        return {
            "address": address,
            "balance": state.balance_of(address),
            "nonce": state.nonce_of(address),
            "next_nonce": self.next_nonce(state, address, pending),
            "height": height,
        }
