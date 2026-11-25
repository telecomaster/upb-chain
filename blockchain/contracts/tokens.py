"""
Contrato de tokens para estudiantes (P1-12): presupuestos de emisión por
semestre, premios de los docentes y canjes.

Puntos de CIRCUITO CERRADO, SIN VALOR MONETARIO: no se compran, no se venden
ni se cambian por dinero; solo se ganan (premios) y se canjean en direcciones
de la UPB. Pendiente el visto bueno del área legal de la UPB (ver "Decisiones
abiertas" en ``docs/ROADMAP.md``). El nombre ``TOKEN_SYMBOL`` es provisorio.

Los SALDOS los lleva el contrato de cuentas (``accounts.py``): este contrato
decide QUIÉN puede emitir y DÓNDE se puede canjear, y guarda el historial.

Reglas:

    ISSUER_BUDGET            sender = autoridad; payload {issuer_address,
                             semester "AAAA-1"|"AAAA-2", amount int >= 0}.
                             FIJA el presupuesto del emisor (registrado en el
                             contrato de credenciales) para ese semestre; no
                             puede quedar por debajo de lo ya emitido en él.
    TOKEN_MINT               - autoridad: sin presupuesto (como en P0-9).
                             - emisor registrado: payload {amount, reason}
                               (reason: texto de 1 a 140), recipient distinto
                               del emisor y amount <= presupuesto restante del
                               semestre del BLOQUE (ver ``semester_of``).
    REDEEM_ADDRESS_REGISTER  sender = autoridad; payload {redeem_address,
                             label}; una dirección de canje (cafetería,
                             biblioteca…) se registra una sola vez.
    TOKEN_REDEEM             recipient = dirección de canje registrada; el
                             contrato de cuentas quema ``amount`` del sender.

No hay recompensa por minado: los mineros son nodos de la UPB.

Lectura entre contratos: "emisor registrado" se consulta con
``ctx.view("credentials").is_registered_issuer`` (solo lectura; ver ``base.py``).
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from blockchain.contracts.base import Contract, TxContext, is_int, tx_type_of

# Nombre provisorio de los puntos: decisión abierta (ROADMAP, "Decisiones abiertas").
TOKEN_SYMBOL = "PUPB"
TOKEN_NAME = "puntos UPB"

MAX_REASON = 140
MAX_LABEL = 64

# Semestre en hora de Bolivia (UTC−4, sin horario de verano): enteros, sin reloj.
BOLIVIA_OFFSET_SECONDS = -4 * 3600
SECONDS_PER_DAY = 86400


def _civil_from_days(days: int) -> Tuple[int, int, int]:
    """Fecha (año, mes, día) del día ``days`` contado desde 1970-01-01.

    Algoritmo de calendario gregoriano proléptico solo con enteros (H. Hinnant,
    "chrono-Compatible Low-Level Date Algorithms"): no usa ``datetime`` ni floats.
    """
    z = days + 719468
    era = z // 146097
    doe = z - era * 146097                                   # día de la era [0, 146096]
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)          # día del año desde el 1 de marzo
    mp = (5 * doy + 2) // 153
    day = doy - (153 * mp + 2) // 5 + 1
    month = mp + 3 if mp < 10 else mp - 9
    year = yoe + era * 400 + (1 if month <= 2 else 0)
    return year, month, day


def semester_of(timestamp) -> str:
    """Semestre de un timestamp de bloque: ``"AAAA-1"`` (ene–jun) o ``"AAAA-2"`` (jul–dic).

    Regla de frontera: se trunca el timestamp a segundos enteros (``int``) y se
    pasa a hora de Bolivia (UTC−4); el semestre 2 empieza el 1 de julio a las
    00:00:00 y el 1 el 1 de enero a las 00:00:00, hora de Bolivia. Es la hora del
    ENCABEZADO del bloque, igual en todos los nodos; nunca el reloj del nodo.
    """
    year, month, _ = _civil_from_days((int(timestamp) + BOLIVIA_OFFSET_SECONDS) // SECONDS_PER_DAY)
    return f"{year}-{1 if month <= 6 else 2}"


def is_semester(value) -> bool:
    """``"AAAA-1"`` o ``"AAAA-2"`` (año de 4 dígitos)."""
    return (isinstance(value, str) and len(value) == 6 and value[:4].isdigit()
            and value[:4].isascii() and value[4] == "-" and value[5] in ("1", "2"))


def text_or_none(value, max_len: int) -> Optional[str]:
    """``value`` si es texto no vacío de hasta ``max_len`` caracteres; si no, None."""
    if isinstance(value, str) and 0 < len(value.strip()) and len(value) <= max_len:
        return value
    return None


def is_registered_issuer(ctx: TxContext, address) -> bool:
    """¿``address`` es emisor registrado? Lee el contrato de credenciales vía ``ctx``."""
    credentials = ctx.view("credentials")
    return (credentials is not None and isinstance(address, str)
            and credentials.is_registered_issuer(address))


@dataclass
class TokenState:
    """Estado del contrato de tokens (los saldos están en ``accounts``)."""
    budgets: Dict[str, Dict[str, int]] = field(default_factory=dict)  # emisor → {semestre → presupuesto}
    minted: Dict[str, Dict[str, int]] = field(default_factory=dict)   # emisor → {semestre → emitido}
    redeem_addresses: Dict[str, str] = field(default_factory=dict)    # dirección → etiqueta
    redeemed: Dict[str, int] = field(default_factory=dict)            # dirección de canje → total quemado
    awards: Dict[str, List[dict]] = field(default_factory=dict)       # estudiante → premios recibidos

    def budget_of(self, issuer: str, semester: str) -> int:
        return self.budgets.get(issuer, {}).get(semester, 0)

    def minted_by(self, issuer: str, semester: str) -> int:
        return self.minted.get(issuer, {}).get(semester, 0)

    def remaining(self, issuer: str, semester: str) -> int:
        return self.budget_of(issuer, semester) - self.minted_by(issuer, semester)


class TokenContract(Contract):
    NAME = "tokens"
    HANDLED_TYPES = frozenset({"ISSUER_BUDGET", "TOKEN_MINT",
                               "REDEEM_ADDRESS_REGISTER", "TOKEN_REDEEM"})

    def __init__(self, authority_address: Optional[str] = None) -> None:
        from blockchain.core.block import GENESIS_AUTHORITY_ADDRESS
        self.authority_address = authority_address or GENESIS_AUTHORITY_ADDRESS

    def initial_state(self) -> TokenState:
        return TokenState()

    # ── Reglas (puras) ────────────────────────────────────────────────────────

    def validate(self, state: TokenState, tx: dict, ctx: TxContext) -> Tuple[bool, str]:
        payload = tx.get("payload")
        if not isinstance(payload, dict):
            return False, "payload debe ser un objeto"
        tx_type = tx_type_of(tx)
        sender = tx.get("sender", "")
        if tx_type == "ISSUER_BUDGET":
            return self._check_budget(state, sender, payload, ctx)
        if tx_type == "TOKEN_MINT":
            return self._check_mint(state, sender, tx.get("recipient", ""), payload, ctx)
        if tx_type == "REDEEM_ADDRESS_REGISTER":
            if sender != self.authority_address:
                return False, "Solo la autoridad puede registrar direcciones de canje"
            address = payload.get("redeem_address")
            if not isinstance(address, str) or not address:
                return False, "Falta redeem_address"
            if text_or_none(payload.get("label"), MAX_LABEL) is None:
                return False, f"label debe ser texto de 1 a {MAX_LABEL} caracteres"
            if address in state.redeem_addresses:
                return False, "Dirección de canje ya registrada"
            return True, "OK"
        if tx_type == "TOKEN_REDEEM":
            if tx.get("recipient") not in state.redeem_addresses:
                return False, "El destino no es una dirección de canje registrada"
            if not is_int(payload.get("amount")) or payload["amount"] <= 0:
                return False, "amount debe ser un entero > 0"
            return True, "OK"
        return False, f"Tipo no soportado por el contrato: {tx_type}"

    def _check_budget(self, state: TokenState, sender: str, payload: dict,
                      ctx: TxContext) -> Tuple[bool, str]:
        if sender != self.authority_address:
            return False, "Solo la autoridad puede fijar presupuestos"
        issuer, semester, amount = (payload.get("issuer_address"), payload.get("semester"),
                                    payload.get("amount"))
        if not is_registered_issuer(ctx, issuer):
            return False, "Emisor no registrado"
        if not is_semester(semester):
            return False, "semester debe tener la forma AAAA-1 o AAAA-2"
        if not is_int(amount) or amount < 0:
            return False, "amount debe ser un entero >= 0"
        used = state.minted_by(issuer, semester)
        if amount < used:
            return False, f"El presupuesto no puede ser menor a lo ya emitido ({used})"
        return True, "OK"

    def _check_mint(self, state: TokenState, sender: str, recipient: str, payload: dict,
                    ctx: TxContext) -> Tuple[bool, str]:
        amount = payload.get("amount")
        if not is_int(amount) or amount <= 0:
            return False, "amount debe ser un entero > 0"
        if sender == self.authority_address:
            return True, "OK"       # la autoridad emite sin presupuesto (P0-9)
        if not is_registered_issuer(ctx, sender):
            return False, "Solo la autoridad o un emisor registrado pueden emitir tokens"
        if text_or_none(payload.get("reason"), MAX_REASON) is None:
            return False, f"reason es obligatorio (texto de 1 a {MAX_REASON} caracteres)"
        if recipient == sender:
            return False, "Un emisor no puede premiarse a sí mismo"
        if ctx.block_timestamp is None:
            return False, "Sin hora de bloque no se puede saber el semestre"
        semester = semester_of(ctx.block_timestamp)
        remaining = state.remaining(sender, semester)
        if amount > remaining:
            return False, (f"Presupuesto insuficiente en {semester}: "
                           f"quedan {remaining}, pide {amount}")
        return True, "OK"

    # ── Transición ────────────────────────────────────────────────────────────

    def apply(self, state: TokenState, tx: dict, ctx: TxContext) -> TokenState:
        tx_type = tx_type_of(tx)
        payload = tx["payload"]
        sender = tx["sender"]
        if tx_type == "ISSUER_BUDGET":
            state.budgets.setdefault(payload["issuer_address"], {})[payload["semester"]] = \
                payload["amount"]
        elif tx_type == "TOKEN_MINT":
            semester = None
            if sender != self.authority_address:
                semester = semester_of(ctx.block_timestamp)
                per_issuer = state.minted.setdefault(sender, {})
                per_issuer[semester] = per_issuer.get(semester, 0) + payload["amount"]
            state.awards.setdefault(tx["recipient"], []).append({
                "issuer": sender,
                "amount": payload["amount"],
                "reason": payload.get("reason", ""),
                "semester": semester,
                "block_index": ctx.block_index,
                "tx_id": tx.get("tx_id", ""),
            })
        elif tx_type == "REDEEM_ADDRESS_REGISTER":
            state.redeem_addresses[payload["redeem_address"]] = payload["label"]
        elif tx_type == "TOKEN_REDEEM":
            recipient = tx["recipient"]
            state.redeemed[recipient] = state.redeemed.get(recipient, 0) + payload["amount"]
        return state
