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
                             Con ``item_id`` (P2-12) compra un ítem del catálogo:
                             amount == precio, stock > 0, recipient == la dirección
                             de canje del ítem; descuenta 1 de stock y guarda un
                             recibo cuyo id sale del ``tx_id``.
    CATALOG_ITEM  (P2-12)    sender = autoridad; payload {item_id, title, price int > 0,
                             stock int >= 0, redeem_address registrada}. Un ``item_id``
                             se publica una sola vez. Entradas, impresiones o turnos
                             de laboratorio son solo ejemplos de datos, no del código.
    AWARD_RULE    (P2-12)    sender = autoridad; payload {rule_id, credential_type,
                             issuer_address registrado, amount int > 0}. "Al emitir
                             ``issuer_address`` una credencial de ese tipo, premiar al
                             estudiante con ``amount``, a cargo del presupuesto
                             semestral del emisor." Un par (tipo, emisor) tiene una
                             sola regla.

Premio automático (P2-12): ``CREDENTIAL_ISSUE`` también es de este contrato. Si hay
una regla para (tipo, emisor) se calcula con ``auto_award`` (función pura, la misma
para tokens y cuentas): si el semestre del bloque tiene presupuesto restante >=
monto, se acredita; si NO alcanza, el premio se OMITE y la credencial se emite igual.
No invalida el bloque porque el emisor firmó una credencial, no un premio: de lo
contrario un emisor sin presupuesto no podría emitir credenciales (excepción a la
política de TX inválida de P1-13, a propósito). Como los saldos son del contrato de
cuentas, ese contrato acredita el monto leyendo ``ctx.view("tokens")`` ANTES de que
este contrato aplique la TX; ambos usan el mismo estado previo, así que coinciden.

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


MAX_ID = 64
MAX_TITLE = 140


def receipt_id_of(tx_id: str) -> str:
    """Id determinista del recibo de un canje: sale del ``tx_id`` (P2-12)."""
    return "R-" + str(tx_id)[:16]


def auto_award(state: "TokenState", tx: dict, ctx: TxContext) -> Optional[dict]:
    """Premio automático que corresponde a una TX ``CREDENTIAL_ISSUE`` (P2-12), o None.

    Pura y determinista: solo mira ``state`` (previo a la TX), la TX y la hora del
    bloque. Devuelve ``{rule_id, amount, issuer, recipient, semester}`` si hay regla
    para (credential_type, emisor) y el presupuesto del semestre del bloque alcanza;
    None en cualquier otro caso (sin regla, sin hora, emisor sin presupuesto).
    """
    if tx_type_of(tx) != "CREDENTIAL_ISSUE" or ctx.block_timestamp is None:
        return None
    payload = tx.get("payload")
    if not isinstance(payload, dict):
        return None
    sender, recipient = tx.get("sender", ""), tx.get("recipient", "")
    ctype = payload.get("credential_type")
    if not isinstance(ctype, str) or not isinstance(recipient, str) or recipient in ("", sender):
        return None
    for rule_id, rule in state.rules.items():
        if rule["credential_type"] == ctype and rule["issuer_address"] == sender:
            semester = semester_of(ctx.block_timestamp)
            if rule["amount"] > state.remaining(sender, semester):
                return None     # presupuesto insuficiente: se omite el premio
            return {"rule_id": rule_id, "amount": rule["amount"], "issuer": sender,
                    "recipient": recipient, "semester": semester}
    return None


@dataclass
class TokenState:
    """Estado del contrato de tokens (los saldos están en ``accounts``)."""
    budgets: Dict[str, Dict[str, int]] = field(default_factory=dict)  # emisor → {semestre → presupuesto}
    minted: Dict[str, Dict[str, int]] = field(default_factory=dict)   # emisor → {semestre → emitido}
    redeem_addresses: Dict[str, str] = field(default_factory=dict)    # dirección → etiqueta
    redeemed: Dict[str, int] = field(default_factory=dict)            # dirección de canje → total quemado
    awards: Dict[str, List[dict]] = field(default_factory=dict)       # estudiante → premios recibidos
    catalog: Dict[str, dict] = field(default_factory=dict)            # item_id → ítem (P2-12)
    receipts: Dict[str, dict] = field(default_factory=dict)           # recibo → canje de catálogo (P2-12)
    rules: Dict[str, dict] = field(default_factory=dict)              # rule_id → premio automático (P2-12)

    def budget_of(self, issuer: str, semester: str) -> int:
        return self.budgets.get(issuer, {}).get(semester, 0)

    def minted_by(self, issuer: str, semester: str) -> int:
        return self.minted.get(issuer, {}).get(semester, 0)

    def remaining(self, issuer: str, semester: str) -> int:
        return self.budget_of(issuer, semester) - self.minted_by(issuer, semester)


class TokenContract(Contract):
    NAME = "tokens"
    HANDLED_TYPES = frozenset({"ISSUER_BUDGET", "TOKEN_MINT",
                               "REDEEM_ADDRESS_REGISTER", "TOKEN_REDEEM",
                               "CATALOG_ITEM", "AWARD_RULE", "CREDENTIAL_ISSUE"})

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
            if "item_id" in payload:
                return self._check_item_redeem(state, tx.get("recipient"), payload)
            return True, "OK"
        if tx_type == "CATALOG_ITEM":
            return self._check_catalog_item(state, sender, payload)
        if tx_type == "AWARD_RULE":
            return self._check_award_rule(state, sender, payload, ctx)
        if tx_type == "CREDENTIAL_ISSUE":
            return True, "OK"   # la valida el contrato de credenciales; aquí solo se premia
        return False, f"Tipo no soportado por el contrato: {tx_type}"

    @staticmethod
    def _check_item_redeem(state: TokenState, redeem_address, payload: dict) -> Tuple[bool, str]:
        item = state.catalog.get(payload["item_id"]) if isinstance(payload["item_id"], str) else None
        if item is None:
            return False, "El ítem no existe en el catálogo"
        if payload["amount"] != item["price"]:
            return False, f"El precio del ítem es {item['price']}, se ofreció {payload['amount']}"
        if item["stock"] <= 0:
            return False, "Ítem agotado"
        if redeem_address != item["redeem_address"]:
            return False, "El ítem se canjea en otra dirección de canje"
        return True, "OK"

    def _check_catalog_item(self, state: TokenState, sender: str, payload: dict) -> Tuple[bool, str]:
        if sender != self.authority_address:
            return False, "Solo la autoridad puede publicar ítems del catálogo"
        item_id = text_or_none(payload.get("item_id"), MAX_ID)
        if item_id is None:
            return False, f"item_id debe ser texto de 1 a {MAX_ID} caracteres"
        if text_or_none(payload.get("title"), MAX_TITLE) is None:
            return False, f"title debe ser texto de 1 a {MAX_TITLE} caracteres"
        if not is_int(payload.get("price")) or payload["price"] <= 0:
            return False, "price debe ser un entero > 0"
        if not is_int(payload.get("stock")) or payload["stock"] < 0:
            return False, "stock debe ser un entero >= 0"
        if payload.get("redeem_address") not in state.redeem_addresses:
            return False, "redeem_address no es una dirección de canje registrada"
        if item_id in state.catalog:
            return False, f"El ítem {item_id} ya está en el catálogo"
        return True, "OK"

    def _check_award_rule(self, state: TokenState, sender: str, payload: dict,
                          ctx: TxContext) -> Tuple[bool, str]:
        if sender != self.authority_address:
            return False, "Solo la autoridad puede crear reglas de premio"
        rule_id = text_or_none(payload.get("rule_id"), MAX_ID)
        if rule_id is None:
            return False, f"rule_id debe ser texto de 1 a {MAX_ID} caracteres"
        ctype = text_or_none(payload.get("credential_type"), MAX_ID)
        if ctype is None:
            return False, f"credential_type debe ser texto de 1 a {MAX_ID} caracteres"
        if not is_registered_issuer(ctx, payload.get("issuer_address")):
            return False, "Emisor no registrado"
        if not is_int(payload.get("amount")) or payload["amount"] <= 0:
            return False, "amount debe ser un entero > 0"
        if rule_id in state.rules:
            return False, f"La regla {rule_id} ya existe"
        for rule in state.rules.values():
            if (rule["credential_type"] == ctype
                    and rule["issuer_address"] == payload["issuer_address"]):
                return False, "Ya hay una regla para ese tipo de credencial y emisor"
        return True, "OK"

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
            if "item_id" in payload:
                state.catalog[payload["item_id"]]["stock"] -= 1
                state.receipts[receipt_id_of(tx.get("tx_id", ""))] = {
                    "receipt_id": receipt_id_of(tx.get("tx_id", "")),
                    "buyer": sender, "item_id": payload["item_id"],
                    "price": payload["amount"], "redeem_address": recipient,
                    "block_index": ctx.block_index, "tx_id": tx.get("tx_id", ""),
                }
        elif tx_type == "CATALOG_ITEM":
            state.catalog[payload["item_id"]] = {
                "item_id": payload["item_id"], "title": payload["title"],
                "price": payload["price"], "stock": payload["stock"],
                "redeem_address": payload["redeem_address"],
            }
        elif tx_type == "AWARD_RULE":
            state.rules[payload["rule_id"]] = {
                "rule_id": payload["rule_id"], "credential_type": payload["credential_type"],
                "issuer_address": payload["issuer_address"], "amount": payload["amount"],
            }
        elif tx_type == "CREDENTIAL_ISSUE":
            award = auto_award(state, tx, ctx)
            if award is not None:     # sin premio: la credencial se emite igual (ver docstring)
                per_issuer = state.minted.setdefault(sender, {})
                per_issuer[award["semester"]] = per_issuer.get(award["semester"], 0) + award["amount"]
                state.awards.setdefault(award["recipient"], []).append({
                    "issuer": sender, "amount": award["amount"],
                    "reason": f"premio automático por credencial ({award['rule_id']})",
                    "semester": award["semester"], "block_index": ctx.block_index,
                    "tx_id": tx.get("tx_id", ""), "rule_id": award["rule_id"],
                })
        return state
