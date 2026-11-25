"""
Contratos desplegables por estudiantes (P2-11): reglas de ``CONTRACT_DEPLOY`` y
``CONTRACT_CALL`` sobre la VM de pila de ``blockchain/vm``.

Un contrato desplegado es BYTECODE guardado en la cadena, no un módulo Python:
lo ejecuta ``blockchain.vm.machine.run``, que solo sabe sumar, comparar, saltar,
leer/escribir su storage y mover los PUPB que el contrato tiene. Nunca ``exec``.

TXs (los montos son PUPB enteros; ``gas_price`` ≥ ``MIN_GAS_PRICE``):

    CONTRACT_DEPLOY  recipient = ``contract_address(sender, nonce)`` ("UPC" + 32 hex)
                     payload {code: hex, storage?: [[clave, valor], …],
                              gas_limit, gas_price}
                     Cuesta ``deploy_gas(code, storage) * gas_price`` (se QUEMA).
    CONTRACT_CALL    recipient = dirección del contrato
                     payload {args: [int, …], value, gas_limit, gas_price}
                     ``value`` PUPB pasan del sender al contrato si la llamada
                     termina bien. Cuesta ``gas_used * gas_price`` (se QUEMA).

Regla de validez (distinta de la regla general "TX inválida ⇒ bloque inválido"):

    Una llamada que se queda sin gas, hace REVERT o falla (pila, salto, división
    por 0, saldo del contrato) es una TX VÁLIDA: entra al bloque, consume nonce,
    cobra el gas y NO cambia nada más (storage, logs, saldos del contrato y
    ``value`` vuelven a como estaban). Así funciona Ethereum, y hay una razón:
    para saber si una llamada fracasa hay que EJECUTARLA, y ese trabajo lo hizo
    toda la red; si la TX fuera inválida nadie lo pagaría (un atacante podría
    mandar bucles infinitos gratis). Por eso la validez depende solo de cosas
    que se comprueban SIN ejecutar:

    INVÁLIDAS (400 en la API, bloque rechazado):
      - payload mal formado (tipos, rangos, más de MAX_ARGS argumentos…);
      - saldo < fee + value + gas_limit * gas_price (no alcanza para el peor caso);
      - gas_limit < gas mínimo (CALL_BASE_GAS / deploy_gas) o > MAX_GAS_LIMIT;
      - deploy: bytecode mal formado (opcode desconocido, PUSH truncado, > 4096 B),
        storage inicial demasiado grande o recipient ≠ dirección derivada;
      - call: contrato inexistente.

Quién mueve los PUPB: el contrato ``accounts`` (los saldos son suyos). Para no
romper la regla "un contrato no escribe el estado de otro", ``accounts`` y este
contrato ejecutan la MISMA función pura ``execute_call`` con las MISMAS entradas
(el estado de la VM justo antes de la TX, la TX y la altura): ``accounts`` aplica
gas, ``value`` y TRANSFER a los saldos; este contrato aplica storage, logs y el
saldo del contrato. Como la ejecución es determinista, coinciden. Cuesta ejecutar
dos veces; el gas lo acota. (Este contrato va DESPUÉS de ``accounts`` en el
registro, que siempre es el primero: ``ctx.view("vm")`` en ``accounts`` es el
estado previo a la TX.)

Invariante de oferta: Σ saldos de cuentas + Σ saldos de contratos = total_supply.
"""
import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from blockchain.contracts.base import Contract, TxContext, is_int, tx_type_of
from blockchain.vm.asm import address_to_int, int_to_address
from blockchain.vm.machine import (
    MAX_ARGS, MAX_CODE_SIZE, MAX_GAS_LIMIT, MAX_STORAGE_SLOTS, WORD_MOD,
    BytecodeError, Result, run, validate_code,
)

CONTRACT_PREFIX = "UPC"
MIN_GAS_PRICE = 1
CALL_BASE_GAS = 100              # gas fijo de toda llamada (antes de la 1.ª instrucción)
DEPLOY_BASE_GAS = 1000
DEPLOY_GAS_PER_BYTE = 20
DEPLOY_GAS_PER_SLOT = 200
MAX_LOGS_KEPT = 100              # logs guardados por contrato (se descartan los más viejos)

DEPLOY, CALL = "CONTRACT_DEPLOY", "CONTRACT_CALL"


def contract_address(sender: str, nonce: int) -> str:
    """Dirección determinista de un contrato: hash(sender, nonce de la TX de despliegue)."""
    digest = hashlib.sha256(f"{sender}:{nonce}".encode("utf-8")).hexdigest().upper()
    return CONTRACT_PREFIX + digest[:32]


def is_contract_address(address: Any) -> bool:
    return isinstance(address, str) and address.startswith(CONTRACT_PREFIX)


def deploy_gas(code_hex: str, storage: Optional[list]) -> int:
    """Gas de un despliegue: fijo + por byte de código + por casilla inicial."""
    return (DEPLOY_BASE_GAS + DEPLOY_GAS_PER_BYTE * (len(code_hex) // 2)
            + DEPLOY_GAS_PER_SLOT * len(storage or []))


def _is_word(value) -> bool:
    return is_int(value) and 0 <= value < WORD_MOD


def check_payload(tx: dict) -> Tuple[bool, str]:
    """Forma del payload de una TX de contrato (sin mirar estado). La usa también ``accounts``."""
    payload = tx.get("payload")
    if not isinstance(payload, dict):
        return False, "payload debe ser un objeto"
    gas_limit, gas_price = payload.get("gas_limit"), payload.get("gas_price")
    if not is_int(gas_price) or gas_price < MIN_GAS_PRICE:
        return False, f"gas_price debe ser un entero >= {MIN_GAS_PRICE}"
    if not is_int(gas_limit) or not 0 < gas_limit <= MAX_GAS_LIMIT:
        return False, f"gas_limit debe ser un entero entre 1 y {MAX_GAS_LIMIT}"
    if tx_type_of(tx) == DEPLOY:
        code = payload.get("code")
        if not isinstance(code, str) or len(code) % 2 or len(code) > 2 * MAX_CODE_SIZE:
            return False, f"code debe ser hex de hasta {MAX_CODE_SIZE} bytes"
        try:
            validate_code(bytes.fromhex(code))
        except (BytecodeError, ValueError) as e:
            return False, f"bytecode inválido: {e}"
        storage = payload.get("storage", [])
        if not isinstance(storage, list) or len(storage) > MAX_STORAGE_SLOTS:
            return False, f"storage debe ser una lista de hasta {MAX_STORAGE_SLOTS} pares"
        keys = set()
        for pair in storage:
            if (not isinstance(pair, list) or len(pair) != 2
                    or not _is_word(pair[0]) or not _is_word(pair[1]) or pair[1] == 0):
                return False, "storage: cada par es [clave, valor] con enteros de 256 bits, valor ≠ 0"
            keys.add(pair[0])
        if len(keys) != len(storage):
            return False, "storage: claves repetidas"
        if set(payload) - {"code", "storage", "gas_limit", "gas_price"}:
            return False, "payload con claves desconocidas"
        need = deploy_gas(code, storage)
        if gas_limit < need:
            return False, f"gas_limit insuficiente para desplegar: necesita {need}"
        return True, "OK"
    args, value = payload.get("args", []), payload.get("value", 0)
    if not isinstance(args, list) or len(args) > MAX_ARGS or not all(_is_word(a) for a in args):
        return False, f"args debe ser una lista de hasta {MAX_ARGS} enteros de 256 bits"
    if not is_int(value) or value < 0:
        return False, "value debe ser un entero >= 0"
    if set(payload) - {"args", "value", "gas_limit", "gas_price"}:
        return False, "payload con claves desconocidas"
    if gas_limit < CALL_BASE_GAS:
        return False, f"gas_limit debe ser >= {CALL_BASE_GAS}"
    return True, "OK"


def max_cost(tx: dict) -> int:
    """Lo que el sender debe tener (además del fee): value + gas_limit * gas_price."""
    payload = tx["payload"]
    return payload.get("value", 0) + payload["gas_limit"] * payload["gas_price"]


def block_height_of(ctx: TxContext) -> int:
    """Altura que ve ``BLOCKHEIGHT``: la del bloque. En el mempool el registro pone la
    del PRÓXIMO bloque (altura + 1, P2-12), así el minero simula con la misma que verá
    la red. Sin registro (``execute`` en tests) vale 0."""
    return ctx.block_index if ctx.block_index is not None else 0


def call_code(code_hex: str, *, gas_limit: int, **env) -> Result:
    """Una llamada: ``CALL_BASE_GAS`` fijo + la ejecución en la VM (``env`` = entorno de ``run``)."""
    result = run(bytes.fromhex(code_hex), gas_limit=gas_limit - CALL_BASE_GAS, **env)
    result.gas_used += CALL_BASE_GAS
    return result


def execute_call(state: "VmState", tx: dict, ctx: TxContext) -> Result:
    """Ejecuta un CONTRACT_CALL (válido) contra ``state``. PURA: no modifica nada.

    ``accounts`` y ``vm`` la llaman con las mismas entradas y obtienen el mismo
    resultado (ver docstring del módulo).
    """
    payload = tx["payload"]
    entry = state.contracts[tx["recipient"]]
    return call_code(entry["code"], storage=entry["storage"],
                     caller=address_to_int(tx["sender"]), value=payload.get("value", 0),
                     args=tuple(payload.get("args", [])), block_height=block_height_of(ctx),
                     balance=entry["balance"], gas_limit=payload["gas_limit"])


def gas_charged(state: "VmState", tx: dict, ctx: TxContext) -> Tuple[int, Optional[Result]]:
    """(gas cobrado, resultado de la ejecución o None si es un despliegue)."""
    payload = tx["payload"]
    if tx_type_of(tx) == DEPLOY:
        return deploy_gas(payload["code"], payload.get("storage")), None
    result = execute_call(state, tx, ctx)
    return result.gas_used, result


@dataclass
class VmState:
    """Estado de la VM: contratos desplegados, sus logs y los recibos de cada TX."""
    # dirección → {creator, code (hex), storage {int: int}, balance, deployed_at, calls}
    contracts: Dict[str, dict] = field(default_factory=dict)
    logs: Dict[str, List[dict]] = field(default_factory=dict)     # dirección → últimos logs
    receipts: Dict[str, dict] = field(default_factory=dict)       # tx_id → resultado
    gas_burned: int = 0                                           # PUPB quemados en gas

    def contract(self, address: str) -> Optional[dict]:
        return self.contracts.get(address)


class ProgramContract(Contract):
    NAME = "vm"
    HANDLED_TYPES = frozenset({DEPLOY, CALL})

    def initial_state(self) -> VmState:
        return VmState()

    def validate(self, state: VmState, tx: dict, ctx: TxContext) -> Tuple[bool, str]:
        ok, reason = check_payload(tx)
        if not ok:
            return ok, reason
        recipient = tx.get("recipient")
        if tx_type_of(tx) == DEPLOY:
            expected = contract_address(tx.get("sender", ""), tx.get("nonce"))
            if recipient != expected:
                return False, f"recipient debe ser la dirección del contrato: {expected}"
            if recipient in state.contracts:
                return False, "Ya existe un contrato en esa dirección"
            return True, "OK"
        if recipient not in state.contracts:
            return False, f"Contrato inexistente: {recipient}"
        try:
            address_to_int(tx.get("sender", ""))
        except ValueError:
            return False, "sender no es una dirección UPB"
        return True, "OK"

    def apply(self, state: VmState, tx: dict, ctx: TxContext) -> VmState:
        payload, address = tx["payload"], tx["recipient"]
        gas, result = gas_charged(state, tx, ctx)
        price = payload["gas_price"]
        state.gas_burned += gas * price
        receipt = {"type": tx_type_of(tx), "contract": address, "sender": tx["sender"],
                   "gas_used": gas, "gas_price": price, "cost": gas * price,
                   "block_index": ctx.block_index}
        if result is None:                                    # despliegue
            state.contracts[address] = {
                "creator": tx["sender"], "code": payload["code"].lower(),
                "storage": {k: v for k, v in payload.get("storage", [])},
                "balance": 0, "deployed_at": ctx.block_index, "calls": 0,
            }
            receipt["status"] = "ok"
        else:
            entry = state.contracts[address]
            entry["calls"] += 1
            receipt.update(status=result.status, error=result.error,
                           return_value=result.return_value)
            if result.ok:
                entry["storage"] = result.storage
                entry["balance"] += payload.get("value", 0) - sum(a for _, a in result.transfers)
                receipt["transfers"] = [[int_to_address(to), amount]
                                        for to, amount in result.transfers]
                logs = state.logs.setdefault(address, [])
                logs.extend({"value": v, "tx_id": tx.get("tx_id", ""),
                             "block_index": ctx.block_index} for v in result.logs)
                del logs[:-MAX_LOGS_KEPT]
        state.receipts[tx.get("tx_id", "")] = receipt
        return state

    # ── Fotos de estado (P2-4): las claves de storage son int; en JSON van como texto.

    def state_to_json(self, state: VmState) -> Any:
        return {
            "contracts": {a: {**c, "storage": [[k, v] for k, v in c["storage"].items()]}
                          for a, c in state.contracts.items()},
            "logs": state.logs, "receipts": state.receipts, "gas_burned": state.gas_burned,
        }

    def state_from_json(self, data: Any) -> VmState:
        return VmState(
            contracts={a: {**c, "storage": {k: v for k, v in c["storage"]}}
                       for a, c in data["contracts"].items()},
            logs=data["logs"], receipts=data["receipts"], gas_burned=data["gas_burned"],
        )
