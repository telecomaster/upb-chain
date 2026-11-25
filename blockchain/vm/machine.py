"""
Máquina virtual de pila de UPB-Chain (P2-11): ejecuta el bytecode de los contratos
de estudiantes. Nunca se ejecuta Python del estudiante (ni ``exec`` ni ``eval``):
el contrato es una lista de bytes que este intérprete recorre, instrucción por
instrucción, con un costo de gas fijo por instrucción.

Modelo (ver ``docs/vm.md``):

    palabra   entero sin signo de 256 bits. La aritmética es MÓDULO 2**256 (como la
              EVM): 0 - 1 = 2**256 - 1. Es a propósito: el desborde silencioso es un
              error clásico de contratos que conviene ver en clase. Dividir por 0 es
              un error de ejecución.
    pila      a lo sumo ``MAX_STACK`` palabras.
    storage   dict palabra → palabra, propio de cada contrato y persistente entre
              llamadas. Guardar 0 borra la casilla. A lo sumo ``MAX_STORAGE_SLOTS``.
    entorno   CALLER (quien firmó la TX), CALLVALUE (PUPB enviados), BLOCKHEIGHT
              (altura del bloque, nunca el reloj), ARG n (argumentos de la llamada),
              BALANCE (PUPB que tiene el contrato).
    salida    STOP/RETURN = éxito; REVERT = fracaso pedido por el contrato; cualquier
              otro error (gas, pila, salto, división por 0, saldo) = fracaso.

Determinismo: solo enteros; sin reloj, sin azar, sin E/S, sin llamadas a otros
contratos (v1). La misma entrada da siempre el mismo resultado en todos los nodos.

Codificación: cada instrucción es 1 byte de opcode. Las que llevan dato inmediato:
``PUSH`` (1 byte de largo L ∈ [0, 32] + L bytes big-endian), ``ARG``/``DUP``/``SWAP``
(1 byte). Los saltos van a posiciones de byte que deben ser un ``JUMPDEST``.
"""
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

WORD_BITS = 256
WORD_MOD = 1 << WORD_BITS
ADDRESS_BITS = 128            # direcciones "UPB" + 32 hex = 128 bits

MAX_CODE_SIZE = 4096          # bytes de bytecode por contrato
MAX_STACK = 256
MAX_STORAGE_SLOTS = 256       # casillas no nulas por contrato
MAX_ARGS = 16
MAX_LOGS = 16                 # LOG por llamada
MAX_TRANSFERS = 16            # TRANSFER por llamada
MAX_TRACE = 500               # pasos guardados en la traza (solo simulación)
MAX_GAS_LIMIT = 200_000      # por TX: acota el trabajo de cada nodo
MAX_IMMEDIATE = 32            # bytes de un PUSH
MAX_DUP_SWAP = 16


class BytecodeError(ValueError):
    """Bytecode mal formado: el despliegue es inválido (la TX no entra)."""


class VmError(Exception):
    """Error de ejecución: la llamada fracasa (se revierte y se cobra todo el gas)."""


# ── Tabla de opcodes: (código, nombre, gas, bytes inmediatos, descripción) ────
# ``imm``: 0 = sin dato; 1 = un byte (ARG, DUP, SWAP); -1 = PUSH (largo + bytes).
OPCODES: List[Tuple[int, str, int, int, str]] = [
    (0x00, "STOP",        0, 0, "termina con éxito, sin valor"),
    (0x01, "ADD",         3, 0, "a b → a+b (mód 2^256)"),
    (0x02, "SUB",         3, 0, "a b → a−b (mód 2^256)"),
    (0x03, "MUL",         5, 0, "a b → a·b (mód 2^256)"),
    (0x04, "DIV",         5, 0, "a b → a // b (b = 0 es error)"),
    (0x05, "MOD",         5, 0, "a b → a % b (b = 0 es error)"),
    (0x10, "LT",          3, 0, "a b → 1 si a < b, si no 0"),
    (0x11, "GT",          3, 0, "a b → 1 si a > b, si no 0"),
    (0x12, "EQ",          3, 0, "a b → 1 si a = b, si no 0"),
    (0x13, "ISZERO",      3, 0, "a → 1 si a = 0, si no 0"),
    (0x14, "AND",         3, 0, "a b → a AND b (bit a bit)"),
    (0x15, "OR",          3, 0, "a b → a OR b"),
    (0x16, "XOR",         3, 0, "a b → a XOR b"),
    (0x17, "NOT",         3, 0, "a → NOT a (256 bits)"),
    (0x20, "HASH",       30, 0, "a → sha256(a en 32 bytes big-endian)"),
    (0x30, "CALLER",      2, 0, "→ dirección de quien firmó la TX (entero de 128 bits)"),
    (0x31, "CALLVALUE",   2, 0, "→ PUPB enviados con la llamada"),
    (0x32, "BLOCKHEIGHT", 2, 0, "→ altura del bloque (no hay reloj)"),
    (0x33, "ARG",         3, 1, "→ argumento n de la llamada (n inmediato)"),
    (0x34, "NARGS",       2, 0, "→ cantidad de argumentos"),
    (0x35, "BALANCE",     5, 0, "→ PUPB que tiene el contrato (incluye CALLVALUE)"),
    (0x40, "POP",         2, 0, "a →"),
    (0x41, "DUP",         3, 1, "copia el n-ésimo de arriba (1 = el tope)"),
    (0x42, "SWAP",        3, 1, "intercambia el tope con el (n+1)-ésimo"),
    (0x50, "SLOAD",      50, 0, "clave → storage[clave] (0 si no existe)"),
    (0x51, "SSTORE",    200, 0, "valor clave → (storage[clave] = valor)"),
    (0x56, "JUMP",        8, 0, "destino → salta (debe ser JUMPDEST)"),
    (0x57, "JUMPI",      10, 0, "cond destino → salta si cond ≠ 0"),
    (0x5B, "JUMPDEST",    1, 0, "marca un destino de salto válido"),
    (0x60, "PUSH",        3, -1, "→ constante (hasta 32 bytes)"),
    (0xA0, "LOG",        50, 0, "a → registra a en los logs del contrato"),
    (0xF0, "TRANSFER",  100, 0, "monto dirección → envía PUPB del contrato"),
    (0xF3, "RETURN",      0, 0, "a → termina con éxito y devuelve a"),
    (0xFD, "REVERT",      0, 0, "código → fracasa: revierte todo, cobra el gas usado"),
]
BY_CODE = {code: (name, gas, imm) for code, name, gas, imm, _ in OPCODES}
BY_NAME = {name: (code, gas, imm) for code, name, gas, imm, _ in OPCODES}


# Operaciones binarias: sacan b (tope) y a (debajo) y apilan a ∘ b, módulo 2**256.
BINARY = {
    "ADD": lambda a, b: a + b,
    "SUB": lambda a, b: a - b,
    "MUL": lambda a, b: a * b,
    "DIV": lambda a, b: a // b,
    "MOD": lambda a, b: a % b,
    "LT": lambda a, b: int(a < b),
    "GT": lambda a, b: int(a > b),
    "EQ": lambda a, b: int(a == b),
    "AND": lambda a, b: a & b,
    "OR": lambda a, b: a | b,
    "XOR": lambda a, b: a ^ b,
}


@dataclass(frozen=True)
class Instr:
    pc: int            # posición en bytes
    name: str
    arg: Optional[int]  # dato inmediato (PUSH/ARG/DUP/SWAP) o None
    size: int          # bytes que ocupa


def decode(code: bytes) -> List[Instr]:
    """Bytecode → instrucciones. Lanza ``BytecodeError`` si está mal formado."""
    if not code:
        raise BytecodeError("bytecode vacío")
    if len(code) > MAX_CODE_SIZE:
        raise BytecodeError(f"bytecode de {len(code)} bytes (máximo {MAX_CODE_SIZE})")
    out, pc = [], 0
    while pc < len(code):
        op = code[pc]
        if op not in BY_CODE:
            raise BytecodeError(f"opcode desconocido 0x{op:02x} en {pc}")
        name, _, imm = BY_CODE[op]
        arg, size = None, 1
        if imm == -1:
            if pc + 1 >= len(code):
                raise BytecodeError(f"PUSH sin largo en {pc}")
            n = code[pc + 1]
            if n > MAX_IMMEDIATE:
                raise BytecodeError(f"PUSH de {n} bytes en {pc} (máximo {MAX_IMMEDIATE})")
            if pc + 2 + n > len(code):
                raise BytecodeError(f"PUSH truncado en {pc}")
            arg, size = int.from_bytes(code[pc + 2:pc + 2 + n], "big"), 2 + n
        elif imm == 1:
            if pc + 1 >= len(code):
                raise BytecodeError(f"{name} sin dato inmediato en {pc}")
            arg, size = code[pc + 1], 2
            if name == "ARG" and arg >= MAX_ARGS:
                raise BytecodeError(f"ARG {arg} en {pc} (máximo {MAX_ARGS - 1})")
            if name in ("DUP", "SWAP") and not 1 <= arg <= MAX_DUP_SWAP:
                raise BytecodeError(f"{name} {arg} en {pc} (debe ser 1..{MAX_DUP_SWAP})")
        out.append(Instr(pc, name, arg, size))
        pc += size
    return out


def validate_code(code: bytes) -> None:
    """Valida el bytecode al desplegar (``BytecodeError`` si no sirve)."""
    decode(code)


@dataclass
class Result:
    """Resultado de una ejecución. ``storage``/``logs``/``transfers`` solo valen si ``ok``."""
    status: str                        # "ok" | "revert" | "error"
    gas_used: int
    error: str = ""
    return_value: Optional[int] = None
    storage: Dict[int, int] = field(default_factory=dict)
    logs: List[int] = field(default_factory=list)
    transfers: List[Tuple[int, int]] = field(default_factory=list)   # (dirección, monto)
    trace: List[dict] = field(default_factory=list)
    steps: int = 0

    @property
    def ok(self) -> bool:
        return self.status == "ok"


def _word(value: int) -> int:
    return value % WORD_MOD


def run(code: bytes, *, storage: Dict[int, int], caller: int = 0, value: int = 0,
        args: Tuple[int, ...] = (), block_height: int = 0, balance: int = 0,
        gas_limit: int = MAX_GAS_LIMIT, trace: bool = False) -> Result:
    """Ejecuta ``code`` con el entorno dado. PURA: no modifica ``storage``.

    ``balance`` es lo que tenía el contrato ANTES de la llamada; ``value`` se suma al
    empezar (si la llamada fracasa, la cadena no mueve nada). Gas: cada instrucción
    cobra su costo antes de ejecutarse; si no alcanza, error "sin gas".
    """
    program = decode(code)
    at = {ins.pc: i for i, ins in enumerate(program)}            # pc → índice
    jumpdests = {ins.pc for ins in program if ins.name == "JUMPDEST"}
    stack: List[int] = []
    store = dict(storage)
    logs: List[int] = []
    transfers: List[Tuple[int, int]] = []
    steps_trace: List[dict] = []
    held = balance + value
    gas, i, steps = 0, 0, 0

    def pop() -> int:
        if not stack:
            raise VmError("pila vacía")
        return stack.pop()

    def push(v: int) -> None:
        if len(stack) >= MAX_STACK:
            raise VmError(f"pila llena ({MAX_STACK})")
        stack.append(_word(v))

    def jump_to(dest: int) -> int:
        if dest not in jumpdests:
            raise VmError(f"salto a {dest}: no es JUMPDEST")
        return at[dest]

    def finish(status: str, error: str = "", ret: Optional[int] = None, used: int = 0) -> Result:
        if status != "ok":
            return Result(status, used, error, ret, trace=steps_trace, steps=steps)
        return Result(status, used, "", ret, store, logs, transfers, steps_trace, steps)

    try:
        while True:
            if i >= len(program):                     # fin del código = STOP
                return finish("ok", used=gas)
            ins = program[i]
            cost = BY_NAME[ins.name][1]
            if gas + cost > gas_limit:
                raise VmError(f"sin gas en {ins.pc} ({ins.name})")
            gas += cost
            steps += 1
            if trace and len(steps_trace) < MAX_TRACE:
                steps_trace.append({"pc": ins.pc, "op": ins.name, "arg": ins.arg,
                                    "gas": gas, "stack": stack[-8:]})
            i += 1
            op = ins.name
            if op == "STOP":
                return finish("ok", used=gas)
            elif op in BINARY:
                b, a = pop(), pop()                   # a quedó debajo de b
                if op in ("DIV", "MOD") and b == 0:
                    raise VmError("división por cero")
                push(BINARY[op](a, b))
            elif op == "ISZERO":
                push(int(pop() == 0))
            elif op == "NOT":
                push(WORD_MOD - 1 - pop())
            elif op == "HASH":
                push(int.from_bytes(hashlib.sha256(pop().to_bytes(32, "big")).digest(), "big"))
            elif op == "CALLER":
                push(caller)
            elif op == "CALLVALUE":
                push(value)
            elif op == "BLOCKHEIGHT":
                push(block_height)
            elif op == "ARG":
                if ins.arg >= len(args):
                    raise VmError(f"ARG {ins.arg}: la llamada trae {len(args)} argumentos")
                push(args[ins.arg])
            elif op == "NARGS":
                push(len(args))
            elif op == "BALANCE":
                push(held)
            elif op == "POP":
                pop()
            elif op == "DUP":
                if ins.arg > len(stack):
                    raise VmError(f"DUP {ins.arg} con {len(stack)} en la pila")
                push(stack[-ins.arg])
            elif op == "SWAP":
                if ins.arg >= len(stack):
                    raise VmError(f"SWAP {ins.arg} con {len(stack)} en la pila")
                stack[-1], stack[-1 - ins.arg] = stack[-1 - ins.arg], stack[-1]
            elif op == "SLOAD":
                push(store.get(pop(), 0))
            elif op == "SSTORE":
                key, val = pop(), pop()
                if val == 0:
                    store.pop(key, None)
                else:
                    if key not in store and len(store) >= MAX_STORAGE_SLOTS:
                        raise VmError(f"storage lleno ({MAX_STORAGE_SLOTS} casillas)")
                    store[key] = val
            elif op == "JUMP":
                i = jump_to(pop())
            elif op == "JUMPI":
                dest, cond = pop(), pop()
                if cond != 0:
                    i = jump_to(dest)
            elif op == "JUMPDEST":
                pass
            elif op == "PUSH":
                push(ins.arg)
            elif op == "LOG":
                if len(logs) >= MAX_LOGS:
                    raise VmError(f"más de {MAX_LOGS} LOG en una llamada")
                logs.append(pop())
            elif op == "TRANSFER":
                to, amount = pop(), pop()
                if to >= 1 << ADDRESS_BITS:
                    raise VmError("TRANSFER: dirección fuera de rango (128 bits)")
                if amount > held:
                    raise VmError(f"TRANSFER de {amount}: el contrato tiene {held}")
                if len(transfers) >= MAX_TRANSFERS:
                    raise VmError(f"más de {MAX_TRANSFERS} TRANSFER en una llamada")
                held -= amount
                if amount:
                    transfers.append((to, amount))
            elif op == "RETURN":
                return finish("ok", ret=pop(), used=gas)
            elif op == "REVERT":
                return finish("revert", f"REVERT {pop()}", used=gas)
    except VmError as e:
        # Error de ejecución: se consume TODO el gas_limit (como la EVM); REVERT no.
        return finish("error", str(e), used=gas_limit)
