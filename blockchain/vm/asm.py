"""
Ensamblador y desensamblador de la VM de UPB-Chain (P2-11).

Los estudiantes escriben archivos ``.upbasm``; este módulo los convierte en el
bytecode que va en la TX ``CONTRACT_DEPLOY``. Sintaxis (una instrucción por línea):

    ; comentario (también con #)
    .const META 100          ; constante con nombre
    inicio:                  ; etiqueta: emite un JUMPDEST y vale su posición en bytes
        PUSH 5               ; decimal, 0x hexadecimal, una dirección UPB… o un nombre
        ARG 0                ; dato inmediato: ARG n, DUP n, SWAP n
        JUMPI fin            ; azúcar: "OP x" = "PUSH x" + "OP"
        SSTORE META          ;   (solo para instrucciones que sacan algo de la pila)
    fin:
        STOP

Las etiquetas se codifican siempre como ``PUSH`` de 2 bytes (el código no pasa de
4096 bytes), así el tamaño de cada línea se conoce en la primera pasada.
"""
import re
from typing import Dict, List, Tuple

from blockchain.vm.machine import (
    ADDRESS_BITS, BY_CODE, BY_NAME, WORD_MOD, BytecodeError, decode,
)

# Instrucciones que no sacan nada de la pila: no admiten el azúcar "OP x".
NO_INPUT = {"STOP", "CALLER", "CALLVALUE", "BLOCKHEIGHT", "NARGS", "BALANCE", "JUMPDEST"}
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class AsmError(ValueError):
    """Error de ensamblado, con número de línea."""


def address_to_int(address: str) -> int:
    """``"UPB" + 32 hex`` → entero de 128 bits (lo que apila ``CALLER``)."""
    body = address[3:]
    if not (address[:3] == "UPB" and len(body) == 32
            and all(c in "0123456789abcdefABCDEF" for c in body)):
        raise ValueError(f"dirección inválida: {address!r}")
    return int(body, 16)


def int_to_address(value: int) -> str:
    """Inverso de ``address_to_int`` (destino de ``TRANSFER``)."""
    if not 0 <= value < 1 << ADDRESS_BITS:
        raise ValueError("dirección fuera de rango (128 bits)")
    return "UPB" + format(value, "032X")


def push_bytes(value: int, width: int = 0) -> bytes:
    """``PUSH`` de ``value``: opcode, largo y bytes big-endian (mínimos o ``width``)."""
    n = width or (value.bit_length() + 7) // 8
    return bytes([BY_NAME["PUSH"][0], n]) + value.to_bytes(n, "big")


def _strip(line: str) -> str:
    for mark in (";", "#"):
        line = line.split(mark, 1)[0]
    return line.strip()


def _literal(token: str, names: Dict[str, int]) -> int:
    """Número, dirección UPB o nombre (constante/etiqueta) → entero."""
    if token in names:
        return names[token]
    if token.startswith("UPB") and len(token) == 35:
        return address_to_int(token)
    try:
        value = int(token, 16) if token.lower().startswith("0x") else int(token, 10)
    except ValueError:
        raise AsmError(f"valor desconocido: {token}") from None
    if not 0 <= value < WORD_MOD:
        raise AsmError(f"{token} no cabe en 256 bits sin signo")
    return value


def _parse(source: str) -> List[Tuple[int, str, List[str]]]:
    """Líneas útiles → [(n.º de línea, palabra, operandos)]."""
    out = []
    for n, raw in enumerate(source.splitlines(), 1):
        line = _strip(raw)
        while line and ":" in line.split()[0]:          # una o más etiquetas
            label, _, line = line.partition(":")
            out.append((n, label.strip() + ":", []))
            line = line.strip()
        if line:
            word, *ops = line.split()
            out.append((n, word, ops))
    return out


def assemble(source: str) -> bytes:
    """Texto ``.upbasm`` → bytecode. Lanza ``AsmError`` con el número de línea."""
    lines = _parse(source)
    labels = {word[:-1] for _, word, _ in lines if word.endswith(":")}
    names: Dict[str, int] = {}
    # Pasada 1: constantes, posición de cada etiqueta y tamaño de cada línea.
    pc = 0
    for n, word, ops in lines:
        try:
            if word.endswith(":"):
                label = word[:-1]
                if not _NAME.match(label) or label in names:
                    raise AsmError(f"etiqueta inválida o repetida: {label}")
                names[label] = pc
                pc += 1                                  # cada etiqueta emite un JUMPDEST
            elif word.lower() == ".const":
                if len(ops) != 2 or not _NAME.match(ops[0]) or ops[0] in names or ops[0] in labels:
                    raise AsmError("uso: .const NOMBRE valor (nombre nuevo)")
                names[ops[0]] = _literal(ops[1], names)
            else:
                pc += len(_emit(word.upper(), ops, names, labels, sizing=True))
        except (AsmError, ValueError) as e:
            raise AsmError(f"línea {n}: {e}") from None
    # Pasada 2: emitir bytes (ya se conocen todas las etiquetas).
    code = bytearray()
    for n, word, ops in lines:
        if word.endswith(":"):
            code.append(BY_NAME["JUMPDEST"][0])
        elif word.lower() != ".const":
            try:
                code += _emit(word.upper(), ops, names, labels)
            except (AsmError, ValueError) as e:
                raise AsmError(f"línea {n}: {e}") from None
    try:
        decode(bytes(code))                              # misma validación que al desplegar
    except BytecodeError as e:
        raise AsmError(str(e)) from None
    return bytes(code)


def _emit(op: str, ops: List[str], names: Dict[str, int], labels: set,
          sizing: bool = False) -> bytes:
    """Bytes de una línea. ``sizing``: primera pasada (una etiqueta puede no tener valor aún)."""
    if op not in BY_NAME:
        raise AsmError(f"instrucción desconocida: {op}")
    code, _, imm = BY_NAME[op]
    if len(ops) > 1:
        raise AsmError(f"{op} lleva a lo sumo un operando")
    if imm == -1 or (imm == 0 and ops):                  # PUSH x, o azúcar "OP x"
        if not ops:
            raise AsmError("PUSH necesita un valor")
        if op in NO_INPUT:
            raise AsmError(f"{op} no saca nada de la pila: no lleva operando")
        token = ops[0]
        if token in labels:                              # etiqueta: siempre 2 bytes
            pushed = push_bytes(0 if sizing else names[token], 2)
        else:
            pushed = push_bytes(_literal(token, names))
        return pushed if imm == -1 else pushed + bytes([code])
    if imm == 1:
        if len(ops) != 1:
            raise AsmError(f"{op} necesita un número (p. ej. {op} 1)")
        value = _literal(ops[0], names)
        if value > 255:
            raise AsmError(f"{op} {value}: el dato inmediato es un byte")
        return bytes([code, value])
    return bytes([code])


def disassemble(code: bytes) -> str:
    """Bytecode → texto legible, una instrucción por línea con su posición."""
    lines = []
    for ins in decode(code):
        arg = "" if ins.arg is None else (f" {ins.arg}" if ins.name != "PUSH" or ins.arg < 1 << 64
                                          else f" 0x{ins.arg:x}")
        lines.append(f"{ins.pc:04d}: {ins.name}{arg}")
    return "\n".join(lines)


def opcode_names() -> List[str]:
    """Nombres de todas las instrucciones, en orden de opcode."""
    return [BY_CODE[c][0] for c in sorted(BY_CODE)]
