"""Tests de P2-11 (parte 1): la VM de pila y el ensamblador, sin cadena.

- cada opcode (la tabla de cobertura obliga a probarlos todos);
- validación de saltos (solo a JUMPDEST, nunca a datos de un PUSH);
- gas: costo exacto, sin gas, error = todo el gas_limit, REVERT = solo lo usado;
- bytecode mal formado; límites de pila, storage, logs y transferencias;
- ensamblador (etiquetas, constantes, azúcar, errores con línea) y la CLI;
- revisión AST: la VM no usa float, reloj, azar, exec ni eval;
- docs/vm.md lista todos los opcodes con su gas.
"""
import ast
import hashlib
import re
from pathlib import Path

import pytest

from blockchain.vm import machine
from blockchain.vm.asm import (
    AsmError, address_to_int, assemble, disassemble, int_to_address, opcode_names, push_bytes,
)
from blockchain.vm.machine import (
    BY_NAME, MAX_ARGS, MAX_CODE_SIZE, MAX_LOGS, MAX_STACK, MAX_STORAGE_SLOTS, MAX_TRACE,
    MAX_TRANSFERS, OPCODES, WORD_MOD, BytecodeError, decode, run,
)

RAIZ = Path(__file__).resolve().parent.parent


def ejecutar(src: str, **env):
    """Ensambla y corre ``src`` con storage vacío salvo que se indique otro."""
    code = assemble(src)
    env.setdefault("storage", {})
    return run(code, **env)


def tope(src: str, **env) -> int:
    """Valor devuelto con RETURN."""
    r = ejecutar(src + "\nRETURN", **env)
    assert r.ok, r.error
    return r.return_value


# ── Aritmética, comparación y lógica ─────────────────────────────────────────

@pytest.mark.unit
@pytest.mark.parametrize("op,a,b,esperado", [
    ("ADD", 2, 3, 5), ("ADD", WORD_MOD - 1, 2, 1),               # desborde: módulo 2^256
    ("SUB", 7, 2, 5), ("SUB", 0, 1, WORD_MOD - 1),
    ("MUL", 6, 7, 42), ("MUL", 1 << 255, 2, 0),
    ("DIV", 7, 2, 3), ("MOD", 7, 2, 1),
    ("LT", 2, 3, 1), ("LT", 3, 3, 0), ("GT", 3, 2, 1), ("GT", 2, 3, 0),
    ("EQ", 4, 4, 1), ("EQ", 4, 5, 0),
    ("AND", 0b1100, 0b1010, 0b1000), ("OR", 0b1100, 0b1010, 0b1110),
    ("XOR", 0b1100, 0b1010, 0b0110),
])
def test_operaciones_binarias(op, a, b, esperado):
    # Orden: "PUSH a; PUSH b; OP" calcula a OP b (b es el tope).
    assert tope(f"PUSH {a}\nPUSH {b}\n{op}") == esperado


@pytest.mark.unit
@pytest.mark.parametrize("op", ["DIV", "MOD"])
def test_division_por_cero_es_error(op):
    r = ejecutar(f"PUSH 1\nPUSH 0\n{op}\nSTOP", gas_limit=1000)
    assert r.status == "error" and "división por cero" in r.error
    assert r.gas_used == 1000                       # un error consume todo el gas_limit


@pytest.mark.unit
def test_unarias_y_hash():
    assert tope("PUSH 0\nISZERO") == 1 and tope("PUSH 9\nISZERO") == 0
    assert tope("PUSH 0\nNOT") == WORD_MOD - 1 and tope("PUSH 5\nNOT\nNOT") == 5
    esperado = int.from_bytes(hashlib.sha256((42).to_bytes(32, "big")).digest(), "big")
    assert tope("PUSH 42\nHASH") == esperado


# ── Entorno ──────────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_entorno_de_la_llamada():
    env = dict(caller=1234, value=50, args=(7, 8, 9), block_height=77, balance=10)
    assert tope("CALLER", **env) == 1234
    assert tope("CALLVALUE", **env) == 50
    assert tope("BLOCKHEIGHT", **env) == 77
    assert tope("ARG 2", **env) == 9
    assert tope("NARGS", **env) == 3
    assert tope("BALANCE", **env) == 60             # saldo previo + value de esta llamada
    r = ejecutar("ARG 3\nSTOP", **env)
    assert r.status == "error" and "ARG 3" in r.error


# ── Pila ─────────────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_pop_dup_swap():
    assert tope("PUSH 1\nPUSH 2\nPOP") == 1
    assert tope("PUSH 1\nPUSH 2\nDUP 2") == 1
    assert tope("PUSH 1\nPUSH 2\nPUSH 3\nSWAP 2") == 1
    assert tope("PUSH 1\nPUSH 2\nPUSH 3\nSWAP 2\nPOP\nPOP") == 3
    for src in ("POP", "PUSH 1\nDUP 2", "PUSH 1\nSWAP 1", "ADD"):
        r = ejecutar(src + "\nSTOP")
        assert r.status == "error", src


@pytest.mark.unit
def test_pila_llena():
    code = assemble("bucle:\nPUSH 1\nJUMP bucle")
    r = run(code, storage={}, gas_limit=100_000)
    assert r.status == "error" and "pila llena" in r.error
    assert r.steps < 4 * (MAX_STACK + 2)


@pytest.mark.unit
def test_push_de_32_bytes():
    assert tope(f"PUSH {WORD_MOD - 1}") == WORD_MOD - 1
    assert tope("PUSH 0x0102") == 0x0102
    assert tope("PUSH 0") == 0
    assert push_bytes(0) == bytes([0x60, 0])        # PUSH de 0 bytes vale 0


# ── Storage ──────────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_sload_sstore_y_borrado():
    previo = {1: 10}
    r = ejecutar("SLOAD 1\nADD 5\nSSTORE 1\nPUSH 3\nSSTORE 2\nPUSH 0\nSSTORE 2\n"
                 "SLOAD 9\nRETURN", storage=previo)
    assert r.ok and r.return_value == 0             # casilla inexistente = 0
    assert r.storage == {1: 15}                     # guardar 0 borra la casilla
    assert previo == {1: 10}                        # run es pura: no toca la entrada


@pytest.mark.unit
def test_storage_lleno():
    lleno = {k: 1 for k in range(MAX_STORAGE_SLOTS)}
    assert ejecutar("PUSH 2\nSSTORE 0\nSTOP", storage=lleno).ok          # casilla existente
    r = ejecutar(f"PUSH 2\nSSTORE {MAX_STORAGE_SLOTS}\nSTOP", storage=lleno)
    assert r.status == "error" and "storage lleno" in r.error


# ── Saltos ───────────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_jump_y_jumpi():
    assert tope("JUMP fin\nPUSH 1\nRETURN\nfin:\nPUSH 2") == 2
    assert tope("PUSH 0\nJUMPI fin\nPUSH 1\nRETURN\nfin:\nPUSH 2") == 1    # cond 0: sigue
    assert tope("PUSH 5\nJUMPI fin\nPUSH 1\nRETURN\nfin:\nPUSH 2") == 2    # cond ≠ 0: salta
    r = ejecutar("PUSH 0\nPUSH 0\nJUMPI\nSTOP")          # destino inválido pero no salta
    assert r.ok


@pytest.mark.unit
def test_salto_solo_a_jumpdest():
    r = ejecutar("JUMP 4\nSTOP\nSTOP\nSTOP")         # 4 no es JUMPDEST
    assert r.status == "error" and "no es JUMPDEST" in r.error
    r = ejecutar(f"JUMP {10 ** 6}\nSTOP")
    assert r.status == "error"


@pytest.mark.unit
def test_no_se_puede_saltar_a_datos_de_un_push():
    # PUSH 0x5b: el byte 0x5b (JUMPDEST) está DENTRO del dato del PUSH, en la posición 2.
    code = bytes([0x60, 1, 0x5B]) + push_bytes(2) + bytes([BY_NAME["JUMP"][0]])
    assert code[2] == BY_NAME["JUMPDEST"][0]
    r = run(code, storage={})
    assert r.status == "error" and "no es JUMPDEST" in r.error


@pytest.mark.unit
def test_fin_del_codigo_es_stop_y_stop_termina():
    r = ejecutar("PUSH 1\nSSTORE 1")
    assert r.ok and r.return_value is None and r.storage == {1: 1}
    r = ejecutar("STOP\nPUSH 1\nSSTORE 1")
    assert r.ok and r.storage == {}


# ── Logs y transferencias ────────────────────────────────────────────────────

@pytest.mark.unit
def test_log_y_limite():
    r = ejecutar("LOG 7\nLOG 8\nSTOP")
    assert r.logs == [7, 8]
    r = ejecutar("bucle:\nLOG 1\nJUMP bucle", gas_limit=100_000)
    assert r.status == "error" and f"más de {MAX_LOGS} LOG" in r.error


@pytest.mark.unit
def test_transfer():
    r = ejecutar("PUSH 30\nCALLER\nTRANSFER\nPUSH 0\nPUSH 5\nTRANSFER\nBALANCE\nRETURN",
                 caller=99, balance=40, value=5)
    assert r.ok and r.transfers == [(99, 30)]       # TRANSFER de 0 no se registra
    assert r.return_value == 15
    r = ejecutar("PUSH 41\nCALLER\nTRANSFER\nSTOP", caller=99, balance=40)
    assert r.status == "error" and "el contrato tiene 40" in r.error
    r = ejecutar(f"PUSH 1\nPUSH {1 << 128}\nTRANSFER\nSTOP", balance=40)
    assert r.status == "error" and "fuera de rango" in r.error
    r = ejecutar("bucle:\nPUSH 1\nCALLER\nTRANSFER\nJUMP bucle", balance=100, gas_limit=100_000)
    assert r.status == "error" and f"más de {MAX_TRANSFERS} TRANSFER" in r.error


# ── Terminación, REVERT y gas ────────────────────────────────────────────────

@pytest.mark.unit
def test_revert_cobra_solo_lo_usado_y_no_devuelve_cambios():
    r = ejecutar("PUSH 1\nSSTORE 1\nLOG 5\nREVERT 3", gas_limit=10_000)
    assert r.status == "revert" and r.error == "REVERT 3"
    assert r.storage == {} and r.logs == [] and r.transfers == []
    assert r.gas_used == 3 + 3 + 200 + 3 + 50 + 3 + 0


@pytest.mark.unit
def test_gas_exacto_y_sin_gas():
    # PUSH 2 (3) + PUSH 3 (3) + ADD (3) + RETURN (0) = 9
    assert ejecutar("PUSH 2\nPUSH 3\nADD\nRETURN").gas_used == 9
    assert ejecutar("PUSH 2\nPUSH 3\nADD\nRETURN", gas_limit=9).ok
    r = ejecutar("PUSH 2\nPUSH 3\nADD\nRETURN", gas_limit=8)
    assert r.status == "error" and "sin gas" in r.error and r.gas_used == 8


@pytest.mark.unit
def test_bucle_infinito_termina_por_gas():
    r = ejecutar("bucle:\nJUMP bucle", gas_limit=machine.MAX_GAS_LIMIT)
    assert r.status == "error" and "sin gas" in r.error
    assert r.gas_used == machine.MAX_GAS_LIMIT


@pytest.mark.unit
def test_traza_acotada():
    r = ejecutar("bucle:\nJUMP bucle", gas_limit=50_000, trace=True)
    assert len(r.trace) == MAX_TRACE and r.steps > MAX_TRACE
    assert r.trace[0] == {"pc": 0, "op": "JUMPDEST", "arg": None, "gas": 1, "stack": []}
    assert not ejecutar("PUSH 1\nSTOP").trace       # sin trace=True no se guarda


# ── Bytecode mal formado ─────────────────────────────────────────────────────

@pytest.mark.unit
@pytest.mark.parametrize("code,motivo", [
    (b"", "vacío"),
    (bytes([0xEE]), "desconocido"),
    (bytes([0x60]), "PUSH sin largo"),
    (bytes([0x60, 3, 1, 2]), "truncado"),
    (bytes([0x60, 33]) + bytes(33), "33 bytes"),
    (bytes([0x33]), "sin dato inmediato"),
    (bytes([0x33, MAX_ARGS]), "ARG"),
    (bytes([0x41, 0]), "DUP 0"),
    (bytes([0x42, 17]), "SWAP 17"),
    (bytes(MAX_CODE_SIZE + 1), "máximo"),
])
def test_bytecode_mal_formado(code, motivo):
    with pytest.raises(BytecodeError, match=motivo):
        decode(code)
    with pytest.raises(BytecodeError):
        run(code, storage={})


# ── Ensamblador y CLI ────────────────────────────────────────────────────────

@pytest.mark.unit
def test_ensamblador_etiquetas_constantes_y_comentarios():
    src = """
    ; comentario
    .const META 0x10     # otro comentario
    JUMP adelante        ; referencia hacia adelante
    atras: RETURN
    adelante:
        PUSH META
        JUMP atras
    """
    code = assemble(src)
    assert run(code, storage={}).return_value == 16
    texto = disassemble(code)
    assert "JUMPDEST" in texto and "PUSH 16" in texto
    # Una dirección UPB es un literal de 128 bits.
    direccion = "UPB" + "0" * 31 + "F"
    assert run(assemble(f"PUSH {direccion}\nRETURN"), storage={}).return_value == 15
    assert int_to_address(address_to_int(direccion)) == direccion


@pytest.mark.unit
@pytest.mark.parametrize("src,motivo", [
    ("FOO", "línea 1: instrucción desconocida"),
    ("STOP\nx:\nx:", "línea 3: etiqueta inválida o repetida"),
    ("CALLER 5", "no saca nada de la pila"),
    ("PUSH", "PUSH necesita un valor"),
    ("PUSH nada", "valor desconocido"),
    (f"PUSH {WORD_MOD}", "no cabe en 256 bits"),
    ("DUP", "DUP necesita un número"),
    ("ARG 300", "un byte"),
    ("ARG 20", "ARG 20"),
    ("ADD 1 2", "a lo sumo un operando"),
    (".const 1x 2", "uso: .const"),
])
def test_errores_del_ensamblador(src, motivo):
    with pytest.raises(AsmError, match=motivo):
        assemble(src)


@pytest.mark.unit
def test_cli_upbasm(tmp_path, capsys):
    from scripts.upbasm import main
    contador = str(RAIZ / "contratos_estudiantes" / "contador.upbasm")
    assert main(["ensamblar", contador]) == 0
    hexa = capsys.readouterr().out.strip()
    assert main(["desensamblar", hexa]) == 0
    assert "NARGS" in capsys.readouterr().out
    estado = tmp_path / "estado.json"
    assert main(["ejecutar", contador, "--estado", str(estado), "--args", "4"]) == 0
    assert main(["ejecutar", contador, "--estado", str(estado), "--traza"]) == 0
    salida = capsys.readouterr().out
    assert "retorno: 5" in salida and "SSTORE" in salida
    assert main(["ejecutar", hexa, "--gas", "150"]) == 1         # sin gas
    assert main(["hash", "42"]) == 0
    assert capsys.readouterr().out.strip().endswith(
        str(int.from_bytes(hashlib.sha256((42).to_bytes(32, "big")).digest(), "big")))


# ── Reglas del proyecto ──────────────────────────────────────────────────────

FUENTES_VM = [RAIZ / "blockchain" / "vm" / "machine.py", RAIZ / "blockchain" / "vm" / "asm.py",
              RAIZ / "blockchain" / "contracts" / "programs.py"]


@pytest.mark.unit
def test_la_vm_no_usa_float_reloj_azar_exec_ni_eval():
    prohibidos = {"time", "random", "uuid", "datetime", "secrets", "os", "subprocess",
                  "exec", "eval", "compile", "__import__", "open", "input", "float", "globals"}
    for ruta in FUENTES_VM:
        for nodo in ast.walk(ast.parse(ruta.read_text(encoding="utf-8"))):
            if isinstance(nodo, ast.Import):
                assert not {a.name.split(".")[0] for a in nodo.names} & prohibidos, ruta
            elif isinstance(nodo, ast.ImportFrom):
                assert (nodo.module or "").split(".")[0] not in prohibidos, ruta
            elif isinstance(nodo, ast.Name):
                assert nodo.id not in prohibidos, (ruta, nodo.id)
            elif isinstance(nodo, ast.Attribute):
                assert nodo.attr not in {"time", "now", "random", "system"}, (ruta, nodo.attr)
            elif isinstance(nodo, ast.Constant):
                assert not isinstance(nodo.value, float), (ruta, nodo.value)
            elif isinstance(nodo, ast.BinOp):
                assert not isinstance(nodo.op, ast.Div), f"división real '/' en {ruta}"


@pytest.mark.unit
def test_la_vm_es_chica():
    lineas = sum(len(p.read_text(encoding="utf-8").splitlines()) for p in FUENTES_VM[:2])
    assert lineas <= 550, lineas                  # el espíritu: ~500 líneas legibles


@pytest.mark.unit
def test_docs_listan_todos_los_opcodes_con_su_gas():
    doc = (RAIZ / "docs" / "vm.md").read_text(encoding="utf-8")
    filas = {m.group(2): (int(m.group(1), 16), int(m.group(3)))
             for m in re.finditer(r"^\| `0x([0-9A-F]{2})` \| `(\w+)` \| (\d+) \|", doc, re.M)}
    assert filas == {name: (code, gas) for code, name, gas, _, _ in OPCODES}
    assert opcode_names() == [name for _, name, _, _, _ in sorted(OPCODES)]


@pytest.mark.unit
def test_todos_los_opcodes_tienen_test():
    """Cada opcode aparece en algún test de este archivo."""
    fuente = Path(__file__).read_text(encoding="utf-8").split("def test_todos_los_opcodes")[0]
    palabras = set(re.findall("[A-Z]+", fuente))
    faltan = [name for _, name, _, _, _ in OPCODES if name not in palabras]
    assert not faltan, f"opcodes sin test: {faltan}"
