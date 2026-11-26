"""
upbasm: ensamblar, desensamblar y probar contratos de la VM de UPB-Chain (P2-11)
sin nodo ni cadena. El "estado" es un archivo JSON local (storage y saldo).

Uso (desde la raíz del repo):
    venv\\Scripts\\python.exe scripts\\upbasm.py ensamblar contratos_estudiantes\\contador.upbasm
    venv\\Scripts\\python.exe scripts\\upbasm.py desensamblar 6001...
    venv\\Scripts\\python.exe scripts\\upbasm.py ejecutar contratos_estudiantes\\contador.upbasm --args 5 --traza
    venv\\Scripts\\python.exe scripts\\upbasm.py ejecutar colecta.upbasm --estado estado.json \\
        --storage 2=10 --args 1 --value 30 --altura 3 --caller UPB0123...
    venv\\Scripts\\python.exe scripts\\upbasm.py hash 42

Con ``--estado`` el storage y el saldo resultantes se guardan en ese archivo (solo si la
llamada terminó bien), así se pueden encadenar llamadas como en la cadena.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blockchain.contracts.programs import call_code, deploy_gas  # noqa: E402
from blockchain.vm import AsmError, BytecodeError, assemble, disassemble  # noqa: E402
from blockchain.vm.asm import address_to_int, int_to_address  # noqa: E402
from blockchain.vm.machine import MAX_GAS_LIMIT  # noqa: E402


def _word(text: str) -> int:
    if text.startswith("UPB"):
        return address_to_int(text)
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def _code(fuente: str) -> bytes:
    """Archivo .upbasm, archivo con hex o hex directo → bytecode."""
    path = Path(fuente)
    if path.is_file():
        text = path.read_text(encoding="utf-8")
        return assemble(text) if path.suffix == ".upbasm" else bytes.fromhex(text.strip())
    return bytes.fromhex(fuente)


def cmd_ensamblar(a) -> int:
    code = _code(a.fuente)
    print(code.hex())
    print(f"; {len(code)} bytes, gas de despliegue (sin storage) = {deploy_gas(code.hex(), [])}",
          file=sys.stderr)
    return 0


def cmd_desensamblar(a) -> int:
    print(disassemble(_code(a.fuente)))
    return 0


def cmd_hash(a) -> int:
    import hashlib
    valor = _word(a.valor)
    print(int.from_bytes(hashlib.sha256(valor.to_bytes(32, "big")).digest(), "big"))
    return 0


def cmd_ejecutar(a) -> int:
    code = _code(a.fuente)
    estado = {"storage": [], "balance": 0}
    ruta = Path(a.estado) if a.estado else None
    if ruta and ruta.is_file():
        estado = json.loads(ruta.read_text(encoding="utf-8"))
    storage = {k: v for k, v in estado["storage"]}
    for par in a.storage:
        k, _, v = par.partition("=")
        storage[_word(k)] = _word(v)
    r = call_code(code.hex(), storage=storage, caller=_word(a.caller) if a.caller else 0,
                  value=a.value, args=tuple(_word(x) for x in a.args), block_height=a.altura,
                  balance=estado["balance"], gas_limit=a.gas, trace=a.traza)
    if a.traza:
        for paso in r.trace:
            arg = "" if paso["arg"] is None else f" {paso['arg']}"
            print(f"{paso['pc']:04d}  {paso['op'] + arg:<16} gas={paso['gas']:<6} "
                  f"pila (antes)={paso['stack']}")
    print(f"estado: {r.status}" + (f" ({r.error})" if r.error else ""))
    print(f"gas usado: {r.gas_used} (incluye el fijo de la llamada)")
    if r.return_value is not None:
        print(f"retorno: {r.return_value}")
    if r.ok:
        print(f"storage: {dict(r.storage)}")
        if r.logs:
            print(f"logs: {r.logs}")
        for to, monto in r.transfers:
            print(f"transferencia: {monto} PUPB → {int_to_address(to)}")
        if ruta:
            saldo = estado["balance"] + a.value - sum(m for _, m in r.transfers)
            ruta.write_text(json.dumps({"storage": [[k, v] for k, v in r.storage.items()],
                                        "balance": saldo}), encoding="utf-8")
    return 0 if r.ok else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Ensamblador y VM local de UPB-Chain (P2-11)")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("ensamblar", help=".upbasm → hex")
    s.add_argument("fuente")
    s.set_defaults(f=cmd_ensamblar)
    s = sub.add_parser("desensamblar", help="hex → texto")
    s.add_argument("fuente")
    s.set_defaults(f=cmd_desensamblar)
    s = sub.add_parser("hash", help="HASH de un valor, como el opcode HASH")
    s.add_argument("valor")
    s.set_defaults(f=cmd_hash)
    s = sub.add_parser("ejecutar", help="corre una llamada contra un estado local")
    s.add_argument("fuente")
    s.add_argument("--args", nargs="*", default=[])
    s.add_argument("--value", type=int, default=0)
    s.add_argument("--caller", default=None)
    s.add_argument("--altura", type=int, default=1)
    s.add_argument("--gas", type=int, default=50_000)
    s.add_argument("--storage", nargs="*", default=[], help="clave=valor (se suma al estado)")
    s.add_argument("--estado", default=None, help="archivo JSON con storage y saldo")
    s.add_argument("--traza", action="store_true")
    s.set_defaults(f=cmd_ejecutar)
    a = p.parse_args(argv)
    if getattr(a, "gas", 1) > MAX_GAS_LIMIT:
        p.error(f"--gas a lo sumo {MAX_GAS_LIMIT}")
    try:
        return a.f(a)
    except (AsmError, BytecodeError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    for _f in (sys.stdout, sys.stderr):  # flechas y tildes con salida redirigida en Windows
        if hasattr(_f, "reconfigure"):
            _f.reconfigure(encoding="utf-8")
    sys.exit(main())
