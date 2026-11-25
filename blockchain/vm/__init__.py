"""
VM de pila para contratos de estudiantes (P2-11).

- ``machine.py``: el intérprete (opcodes, gas, límites). Solo enteros, sin reloj,
  sin azar, sin E/S; nunca ``exec``/``eval`` de código del estudiante.
- ``asm.py``: ensamblador/desensamblador del lenguaje ``.upbasm``.

Las reglas de la cadena (``CONTRACT_DEPLOY``/``CONTRACT_CALL``, cobro de gas,
direcciones de contrato) están en ``blockchain/contracts/programs.py``.
Ver ``docs/vm.md``.
"""
from blockchain.vm.machine import (  # noqa: F401
    OPCODES, BytecodeError, Result, VmError, decode, run, validate_code,
)
from blockchain.vm.asm import AsmError, assemble, disassemble  # noqa: F401
