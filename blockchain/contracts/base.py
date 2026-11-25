"""
Interfaz única de contratos de UPB-Chain (P1-13).

Un contrato es un conjunto de REGLAS sobre un ESTADO derivado de la cadena:

    estado(H) = apply(... apply(apply(estado_inicial, tx_1, ctx_1), tx_2, ctx_2) ..., tx_n, ctx_n)

donde tx_1..tx_n son las TXs de los bloques 1..H, en orden. El contrato no
guarda estado propio: lo recibe y lo devuelve. Quien guarda el estado
confirmado de cada contrato es el ``ContractRegistry`` (``registry.py``), y
quien decide qué bloques entran es la cadena (``Blockchain``).

Lo que define un contrato:

    NAME             nombre único ("accounts", "credentials", "voting", …)
    HANDLED_TYPES    tipos de TX (str) que le interesan; ``None`` = todos
    initial_state()  estado vacío (antes del bloque 1)
    validate(state, tx, ctx) -> (ok, motivo)
                     ¿es válida la TX contra este estado? PURA: no modifica nada.
    apply(state, tx, ctx) -> state
                     transición de estado; solo se llama si ``validate`` dio OK.

Política única para TXs inválidas (regla de CONSENSO):
    Si ``validate`` rechaza una TX de un bloque, el BLOQUE ENTERO es inválido,
    para cualquier contrato. En el mempool, la misma ``validate`` contra el
    estado especulativo (confirmado + pendientes) hace que la API responda 400.
    Una sola función decide las dos cosas, así lo que la API acepta es lo que
    la red acepta.

Reglas de determinismo (todos los nodos deben llegar al mismo estado):
    - Nada de ``time.time()``, ``datetime.now()``, ``random`` ni ``uuid4``
      dentro de ``validate``/``apply``. La única "hora" es ``ctx.block_timestamp``.
    - Montos y contadores como ``int``; nunca ``float`` (0.1 + 0.2 != 0.3).
    - No depender del orden de iteración de un ``set``; los ``dict`` de Python
      conservan el orden de inserción, que aquí es el orden de la cadena.
    - No leer archivos, red ni variables de entorno.
    - La firma y el ``sender`` ya los verificó la cadena antes de llamar al
      contrato: ``tx["sender"]`` es quien firmó.

``apply`` puede modificar el ``state`` recibido y devolverlo: el registro
siempre le pasa una COPIA DE TRABAJO, nunca el estado confirmado. Visto desde
afuera la transición es pura: el estado confirmado solo cambia cuando el
bloque entero resultó válido (ver ``ContractRegistry.check_block``).
"""
from dataclasses import dataclass
from typing import Any, Optional, Tuple


def tx_type_of(tx: dict) -> str:
    """Tipo de una TX en dict como str (puede venir como enum o como texto)."""
    tx_type = tx.get("type")
    return getattr(tx_type, "value", tx_type)


def is_int(value) -> bool:
    """Entero de verdad (``True`` y ``1.0`` no cuentan): montos sin floats."""
    return isinstance(value, int) and not isinstance(value, bool)


@dataclass(frozen=True)
class TxContext:
    """Datos del bloque que contiene la TX (nunca el reloj del nodo).

    En el mempool la TX aún no tiene bloque: todos los campos son ``None``.
    ``block_timestamp`` es el del encabezado del bloque: igual en todos los
    nodos, así que se puede guardar o comparar, pero no hacer aritmética de
    punto flotante con él en una regla de consenso.
    """
    block_index: Optional[int] = None
    block_hash: Optional[str] = None
    block_timestamp: Optional[float] = None

    @classmethod
    def of_block(cls, block) -> "TxContext":
        return cls(block.header.index, block.hash, block.header.timestamp)


# Contexto de las TXs pendientes (admisión al mempool, armado de bloques).
MEMPOOL = TxContext()


class Contract:
    """Base de todos los contratos. Ver el docstring del módulo y ``docs/contratos.md``."""

    NAME: str = ""
    HANDLED_TYPES: Optional[frozenset] = frozenset()

    def handles(self, tx: dict) -> bool:
        """¿Le interesa esta TX al contrato? (``HANDLED_TYPES = None`` → todas)."""
        return self.HANDLED_TYPES is None or tx_type_of(tx) in self.HANDLED_TYPES

    def initial_state(self) -> Any:
        raise NotImplementedError

    def validate(self, state: Any, tx: dict, ctx: TxContext) -> Tuple[bool, str]:
        raise NotImplementedError

    def apply(self, state: Any, tx: dict, ctx: TxContext) -> Any:
        raise NotImplementedError

    def execute(self, state: Any, tx: dict, ctx: TxContext = MEMPOOL) -> Tuple[bool, str, Any]:
        """``validate`` + ``apply`` en un paso (para tests y ejemplos).

        Devuelve ``(ok, motivo, estado)``; si la TX es inválida, el estado
        devuelto es el mismo que se recibió, sin cambios.
        """
        ok, reason = self.validate(state, tx, ctx)
        if not ok:
            return False, reason, state
        return True, "OK", self.apply(state, tx, ctx)
