"""
Registro de contratos (P1-13): enruta cada TX a los contratos que la manejan
y guarda el estado CONFIRMADO de cada uno.

La cadena (``Blockchain``) lo usa en cuatro momentos:

    validar un bloque     ``check_block(block)``  → (ok, motivo, estados_nuevos)
                          sin tocar el estado confirmado; si el bloque entra,
                          ``commit(estados_nuevos, altura)``.
    arrancar con foto     ``load_states(texto)`` adopta la foto guardada en chain.db
                          (``dump_states``) y luego se reproducen solo los bloques
                          posteriores (P2-4).
    cargar / reorg        ``replay(chain)`` reproduce la cadena desde el estado
                          inicial (valida cada bloque) y ``commit`` adopta el resultado.
    admitir al mempool    ``check_transaction(tx, pendientes)`` sobre el estado
                          especulativo = confirmado + pendientes.
    armar un bloque       ``filter_valid(txs)``: las pendientes que siguen
                          siendo válidas una tras otra.

Una TX puede interesar a varios contratos (las cuentas cobran nonce y fee a
TODA TX). Para cada TX se validan primero todos los contratos interesados y
solo si todos aceptan se aplican: una TX es atómica.

Lecturas entre contratos (P1-12): el ``ctx`` de cada TX lleva ``views`` = la
copia de trabajo de TODOS los contratos, así ``ctx.view("credentials")`` ve el
estado de otro contrato tal como quedó tras las TXs anteriores (del bloque o
del mempool). Es determinista: el orden es el de la cadena y, dentro de una
TX, todos los contratos validan contra el estado previo a esa TX.

Copia al escribir: antes de que un contrato aplique su primera TX en un
bloque se copia (``deepcopy``) su estado; los contratos que el bloque no toca
no se copian. Así el estado confirmado nunca se modifica a medias.
"""
import copy
import json
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from blockchain.contracts.base import MEMPOOL, Contract, TxContext

States = Dict[str, Any]


class ContractRegistry:
    """Conjunto ordenado de contratos + su estado confirmado."""

    def __init__(self, contracts: Iterable[Contract]) -> None:
        self._contracts: Dict[str, Contract] = {}
        for contract in contracts:
            if not contract.NAME:
                raise ValueError(f"{type(contract).__name__} no define NAME")
            if contract.NAME in self._contracts:
                raise ValueError(f"Contrato duplicado: {contract.NAME}")
            self._contracts[contract.NAME] = contract
        self._states: States = self.initial_states()
        self.height = -1     # altura del último bloque reflejado en el estado

    # ── Consultas ─────────────────────────────────────────────────────────────

    @property
    def names(self) -> List[str]:
        return list(self._contracts)

    def contract(self, name: str) -> Contract:
        return self._contracts[name]

    def state(self, name: str) -> Any:
        """Estado confirmado del contrato ``name`` (solo lectura para la API).

        Cada bloque aceptado reemplaza el objeto (no lo modifica), así que
        quien lo leyó sigue viendo una foto coherente.
        """
        return self._states[name]

    def handlers(self, tx: dict) -> List[Contract]:
        """Contratos interesados en ``tx``, en orden de registro."""
        return [c for c in self._contracts.values() if c.handles(tx)]

    def initial_states(self) -> States:
        return {name: c.initial_state() for name, c in self._contracts.items()}

    # ── Núcleo: una TX sobre una copia de trabajo ─────────────────────────────

    def _try_tx(self, working: States, copied: Set[str], tx: dict,
                ctx: TxContext) -> Tuple[bool, str]:
        """Valida ``tx`` en todos sus contratos y, si todos aceptan, la aplica.

        ``working`` es la copia de trabajo (se modifica); ``copied`` son los
        contratos cuyo estado ya se copió en esta copia de trabajo.
        """
        handlers = self.handlers(tx)
        for contract in handlers:
            ok, reason = contract.validate(working[contract.NAME], tx, ctx)
            if not ok:
                return False, f"{contract.NAME}: {reason}"
        for contract in handlers:
            name = contract.NAME
            if name not in copied:
                working[name] = copy.deepcopy(working[name])
                copied.add(name)
            working[name] = contract.apply(working[name], tx, ctx)
        return True, "OK"

    def run_block(self, states: States, block) -> Tuple[bool, str, States]:
        """Aplica en orden las TXs de ``block`` sobre ``states`` (que no se modifica).

        Devuelve ``(ok, motivo, estados_nuevos)``. Una TX inválida para
        cualquier contrato invalida el bloque entero (regla de consenso).
        """
        working, copied = dict(states), set()
        ctx = TxContext.of_block(block, working)
        for tx in block.transactions:
            ok, reason = self._try_tx(working, copied, tx, ctx)
            if not ok:
                return False, f"TX {str(tx.get('tx_id'))[:8]}… inválida para {reason}", states
        return True, "OK", working

    # ── Uso desde la cadena ───────────────────────────────────────────────────

    def check_block(self, block) -> Tuple[bool, str, States]:
        """``run_block`` sobre el estado confirmado (no lo modifica)."""
        return self.run_block(self._states, block)

    def commit(self, states: States, height: int) -> None:
        """Adopta ``states`` (resultado de ``check_block`` o ``replay``) como confirmado."""
        self._states = states
        self.height = height

    def replay(self, chain: List) -> Tuple[bool, str, States]:
        """Reproduce ``chain`` desde el estado inicial (el génesis no lleva TXs de estado)."""
        states = self.initial_states()
        for block in chain[1:]:
            ok, reason, states = self.run_block(states, block)
            if not ok:
                return False, f"Bloque {block.header.index}: {reason}", states
        return True, "OK", states

    def rebuild(self, chain: List) -> None:
        """Reproduce y adopta ``chain`` (debe ser válida: lo es si la cadena la aceptó)."""
        ok, reason, states = self.replay(chain)
        if not ok:
            raise ValueError(f"La cadena no es válida para los contratos: {reason}")
        self.commit(states, len(chain) - 1)

    # ── Fotos de estado (P2-4) ────────────────────────────────────────────────

    def dump_states(self, states: States) -> str:
        """Estados de todos los contratos → texto JSON (para ``snapshots`` en chain.db).

        Sin ``sort_keys``: el orden de inserción de los dicts es parte del
        estado (es el orden de la cadena) y debe sobrevivir a la foto.
        """
        data = {name: c.state_to_json(states[name]) for name, c in self._contracts.items()}
        return json.dumps(data, ensure_ascii=False, separators=(",", ":"))

    def load_states(self, text: str) -> States:
        """Inverso de ``dump_states``. Lanza ValueError/KeyError/TypeError si no encaja."""
        data = json.loads(text)
        if list(data) != self.names:
            raise ValueError("La foto no corresponde a estos contratos")
        return {name: c.state_from_json(data[name]) for name, c in self._contracts.items()}

    def _mempool_ctx(self, working: States, timestamp: Optional[float]) -> TxContext:
        """Contexto sin bloque: ``timestamp`` es la hora ESTIMADA del próximo bloque.

        ``block_index`` es la altura del próximo bloque (``height + 1``, P2-12): las
        ventanas de elecciones por altura se validan igual en el mempool y al minar.
        """
        return TxContext(self.height + 1, MEMPOOL.block_hash, timestamp, working)

    def check_transaction(self, tx: dict, pending: Iterable[dict] = (),
                          timestamp: Optional[float] = None) -> Tuple[bool, str]:
        """¿Sería válida ``tx`` minada después de las pendientes? (admisión al mempool)

        Mismo ``validate`` que en un bloque, contra el estado especulativo.
        Las pendientes que ya no son válidas se saltan (el minero tampoco las
        incluiría). El estado confirmado no cambia. El motivo es el del contrato,
        sin prefijo, para que la API lo muestre tal cual. ``timestamp`` es la
        hora estimada del próximo bloque (la pone la cadena; ver ``TxContext``).
        """
        working, copied = dict(self._states), set()
        ctx = self._mempool_ctx(working, timestamp)
        for p in pending:
            self._try_tx(working, copied, p, ctx)
        for contract in self.handlers(tx):
            ok, reason = contract.validate(working[contract.NAME], tx, ctx)
            if not ok:
                return False, reason
        return True, "OK"

    # ── Admisión incremental (política local) ─────────────────────────────────

    def speculative_start(self) -> Tuple[States, Set[str], States]:
        """Copia de trabajo vacía sobre el estado confirmado: ``(working, copied, base)``.

        ``base`` es el objeto de estado confirmado del que parte; si la cadena
        adopta otro (bloque nuevo, reorg), la copia de trabajo ya no sirve.
        """
        return dict(self._states), set(), self._states

    def speculative_admit(self, working: States, copied: Set[str], tx: dict,
                          timestamp: Optional[float] = None) -> Tuple[bool, str]:
        """Valida ``tx`` sobre ``working`` y, si es válida, la aplica ahí mismo.

        Equivale a ``check_transaction`` pero sin reproducir las pendientes: la
        copia de trabajo ya las contiene. El motivo es el del contrato, sin prefijo.
        """
        ctx = self._mempool_ctx(working, timestamp)
        for contract in self.handlers(tx):
            ok, reason = contract.validate(working[contract.NAME], tx, ctx)
            if not ok:
                return False, reason
        self._try_tx(working, copied, tx, ctx)
        return True, "OK"

    def filter_valid(self, txs: Iterable[dict],
                     timestamp: Optional[float] = None) -> List[dict]:
        """Las TXs de ``txs`` que, aplicadas en orden, serían válidas (sin mutar).

        Política local del minero/mempool (no consenso): no armar un bloque que
        la red rechazaría por una TX que caducó (nonce usado, credencial ya
        emitida en otro bloque, voto ya contado, …). Al armar un bloque,
        ``timestamp`` es la hora del encabezado del candidato: la misma que
        verá ``check_block``.
        """
        working, copied = dict(self._states), set()
        ctx = self._mempool_ctx(working, timestamp)
        return [tx for tx in txs if self._try_tx(working, copied, tx, ctx)[0]]
