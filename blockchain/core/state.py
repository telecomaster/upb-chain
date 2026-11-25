"""
Estado derivado de la cadena (P0-6): "estado = reproducción de las TXs confirmadas".

Idea central (la misma que usan Bitcoin y Ethereum):

    estado(H) = apply(apply(... apply(estado_vacío, tx_1) ...), tx_n)

donde tx_1..tx_n son las TXs de los bloques 1..H en orden. Nada de lo que hace
la API muta el estado directamente: la API solo pone TXs firmadas en el mempool,
y el estado cambia cuando un bloque que las contiene se agrega a la cadena.

Consecuencias:
    - Reiniciar el nodo = volver a reproducir chain.json → mismo estado.
    - Dos nodos con la misma cadena derivan exactamente el mismo estado.
    - Ante un reorg (replace_chain) se reconstruye todo desde el génesis
      (O(H·n); simple y explicable, suficiente para una red académica).

Reglas de validez:
    - Admisión al mempool (``check_transaction``): se valida la TX contra el
      estado confirmado MÁS las TXs pendientes (estado especulativo); si no es
      válida, la API responde 400.
    - Reproducción (``apply_block``): una TX inválida para el estado se ignora
      (no se aplica) y se registra en el log. Como la decisión solo depende del
      estado previo y de la TX, todos los nodos ignoran las mismas TXs.

Determinismo: ``validate_tx``/``apply_tx`` no deben usar ``time.time()`` ni
aleatoriedad; si necesitan una fecha usan la del bloque (``block_timestamp``).

Uso:
    contrato = MiContrato()
    blockchain.register_state_listener(contrato)  # reproduce la cadena cargada
    # desde ahí la cadena llama apply_block / rebuild / check_transaction
"""
import copy
import logging
from typing import Iterable, List, Optional, Tuple

logger = logging.getLogger("upb_chain.state")


class ReplayState:
    """Base para estados que se derivan reproduciendo TXs confirmadas.

    Las subclases definen:
        HANDLED_TYPES       → tipos de TX que les interesan (valores str)
        reset()             → deja el estado vacío
        validate_tx(tx)     → (ok, motivo) contra el estado actual, sin mutarlo
        _apply_valid_tx(tx, block_index, block_timestamp) → aplica una TX ya validada
    """

    HANDLED_TYPES: frozenset = frozenset()

    def __init__(self) -> None:
        self.height = -1        # altura del último bloque reproducido
        self.reset()

    # ── A implementar por la subclase ─────────────────────────────────────────

    def reset(self) -> None:
        raise NotImplementedError

    def validate_tx(self, tx: dict) -> Tuple[bool, str]:
        raise NotImplementedError

    def _apply_valid_tx(self, tx: dict, block_index: Optional[int],
                        block_timestamp: Optional[float]) -> None:
        raise NotImplementedError

    # ── Transición de estado ──────────────────────────────────────────────────

    def handles(self, tx: dict) -> bool:
        tx_type = tx.get("type")
        return getattr(tx_type, "value", tx_type) in self.HANDLED_TYPES

    @staticmethod
    def _authenticated(tx: dict) -> Tuple[bool, str]:
        """Validez de consenso de la TX: firma y sender, sin depender del reloj (P0-3)."""
        from blockchain.core.transaction import Transaction
        try:
            return Transaction.from_dict(tx).is_consensus_valid()
        except (KeyError, ValueError, TypeError):
            return False, "TX malformada"

    def apply_tx(self, tx: dict, block_index: Optional[int] = None,
                 block_timestamp: Optional[float] = None) -> Tuple[bool, str]:
        """apply(estado, tx): valida y, si es válida, aplica. Si no, la ignora."""
        if not self.handles(tx):
            return True, "No aplica a este estado"
        ok, reason = self._authenticated(tx)
        if ok:
            ok, reason = self.validate_tx(tx)
        if not ok:
            logger.info(f"{type(self).__name__}: TX {str(tx.get('tx_id'))[:8]}… ignorada: {reason}")
            return False, reason
        self._apply_valid_tx(tx, block_index, block_timestamp)
        return True, "OK"

    def apply_block(self, block) -> None:
        """Aplica en orden las TXs de un bloque recién agregado a la cadena."""
        for tx in block.transactions:
            self.apply_tx(tx, block.header.index, block.header.timestamp)
        self.height = block.header.index

    def rebuild(self, chain: List) -> None:
        """Reproduce la cadena completa desde un estado vacío (inicio y reorg)."""
        self.reset()
        self.height = -1
        for block in chain:
            if block.header.index == 0:      # el génesis no lleva TXs de estado
                self.height = 0
                continue
            self.apply_block(block)

    # ── Admisión al mempool ───────────────────────────────────────────────────

    def check_transaction(self, tx: dict, pending: Iterable[dict] = ()) -> Tuple[bool, str]:
        """¿Sería válida ``tx`` si se minara después de las TXs pendientes?

        Se trabaja sobre una copia: el estado confirmado no cambia.
        """
        if not self.handles(tx):
            return True, "OK"
        speculative = copy.deepcopy(self)
        for p in pending:
            speculative.apply_tx(p)
        return speculative.validate_tx(tx)
