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
      Excepción: el estado de cuentas (``AccountState``, P0-9) es regla de
      CONSENSO: un bloque con una TX sin saldo o con nonce incorrecto se
      rechaza entero (ver ``AccountState.check_block``).

Determinismo: ``validate_tx``/``apply_tx`` no deben usar ``time.time()`` ni
aleatoriedad; si necesitan una fecha usan la del bloque (``block_timestamp``).

Uso:
    contrato = MiContrato()
    blockchain.register_state_listener(contrato)  # reproduce la cadena cargada
    # desde ahí la cadena llama apply_block / rebuild / check_transaction
"""
import copy
import logging
from typing import Dict, Iterable, List, Optional, Tuple

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


# ── Estado de cuentas (P0-9) ─────────────────────────────────────────────────

def _is_int(value) -> bool:
    """Entero de verdad (``True`` y ``1.0`` no cuentan): montos sin floats."""
    return isinstance(value, int) and not isinstance(value, bool)


class AccountState(ReplayState):
    """Saldo y nonce por dirección, derivados de la cadena (P0-9).

    Montos: enteros en la unidad mínima (como los satoshis de Bitcoin o el wei
    de Ethereum). Nunca floats: 0.1 + 0.2 != 0.3 y dos nodos podrían discrepar.

    Reglas (aplican a TODAS las TXs firmadas, de cualquier tipo):

        nonce   La TX número k de una dirección lleva ``nonce = k`` (la primera,
                1). Válida solo si ``nonce == nonce_confirmado(sender) + 1``.
                Así una TX firmada no se puede "reproducir" (replay) ni
                reordenar: la misma firma con el mismo nonce ya no es válida.
        fee     Entero >= 0. Se descuenta del sender y se QUEMA (sale de la
                oferta total). No hay recompensa de minado (ver P1-12), así que
                no hay a quién acreditarla sin inventar una regla nueva. Con
                fee 0 (por defecto) las credenciales funcionan sin saldo.
        saldo   ``saldo(sender) >= fee + amount`` (amount solo en transferencias).

    Tipos con efecto sobre saldos:

        TOKEN_MINT      sender = autoridad del génesis; payload {"amount": int > 0}.
                        Crea ``amount`` unidades para ``recipient``. Es la fuente
                        de la oferta sin cambiar el génesis (GENESIS_HASH); P1-12
                        la extenderá con presupuestos por emisor.
        TOKEN_TRANSFER  payload {"amount": int > 0}; mueve saldo sender → recipient.

    Los demás tipos (credenciales, DATA_RECORD, VOTE, …) solo consumen nonce y
    fee. Una TX que el contrato de credenciales ignora (p. ej. credencial
    duplicada) igual consume su nonce, como una TX fallida en Ethereum: el
    orden de las TXs de cada firmante queda fijado por la cadena.

    Consenso: a diferencia del contrato de credenciales, una TX inválida para
    este estado invalida el BLOQUE entero (``check_block``), así cada bloque
    aceptado deja a todos los nodos con los mismos saldos. Es determinista:
    depende solo del estado previo y de las TXs, en el orden del bloque.
    """

    HANDLED_TYPES = frozenset()  # se sobrescribe en handles(): aplica a todo tipo

    def __init__(self, authority_address: Optional[str] = None) -> None:
        from blockchain.core.block import GENESIS_AUTHORITY_ADDRESS
        self.authority_address = authority_address or GENESIS_AUTHORITY_ADDRESS
        super().__init__()

    def reset(self) -> None:
        self.balances: Dict[str, int] = {}
        self.nonces: Dict[str, int] = {}
        self.total_supply = 0   # Σ minado − Σ fees quemadas
        self.burned_fees = 0

    def handles(self, tx: dict) -> bool:
        return True

    # ── Consultas ─────────────────────────────────────────────────────────────

    def balance_of(self, address: str) -> int:
        return self.balances.get(address, 0)

    def nonce_of(self, address: str) -> int:
        """Nonce de la última TX confirmada de ``address`` (0 si no tiene)."""
        return self.nonces.get(address, 0)

    # ── Reglas de validez (puras: no mutan el estado) ─────────────────────────

    @staticmethod
    def _amount(tx: dict) -> int:
        """Monto que mueve la TX (0 si el tipo no mueve saldo)."""
        tx_type = getattr(tx.get("type"), "value", tx.get("type"))
        if tx_type in ("TOKEN_TRANSFER", "TOKEN_MINT"):
            payload = tx.get("payload")
            return payload.get("amount") if isinstance(payload, dict) else None
        return 0

    def validate_tx(self, tx: dict) -> Tuple[bool, str]:
        sender = tx.get("sender", "")
        tx_type = getattr(tx.get("type"), "value", tx.get("type"))
        nonce, fee = tx.get("nonce"), tx.get("fee", 0)
        if not _is_int(nonce):
            return False, "nonce debe ser un entero"
        expected = self.nonce_of(sender) + 1
        if nonce != expected:
            return False, f"Nonce inválido: esperado {expected}, recibido {nonce}"
        if not _is_int(fee) or fee < 0:
            return False, "fee debe ser un entero >= 0"
        amount = self._amount(tx)
        if tx_type in ("TOKEN_TRANSFER", "TOKEN_MINT"):
            if not _is_int(amount) or amount <= 0:
                return False, "amount debe ser un entero > 0 (unidad mínima)"
        if tx_type == "TOKEN_MINT":
            if sender != self.authority_address:
                return False, "Solo la autoridad del génesis puede emitir tokens"
            amount = 0  # el monto minado no sale del saldo del sender
        if self.balance_of(sender) < fee + amount:
            return False, (f"Saldo insuficiente: tiene {self.balance_of(sender)}, "
                           f"necesita {fee + amount}")
        return True, "OK"

    # ── Transición de estado ──────────────────────────────────────────────────

    def _apply_valid_tx(self, tx: dict, block_index: Optional[int],
                        block_timestamp: Optional[float]) -> None:
        sender, recipient = tx["sender"], tx["recipient"]
        tx_type = getattr(tx.get("type"), "value", tx.get("type"))
        fee = tx.get("fee", 0)
        self.nonces[sender] = tx["nonce"]
        self.balances[sender] = self.balance_of(sender) - fee
        self.total_supply -= fee
        self.burned_fees += fee
        amount = tx["payload"]["amount"] if tx_type in ("TOKEN_TRANSFER", "TOKEN_MINT") else 0
        if tx_type == "TOKEN_MINT":
            self.total_supply += amount
        elif tx_type == "TOKEN_TRANSFER":
            self.balances[sender] -= amount
        if amount:
            self.balances[recipient] = self.balance_of(recipient) + amount

    # ── Consenso y mempool ────────────────────────────────────────────────────

    def check_block(self, block, commit: bool = False) -> Tuple[bool, str]:
        """¿Son válidas, en orden, todas las TXs de ``block``?

        Se usa en la validación de consenso de la cadena: si alguna TX falla,
        el bloque se rechaza (no se "ignora" la TX como en el contrato). Se
        trabaja sobre una copia; con ``commit=True`` y bloque válido, la copia
        pasa a ser el estado (lo usa la validación de una cadena completa).
        La firma de cada TX ya la verificó la cadena antes de llamar aquí.
        """
        trial = copy.deepcopy(self)
        for tx in block.transactions:
            ok, reason = trial.validate_tx(tx)
            if not ok:
                return False, f"TX {str(tx.get('tx_id'))[:8]}… inválida para las cuentas: {reason}"
            trial._apply_valid_tx(tx, block.header.index, block.header.timestamp)
        if commit:
            self.__dict__.update(trial.__dict__)
            self.height = block.header.index
        return True, "OK"

    def filter_valid(self, txs: Iterable[dict]) -> List[dict]:
        """Las TXs de ``txs`` que, aplicadas en orden, serían válidas (sin mutar).

        Política local del minero/mempool (no consenso): descarta TXs caducadas
        para no armar un bloque que la red rechazaría.
        """
        trial = copy.deepcopy(self)
        out = []
        for tx in txs:
            if trial.validate_tx(tx)[0]:
                trial._apply_valid_tx(tx, None, None)
                out.append(tx)
        return out

    def check_transaction(self, tx: dict, pending: Iterable[dict] = ()) -> Tuple[bool, str]:
        """Admisión al mempool contra confirmadas + pendientes (en orden FIFO).

        Las pendientes ya pasaron firma y estas mismas reglas al entrar, así que
        se aplican sin volver a verificar ECDSA (O(m) operaciones de diccionario).
        """
        speculative = copy.deepcopy(self)
        for p in pending:
            if speculative.validate_tx(p)[0]:
                speculative._apply_valid_tx(p, None, None)
        return speculative.validate_tx(tx)

    def next_nonce(self, address: str, pending: Iterable[dict] = ()) -> int:
        """Nonce que debe llevar la próxima TX de ``address`` (confirmadas + mempool)."""
        nonce = self.nonce_of(address)
        for p in pending:
            if p.get("sender") == address and p.get("nonce") == nonce + 1:
                nonce += 1
        return nonce + 1

    def account_info(self, address: str, pending: Iterable[dict] = ()) -> dict:
        """Vista de una cuenta para la API."""
        return {
            "address": address,
            "balance": self.balance_of(address),
            "nonce": self.nonce_of(address),
            "next_nonce": self.next_nonce(address, pending),
            "height": self.height,
        }
