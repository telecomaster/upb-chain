"""
Contrato de votación (P1-13, ponderada en P2-12): el contrato de REFERENCIA para copiar.

Es chico y sigue la interfaz única (``base.py``). Para escribir uno nuevo, copiar
este archivo y cambiar las cuatro piezas: estado, ``HANDLED_TYPES``, ``validate``
y ``apply`` (ver ``docs/contratos.md``).

Elecciones SIN configuración (P1-13): TX ``VOTE`` con payload
``{"election_id": str, "choice": str}`` (1 a 64 caracteres cada uno); cada dirección
vota UNA vez; cualquiera vota; sin cierre. Siguen valiendo igual.

Elecciones CONFIGURADAS (P2-12), con la TX ``ELECTION_CREATE``:

    sender          autoridad o emisor registrado
    payload         {election_id, options (2 a 20, distintas), weight_rule,
                     start_height, end_height (enteros, 0 <= inicio <= fin)}
    weight_rule     one_per_address             todos pesan 1
                    by_badge                    + badge_weights {badge_id: peso int > 0}:
                                                pesa el MAYOR peso entre las insignias que
                                                la dirección tiene en el bloque del voto
                    by_pupb_balance_snapshot    + cap int > 0: pesa min(saldo, cap) según
                                                el saldo PUPB justo antes de crear la
                                                elección (foto guardada en el estado)

Idea 8 (opcionales): ``title`` y elegibilidad por credencial ACTIVA
(``eligible_credential_type`` y/o ``eligible_program``); quien no la tiene no vota.

La ventana es por ALTURA de bloque (no por hora): un voto vale si
``start_height <= altura del bloque <= end_height``. El peso sale solo del estado
(insignias en el bloque del voto, o la foto de saldos): sin reloj ni azar. Un voto
de peso 0, fuera de la ventana o con una opción que no existe es inválido (400 en
la API; el bloque entero se rechaza). No se puede repetir un ``election_id`` ni
configurar una elección que ya tiene votos sin configuración.
"""
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from blockchain.contracts.base import Contract, TxContext, is_int, tx_type_of
from blockchain.contracts.tokens import is_registered_issuer

MAX_LEN = 64
MAX_OPTIONS = 20
MAX_WEIGHT = 1_000_000

OPTIONAL_TEXT = ("title", "eligible_credential_type", "eligible_program")
WEIGHT_RULES = ("one_per_address", "by_badge", "by_pupb_balance_snapshot")


@dataclass
class VotingState:
    """elección → {votante → opción}, en el orden en que se confirmaron los votos."""
    elections: Dict[str, Dict[str, str]] = field(default_factory=dict)
    configs: Dict[str, dict] = field(default_factory=dict)            # elección configurada (P2-12)
    weights: Dict[str, Dict[str, int]] = field(default_factory=dict)  # elección → {votante → peso}

    def has_voted(self, election_id: str, voter: str) -> bool:
        return voter in self.elections.get(election_id, {})

    def tally(self, election_id: str) -> Dict[str, int]:
        """Totales por opción (ordenado por opción para que la salida sea estable).

        Sin configuración cuenta votos; configurada suma pesos e incluye las opciones en 0.
        """
        config = self.configs.get(election_id)
        counts: Dict[str, int] = {o: 0 for o in config["options"]} if config else {}
        for voter, choice in self.elections.get(election_id, {}).items():
            counts[choice] = counts.get(choice, 0) + (
                self.weights[election_id][voter] if config else 1)
        return dict(sorted(counts.items()))


def _text(value) -> Optional[str]:
    """``value`` si es un str de 1..MAX_LEN caracteres; si no, None."""
    if isinstance(value, str) and 0 < len(value) <= MAX_LEN:
        return value
    return None


def vote_weight(config: dict, voter: str, ctx: TxContext) -> int:
    """Peso del voto de ``voter`` (0 = no puede votar). Determinista: solo lee estado."""
    rule = config["weight_rule"]
    if rule == "one_per_address":
        return 1
    if rule == "by_badge":
        badges = ctx.view("badges")
        held = badges.badges_of(voter) if badges is not None else {}
        return max((w for b, w in config["badge_weights"].items() if b in held), default=0)
    return config["snapshot"].get(voter, 0)   # by_pupb_balance_snapshot (ya con tope)


def _elegible(config: dict, voter: str, ctx: TxContext) -> bool:
    """Idea 8: restricción opcional a quien tenga una credencial ACTIVA del tipo/programa."""
    tipo, programa = config.get("eligible_credential_type"), config.get("eligible_program")
    if tipo is None and programa is None:
        return True
    credentials = ctx.view("credentials")
    if credentials is None:
        return False
    for c in credentials.get_student_credentials(voter):
        if str(getattr(c.get("status"), "value", c.get("status"))).upper() != "ACTIVE":
            continue
        ctype = str(getattr(c.get("credential_type"), "value", c.get("credential_type")))
        if (tipo is None or ctype == tipo) and (programa is None or c.get("program") == programa):
            return True
    return False


class VotingContract(Contract):
    NAME = "voting"
    HANDLED_TYPES = frozenset({"VOTE", "ELECTION_CREATE"})

    def __init__(self, authority_address: Optional[str] = None) -> None:
        from blockchain.core.block import GENESIS_AUTHORITY_ADDRESS
        self.authority_address = authority_address or GENESIS_AUTHORITY_ADDRESS

    def initial_state(self) -> VotingState:
        return VotingState()

    def validate(self, state: VotingState, tx: dict, ctx: TxContext) -> Tuple[bool, str]:
        payload = tx.get("payload")
        if not isinstance(payload, dict):
            return False, "payload debe ser un objeto"
        election_id = _text(payload.get("election_id"))
        if election_id is None:
            return False, f"election_id debe ser texto de 1 a {MAX_LEN} caracteres"
        if tx_type_of(tx) == "ELECTION_CREATE":
            return self._check_create(state, tx.get("sender", ""), election_id, payload, ctx)
        choice = _text(payload.get("choice"))
        if choice is None:
            return False, f"choice debe ser texto de 1 a {MAX_LEN} caracteres"
        voter = tx.get("sender", "")
        if state.has_voted(election_id, voter):
            return False, f"Ya votó en la elección {election_id}"
        config = state.configs.get(election_id)
        if config is None:
            return True, "OK"      # elección sin configuración: regla de P1-13
        if ctx.block_index is None:
            return False, "Sin altura de bloque no se puede validar la ventana"
        if not config["start_height"] <= ctx.block_index <= config["end_height"]:
            return False, (f"La elección {election_id} está cerrada en el bloque {ctx.block_index} "
                           f"(ventana {config['start_height']}-{config['end_height']})")
        if choice not in config["options"]:
            return False, f"Opción inválida: {choice}"
        if not _elegible(config, voter, ctx):
            return False, "Esta dirección no cumple la elegibilidad de la elección (credencial)"
        if vote_weight(config, voter, ctx) <= 0:
            return False, "Esta dirección no tiene peso de voto en la elección"
        return True, "OK"

    def _check_create(self, state: VotingState, sender: str, election_id: str, payload: dict,
                      ctx: TxContext) -> Tuple[bool, str]:
        if sender != self.authority_address and not is_registered_issuer(ctx, sender):
            return False, "Solo la autoridad o un emisor registrado pueden crear elecciones"
        if election_id in state.configs:
            return False, f"La elección {election_id} ya existe"
        options = payload.get("options")
        if (not isinstance(options, list) or not 2 <= len(options) <= MAX_OPTIONS
                or any(_text(o) is None for o in options) or len(set(options)) != len(options)):
            return False, f"options debe ser una lista de 2 a {MAX_OPTIONS} textos distintos"
        start, end = payload.get("start_height"), payload.get("end_height")
        if not is_int(start) or not is_int(end) or start < 0 or end < start:
            return False, "start_height y end_height deben ser enteros con 0 <= inicio <= fin"
        rule = payload.get("weight_rule")
        if rule not in WEIGHT_RULES:
            return False, f"weight_rule debe ser una de {', '.join(WEIGHT_RULES)}"
        if rule == "by_badge":
            weights = payload.get("badge_weights")
            if (not isinstance(weights, dict) or not weights
                    or any(_text(b) is None or not is_int(w) or not 0 < w <= MAX_WEIGHT
                           for b, w in weights.items())):
                return False, "badge_weights debe ser {badge_id: peso entero 1..1000000}"
        elif rule == "by_pupb_balance_snapshot":
            cap = payload.get("cap")
            if not is_int(cap) or not 0 < cap <= MAX_WEIGHT:
                return False, "cap debe ser un entero 1..1000000"
        for extra in OPTIONAL_TEXT:
            if extra in payload and _text(payload[extra]) is None:
                return False, f"{extra} debe ser texto de 1 a {MAX_LEN} caracteres"
        return True, "OK"

    def apply(self, state: VotingState, tx: dict, ctx: TxContext) -> VotingState:
        payload = tx["payload"]
        election_id = payload["election_id"]
        if tx_type_of(tx) == "ELECTION_CREATE":
            config = {"election_id": election_id, "creator": tx["sender"],
                      "options": list(payload["options"]), "weight_rule": payload["weight_rule"],
                      "start_height": payload["start_height"], "end_height": payload["end_height"],
                      "created_at_block": ctx.block_index}
            for extra in OPTIONAL_TEXT:
                if extra in payload:
                    config[extra] = payload[extra]
            if payload["weight_rule"] == "by_badge":
                config["badge_weights"] = dict(payload["badge_weights"])
            elif payload["weight_rule"] == "by_pupb_balance_snapshot":
                accounts = ctx.view("accounts")
                balances = accounts.balances if accounts is not None else {}
                config["cap"] = payload["cap"]
                config["snapshot"] = {a: min(b, payload["cap"])
                                      for a, b in balances.items() if b > 0}
            # Los votos libres previos (sin configuración) no cuentan: se descartan
            state.elections.pop(election_id, None)
            state.configs[election_id] = config
            return state
        voter = tx["sender"]
        config = state.configs.get(election_id)
        if config is not None:
            state.weights.setdefault(election_id, {})[voter] = vote_weight(config, voter, ctx)
        state.elections.setdefault(election_id, {})[voter] = payload["choice"]
        return state
