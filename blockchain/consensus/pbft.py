"""
UPB-Chain — Consenso PBFT (Practical Byzantine Fault Tolerance)
Universidad Privada Boliviana · Carrera de Ingeniería en IA

Implementación del protocolo PBFT de Castro & Liskov (1999).
Garantiza acuerdo en una red de n nodos cuando a lo sumo f nodos
son defectuosos (Byzantine), siempre que n ≥ 3f + 1.

Para la red UPB (n=4 nodos): f=1 → tolera 1 nodo malicioso o caído.

Protocolo de 3 fases:
    1. PRE-PREPARE: primario difunde la propuesta con digest d = H(request)
    2. PREPARE:     cada réplica vota si acepta la propuesta (quórum = 2f+1)
    3. COMMIT:      cada réplica confirma cuando ve 2f+1 PREPAREs (quórum = 2f+1)

Propiedades garantizadas:
    - Safety:    todos los nodos honestos acuerdan el mismo valor
    - Liveness:  el protocolo termina (con VIEW-CHANGE si el primario falla)

Complejidades:
    propose()        → O(1)
    handle_prepare() → O(f) en conteo de votos
    handle_commit()  → O(f) en conteo de votos
    Mensajes total   → O(n²) por ronda (cuello de botella de escalabilidad)

Referencias:
    Castro, M., & Liskov, B. (1999). Practical Byzantine Fault Tolerance. OSDI'99.
    Lamport, L., Shostak, R., & Pease, M. (1982). The Byzantine Generals Problem.
"""
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set

logger = logging.getLogger("upb_chain.pbft")


class PBFTPhase(str, Enum):
    PRE_PREPARE = "PRE_PREPARE"
    PREPARE     = "PREPARE"
    COMMIT      = "COMMIT"
    REPLY       = "REPLY"


@dataclass
class PBFTMessage:
    phase: PBFTPhase
    view: int
    sequence: int
    node_id: str
    digest: str
    data: Optional[dict] = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "phase": self.phase,
            "view": self.view,
            "sequence": self.sequence,
            "node_id": self.node_id,
            "digest": self.digest,
            "data": self.data,
            "timestamp": self.timestamp,
        }

    @staticmethod
    def compute_digest(data: dict) -> str:
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


@dataclass
class ConsensusState:
    sequence: int
    view: int
    request: dict
    digest: str
    pre_prepared: bool = False
    prepare_votes: Set[str] = field(default_factory=set)
    commit_votes: Set[str] = field(default_factory=set)
    committed: bool = False
    start_time: float = field(default_factory=time.time)


class PBFTNode:
    def __init__(self, node_id: str, peers: List[str], is_primary: bool = False):
        self.node_id = node_id
        self.peers = peers  # IDs de todos los nodos en la red
        self.is_primary = is_primary
        self.view = 0
        self.sequence = 0
        self.f = (len(peers) - 1) // 3  # máx nodos defectuosos tolerados
        self.quorum = 2 * self.f + 1   # votos necesarios

        self._states: Dict[int, ConsensusState] = {}
        self._committed_sequences: Set[int] = set()
        self._message_log: List[PBFTMessage] = []

    @property
    def n_nodes(self) -> int:
        return len(self.peers)

    def propose(self, request: dict) -> Optional[PBFTMessage]:
        """Solo el nodo primario propone bloques nuevos."""
        if not self.is_primary:
            logger.warning(f"{self.node_id}: intento de propuesta desde nodo secundario")
            return None

        self.sequence += 1
        digest = PBFTMessage.compute_digest(request)
        self._states[self.sequence] = ConsensusState(
            sequence=self.sequence,
            view=self.view,
            request=request,
            digest=digest,
            pre_prepared=True,
        )
        msg = PBFTMessage(
            phase=PBFTPhase.PRE_PREPARE,
            view=self.view,
            sequence=self.sequence,
            node_id=self.node_id,
            digest=digest,
            data=request,
        )
        self._log_message(msg)
        logger.info(f"[{self.node_id}] PRE-PREPARE seq={self.sequence}")
        return msg

    def handle_pre_prepare(self, msg: PBFTMessage) -> Optional[PBFTMessage]:
        """Nodo secundario acepta la propuesta y emite PREPARE."""
        if msg.sequence in self._committed_sequences:
            return None
        if msg.view != self.view:
            logger.warning(f"{self.node_id}: vista incorrecta {msg.view} != {self.view}")
            return None

        digest = PBFTMessage.compute_digest(msg.data)
        if digest != msg.digest:
            logger.warning(f"{self.node_id}: digest inválido en PRE-PREPARE")
            return None

        self._states[msg.sequence] = ConsensusState(
            sequence=msg.sequence,
            view=self.view,
            request=msg.data,
            digest=digest,
            pre_prepared=True,
        )
        prepare_msg = PBFTMessage(
            phase=PBFTPhase.PREPARE,
            view=self.view,
            sequence=msg.sequence,
            node_id=self.node_id,
            digest=digest,
        )
        self._log_message(prepare_msg)
        logger.info(f"[{self.node_id}] PREPARE seq={msg.sequence}")
        return prepare_msg

    def handle_prepare(self, msg: PBFTMessage) -> Optional[PBFTMessage]:
        """Cuenta votos PREPARE; al llegar al quórum emite COMMIT."""
        state = self._states.get(msg.sequence)
        if not state or state.digest != msg.digest:
            return None

        state.prepare_votes.add(msg.node_id)
        logger.debug(
            f"[{self.node_id}] PREPARE seq={msg.sequence} votos={len(state.prepare_votes)}/{self.quorum}"
        )

        if len(state.prepare_votes) >= self.quorum and not state.committed:
            commit_msg = PBFTMessage(
                phase=PBFTPhase.COMMIT,
                view=self.view,
                sequence=msg.sequence,
                node_id=self.node_id,
                digest=state.digest,
            )
            self._log_message(commit_msg)
            logger.info(f"[{self.node_id}] COMMIT seq={msg.sequence}")
            return commit_msg
        return None

    def handle_commit(self, msg: PBFTMessage) -> Optional[dict]:
        """Cuenta votos COMMIT; al llegar al quórum confirma la solicitud."""
        state = self._states.get(msg.sequence)
        if not state or state.digest != msg.digest:
            return None

        state.commit_votes.add(msg.node_id)
        logger.debug(
            f"[{self.node_id}] COMMIT seq={msg.sequence} votos={len(state.commit_votes)}/{self.quorum}"
        )

        if len(state.commit_votes) >= self.quorum and not state.committed:
            state.committed = True
            self._committed_sequences.add(msg.sequence)
            elapsed = time.time() - state.start_time
            logger.info(
                f"[{self.node_id}] COMMITTED seq={msg.sequence} tiempo={elapsed:.3f}s"
            )
            return {
                "sequence": msg.sequence,
                "request": state.request,
                "digest": state.digest,
                "latency_s": elapsed,
            }
        return None

    def trigger_view_change(self) -> PBFTMessage:
        """Inicia cambio de vista cuando el primario falla (timeout)."""
        self.view += 1
        self.is_primary = False  # se re-elije en el nuevo view
        msg = PBFTMessage(
            phase=PBFTPhase.PRE_PREPARE,  # re-uso como VIEW_CHANGE para simplicidad
            view=self.view,
            sequence=self.sequence,
            node_id=self.node_id,
            digest="VIEW_CHANGE",
            data={"reason": "primary_timeout", "new_view": self.view},
        )
        logger.warning(f"[{self.node_id}] VIEW CHANGE → vista {self.view}")
        return msg

    def get_consensus_stats(self) -> dict:
        committed = [s for s in self._states.values() if s.committed]
        latencies = [
            time.time() - s.start_time for s in committed
        ]
        return {
            "node_id": self.node_id,
            "view": self.view,
            "sequence": self.sequence,
            "committed_blocks": len(committed),
            "pending_sequences": len(self._states) - len(committed),
            "fault_tolerance_f": self.f,
            "quorum_size": self.quorum,
            "avg_latency_s": sum(latencies) / len(latencies) if latencies else 0,
        }

    def _log_message(self, msg: PBFTMessage) -> None:
        self._message_log.append(msg)
