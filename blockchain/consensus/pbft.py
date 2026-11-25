"""
UPB-Chain — Consenso PBFT (Practical Byzantine Fault Tolerance, P1-1)
Universidad Privada Boliviana · Carrera de Ingeniería en IA

Implementación pequeña y legible del protocolo de Castro & Liskov (1999) para
ordenar BLOQUES: el "número de secuencia" de PBFT es la altura del bloque.

Réplicas y quórums
------------------
n réplicas fijas (``pbft_replicas.json``: id, dirección y llave pública), con
f = ⌊(n - 1) / 3⌋ fallas bizantinas toleradas. El objetivo de UPB son n = 4
réplicas (2 por Raspberry Pi) → f = 1. El primario de la vista v es
``replicas[v mod n]`` (§4.1 del artículo).

Caso normal (§4.2) — variante implementada
------------------------------------------
1. PRE-PREPARE ⟨v, n, d⟩ firmado por el primario, con el bloque adjunto
   (d = hash del bloque, n = altura). Lo acepta una réplica que está en la
   vista v, no tiene otro PRE-PREPARE para (v, n) y para la que el bloque es
   válido (``Blockchain.check_block``: misma validación de consenso que PoW,
   salvo el trabajo; ver "Validez de un bloque" en docs/arquitectura.md).
2. PREPARE ⟨v, n, d, i⟩: lo envían los RESPALDOS (no el primario).
   prepared(v, n, d) ⇔ PRE-PREPARE aceptado + 2f PREPARE de réplicas
   distintas del primario. Es la regla textual del artículo: el PRE-PREPARE
   cuenta como el voto del primario, así que el quórum efectivo es 2f + 1
   (antes de P1-1 el primario nunca contaba y con una réplica caída no había
   commit).
3. COMMIT ⟨v, n, d, i⟩: lo envía toda réplica que llegó a prepared.
   committed-local ⇔ prepared + 2f + 1 COMMIT de réplicas distintas (incluido
   el propio). Entonces se agrega el bloque a la cadena junto con su
   CERTIFICADO DE COMMIT (las 2f + 1 firmas), que se guarda aparte del bloque.

Cambio de vista (§4.4)
----------------------
Si una réplica espera trabajo pendiente (TXs en el mempool o un bloque
aceptado sin confirmar) más de ``view_timeout`` segundos, pasa a la vista v+1:
deja de aceptar mensajes de la vista v y difunde VIEW-CHANGE ⟨v+1, h, P, i⟩
(h = su altura confirmada, P = certificados "prepared" por encima de h). El
nuevo primario, con 2f VIEW-CHANGE de otras réplicas más el suyo, difunde
NEW-VIEW ⟨v+1, V, O⟩: V = las 2f + 1 pruebas y O = los PRE-PREPARE que
re-proponen el bloque "prepared" de mayor vista en la altura max(h) + 1. Cada
réplica recalcula O a partir de V y lo rechaza si no coincide. Si la vista
v+1 tampoco avanza, se intenta v+2 con el doble de espera. Regla de vivacidad:
con f + 1 VIEW-CHANGE para vistas mayores, la réplica se une a la menor.

Qué se omite (documentado en docs/arquitectura.md §4)
-----------------------------------------------------
- Checkpoints y recolección de basura: la "ventana" es de UN bloque (el
  primario no propone la altura h + 2 hasta confirmar h + 1), así que el log
  solo guarda la altura siguiente y la cadena confirmada hace de checkpoint
  estable (la altura h viaja en el VIEW-CHANGE y el certificado de commit de
  cada bloque es la prueba).
- Peticiones nulas en NEW-VIEW: con ventana 1 no hay huecos que rellenar.
- Respuestas a clientes (REPLY): el "cliente" mira la cadena (API).
- Transferencia de estado: una réplica atrasada se sincroniza por P2P
  (GET_CHAIN) y verifica los certificados de cada bloque.
- La vista no se guarda en disco: al arrancar se toma la vista del último
  certificado de la cadena.

Firmas: ECDSA secp256k1 con la llave de cada réplica (``PBFT_KEY_FILE``, el
mismo formato que una wallet). La firma cubre el mensaje en JSON canónico,
excepto los campos ``signature`` y ``block`` (el bloque queda atado por d).

Referencias:
    Castro, M., & Liskov, B. (1999). Practical Byzantine Fault Tolerance. OSDI'99.
    Lamport, L., Shostak, R., & Pease, M. (1982). The Byzantine Generals Problem.
"""
import json
import logging
import queue
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from blockchain.core.block import Block
from security.crypto_utils import sign_data, verify_signature

logger = logging.getLogger("upb_chain.pbft")

# Tipos de mensaje PBFT (viajan dentro de un mensaje P2P "PBFT").
PRE_PREPARE = "PRE_PREPARE"
PREPARE = "PREPARE"
COMMIT = "COMMIT"
VIEW_CHANGE = "VIEW_CHANGE"
NEW_VIEW = "NEW_VIEW"
MESSAGE_TYPES = (PRE_PREPARE, PREPARE, COMMIT, VIEW_CHANGE, NEW_VIEW)


class PBFTConfigError(ValueError):
    """Configuración de réplicas inválida (mensaje en español)."""


# ── Firmas ────────────────────────────────────────────────────────────────────

def signing_payload(msg: dict) -> str:
    """Texto que se firma: JSON canónico sin ``signature`` ni ``block``."""
    body = {k: v for k, v in msg.items() if k not in ("signature", "block")}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sign_message(msg: dict, private_key_hex: str) -> dict:
    """Devuelve una copia de ``msg`` con su firma ECDSA."""
    signed = {k: v for k, v in msg.items() if k != "signature"}
    signed["signature"] = sign_data(signing_payload(signed), private_key_hex)
    return signed


# ── Conjunto de réplicas ──────────────────────────────────────────────────────

@dataclass(frozen=True)
class Replica:
    id: str
    host: str
    port: int
    public_key: str

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"


class ReplicaSet:
    """Réplicas en orden fijo (el orden define el primario de cada vista)."""

    def __init__(self, replicas: List[Replica]):
        if not replicas:
            raise PBFTConfigError("la lista de réplicas PBFT está vacía")
        ids = [r.id for r in replicas]
        if len(set(ids)) != len(ids):
            raise PBFTConfigError("hay ids de réplica repetidos")
        if len({r.public_key for r in replicas}) != len(replicas):
            raise PBFTConfigError("hay llaves públicas de réplica repetidas")
        self.replicas = list(replicas)
        self._by_id = {r.id: r for r in replicas}
        self.n = len(replicas)
        self.f = (self.n - 1) // 3          # fallas bizantinas toleradas
        self.quorum = 2 * self.f + 1        # COMMIT, VIEW-CHANGE (y PREPARE + PRE-PREPARE)
        self.prepare_quorum = 2 * self.f    # PREPARE de respaldos

    # Construcción ────────────────────────────────────────────────────────────

    @classmethod
    def from_list(cls, items: List[dict]) -> "ReplicaSet":
        replicas = []
        for i, item in enumerate(items):
            try:
                rid = str(item["id"]).strip()
                host, port = str(item["address"]).rsplit(":", 1)
                public_key = str(item["public_key"]).strip()
                bytes.fromhex(public_key)
                replicas.append(Replica(rid, host, int(port), public_key))
            except (KeyError, ValueError, TypeError, AttributeError) as e:
                raise PBFTConfigError(
                    f"réplica #{i}: se esperan 'id', 'address' (host:puerto) y "
                    f"'public_key' (hex): {e}") from None
            if not rid:
                raise PBFTConfigError(f"réplica #{i}: id vacío")
        return cls(replicas)

    @classmethod
    def from_file(cls, path) -> "ReplicaSet":
        """Lee ``{"replicas": [{"id", "address", "public_key"}, ...]}``."""
        path = Path(path)
        if not path.exists():
            raise PBFTConfigError(
                f"{path}: no existe. En modo PBFT hace falta la lista de réplicas "
                f"(ver scripts/crear_llave_replica.py)")
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError) as e:
            raise PBFTConfigError(f"{path}: no se pudo leer: {e}") from None
        items = data.get("replicas") if isinstance(data, dict) else data
        if not isinstance(items, list):
            raise PBFTConfigError(f"{path}: falta la lista 'replicas'")
        return cls.from_list(items)

    def to_list(self) -> List[dict]:
        return [{"id": r.id, "address": r.address, "public_key": r.public_key}
                for r in self.replicas]

    # Consultas ───────────────────────────────────────────────────────────────

    @property
    def ids(self) -> List[str]:
        return [r.id for r in self.replicas]

    def get(self, replica_id: str) -> Optional[Replica]:
        return self._by_id.get(replica_id)

    def primary(self, view: int) -> str:
        """Primario de la vista ``view``: replicas[v mod n] (§4.1)."""
        return self.replicas[view % self.n].id

    def verify(self, msg: dict) -> bool:
        """Firma válida de una réplica conocida (el firmante es ``msg['replica']``)."""
        replica = self.get(msg.get("replica")) if isinstance(msg, dict) else None
        signature = msg.get("signature") if replica else None
        if not isinstance(signature, str):
            return False
        return verify_signature(signing_payload(msg), signature, replica.public_key)

    # Certificados ────────────────────────────────────────────────────────────

    def check_commit_certificate(self, cert, block_hash: str, height: int) -> Tuple[bool, str]:
        """¿``cert`` prueba que el bloque ``block_hash`` se confirmó en la altura ``height``?

        Formato: ``{"view": v, "seq": n, "digest": d, "commits": [COMMIT firmados]}``.
        Exige 2f + 1 COMMIT de réplicas distintas, misma vista, misma altura y
        mismo hash, todos con firma válida. Determinista (sin reloj).
        """
        if not isinstance(cert, dict):
            return False, "Bloque sin certificado de commit PBFT"
        view, commits = cert.get("view"), cert.get("commits")
        if not isinstance(view, int) or not isinstance(commits, list):
            return False, "Certificado de commit malformado"
        if cert.get("seq") != height or cert.get("digest") != block_hash:
            return False, "Certificado de commit de otro bloque"
        signers = set()
        for m in commits:
            if not isinstance(m, dict) or m.get("type") != COMMIT:
                return False, "Certificado con un mensaje que no es COMMIT"
            if m.get("view") != view or m.get("seq") != height or m.get("digest") != block_hash:
                return False, "Certificado con un COMMIT de otra vista o bloque"
            if m.get("replica") in signers:
                return False, f"Certificado con firmante repetido: {m.get('replica')}"
            if not self.verify(m):
                return False, f"Certificado con firma inválida o réplica desconocida: {m.get('replica')}"
            signers.add(m["replica"])
        if len(signers) < self.quorum:
            return False, f"Certificado con {len(signers)} firmas; se necesitan {self.quorum} (2f+1)"
        return True, "OK"

    def check_prepared_certificate(self, pc) -> Optional[Tuple[int, int, str, Block]]:
        """Valida un certificado "prepared" (PRE-PREPARE + 2f PREPARE) de un VIEW-CHANGE.

        Devuelve ``(vista, altura, hash, bloque)`` o None si no es válido.
        """
        if not isinstance(pc, dict):
            return None
        pp, prepares = pc.get("pre_prepare"), pc.get("prepares")
        if not isinstance(pp, dict) or not isinstance(prepares, list):
            return None
        view, seq, digest = pp.get("view"), pp.get("seq"), pp.get("digest")
        if pp.get("type") != PRE_PREPARE or not isinstance(view, int) or not isinstance(seq, int):
            return None
        primary = self.primary(view)
        if pp.get("replica") != primary or not self.verify(pp):
            return None
        block = block_of(pp)
        if block is None or block.header.index != seq:
            return None
        signers = set()
        for m in prepares:
            if not isinstance(m, dict) or m.get("type") != PREPARE:
                return None
            if (m.get("view"), m.get("seq"), m.get("digest")) != (view, seq, digest):
                return None
            if m.get("replica") in (primary, *signers) or not self.verify(m):
                return None
            signers.add(m["replica"])
        if len(signers) < self.prepare_quorum:
            return None
        return view, seq, digest, block


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _well_formed(msg) -> bool:
    """Forma mínima: tipo conocido, réplica y vista enteras; en las fases, altura y digest."""
    if not isinstance(msg, dict) or msg.get("type") not in MESSAGE_TYPES:
        return False
    if not isinstance(msg.get("replica"), str) or not _is_int(msg.get("view")):
        return False
    if msg["type"] in (PRE_PREPARE, PREPARE, COMMIT):
        return _is_int(msg.get("seq")) and isinstance(msg.get("digest"), str)
    return True


def block_of(pre_prepare: dict) -> Optional[Block]:
    """Bloque adjunto a un PRE-PREPARE si su hash es correcto y coincide con d."""
    try:
        block = Block.from_dict(pre_prepare["block"])
    except (KeyError, TypeError, ValueError, AttributeError):
        return None
    if block.hash != pre_prepare.get("digest") or block.compute_hash() != block.hash:
        return None
    return block


def choose_reproposal(view_changes: List[dict], rs: ReplicaSet,
                      ) -> Tuple[int, Optional[dict]]:
    """Cálculo de O del NEW-VIEW (§4.4), determinista a partir de V.

    Devuelve ``(h_max, pc)``: h_max = mayor altura confirmada entre los
    VIEW-CHANGE y pc = el certificado "prepared" de mayor vista para la altura
    h_max + 1 (o None: no hay nada que re-proponer).
    """
    h_max = max(int(vc.get("height", 0)) for vc in view_changes)
    best, best_view = None, -1
    for vc in view_changes:
        for pc in vc.get("prepared") or []:
            info = rs.check_prepared_certificate(pc)
            if info is None:
                continue
            view, seq, _, _ = info
            if seq == h_max + 1 and view > best_view:
                best, best_view = pc, view
    return h_max, best


# ── Log de una altura ─────────────────────────────────────────────────────────

@dataclass
class Slot:
    """Estado de la propuesta (vista, altura) en una réplica."""
    view: int
    seq: int
    pre_prepare: Optional[dict] = None
    block: Optional[Block] = None
    accepted: bool = False                  # bloque validado y PRE-PREPARE aceptado
    prepares: Dict[str, Dict[str, dict]] = field(default_factory=dict)   # digest -> réplica -> msg
    commits: Dict[str, Dict[str, dict]] = field(default_factory=dict)
    prepared: bool = False
    commit_sent: bool = False
    committed: bool = False

    @property
    def digest(self) -> Optional[str]:
        return self.pre_prepare["digest"] if self.pre_prepare else None


# ── Réplica ───────────────────────────────────────────────────────────────────

class PBFTReplica:
    """Una réplica PBFT que ordena bloques de ``blockchain``.

    Dependencias inyectadas (para poder probarla sin red):
      - ``send(msg)``: difunde un mensaje firmado a las DEMÁS réplicas (no bloquea).
      - ``on_event(fase, datos)``: aviso de fase (bus de eventos ``pbft_phase``).
      - ``on_committed(bloque, certificado)``: bloque confirmado y agregado.
      - ``on_equivocation(réplica, vista, altura, tipo, digests)``: mensajes
        contradictorios firmados por la misma réplica (alerta del monitor).
      - ``on_invalid_block(motivo, réplica)``: el primario propuso un bloque inválido.
      - ``request_sync()``: pedir la cadena a los pares (réplica atrasada).
    Todo el estado se protege con un ``RLock``; un hilo propio hace los
    temporizadores y las propuestas del primario.
    """

    TICK = 0.05
    MAX_FUTURE = 500      # mensajes de vistas futuras guardados como máximo

    def __init__(self, replica_id: str, private_key_hex: str, replicas: ReplicaSet,
                 blockchain, send: Callable[[dict], None], *,
                 view_timeout: float = 5.0, batch_interval: float = 0.2,
                 on_event: Optional[Callable[[str, dict], None]] = None,
                 on_committed: Optional[Callable[[Block, dict], None]] = None,
                 on_equivocation: Optional[Callable[..., None]] = None,
                 on_invalid_block: Optional[Callable[[str, str], None]] = None,
                 request_sync: Optional[Callable[[], None]] = None,
                 clock: Callable[[], float] = time.monotonic):
        if replicas.get(replica_id) is None:
            raise PBFTConfigError(f"{replica_id} no figura en la lista de réplicas")
        self.id = replica_id
        self._key = private_key_hex
        self.rs = replicas
        self.bc = blockchain
        self._send = send
        self.view_timeout = view_timeout
        self.batch_interval = batch_interval
        self._on_event = on_event
        self._on_committed = on_committed
        self._on_equivocation = on_equivocation
        self._on_invalid_block = on_invalid_block
        self._request_sync = request_sync
        self._clock = clock

        self._lock = threading.RLock()
        self.view = 0
        self.in_view_change = False
        self.target_view = 0                       # vista a la que se intenta pasar
        self._slots: Dict[Tuple[int, int], Slot] = {}
        self._first_seen: Dict[tuple, str] = {}    # (tipo, vista, altura, réplica) -> digest
        self._equivocations: set = set()
        self._view_changes: Dict[int, Dict[str, dict]] = {}
        self._new_view_sent: set = set()
        self._future: List[dict] = []              # mensajes de vistas aún no instaladas
        self._height = blockchain.height
        self._waiting_since: Optional[float] = None
        self._vc_attempts = 0
        self._last_proposal = 0.0
        self._last_sync = -1e9
        self.last_seen: Dict[str, float] = {}
        # Contadores (GET /consensus y /metrics).
        self.view_changes_total = 0
        self.rejected_messages = 0
        self.committed_blocks = 0
        self._adopt_view_from_chain()

        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ── Ciclo de vida ─────────────────────────────────────────────────────────

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name=f"pbft-{self.id}")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=2)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:
                logger.exception(f"[{self.id}] error en el ciclo PBFT")
            self._stop.wait(self.TICK)

    # ── Consultas ─────────────────────────────────────────────────────────────

    @property
    def primary(self) -> str:
        return self.rs.primary(self.view)

    @property
    def is_primary(self) -> bool:
        return self.primary == self.id and not self.in_view_change

    def status(self) -> dict:
        now = self._clock()
        with self._lock:
            replicas = []
            for r in self.rs.replicas:
                seen = self.last_seen.get(r.id)
                replicas.append({
                    "id": r.id, "address": r.address,
                    "primary": r.id == self.primary, "self": r.id == self.id,
                    "last_message_s_ago": None if seen is None else round(now - seen, 3),
                    "active": r.id == self.id or (
                        seen is not None and now - seen <= 3 * self.view_timeout),
                })
            return {
                "mode": "pbft", "replica_id": self.id, "is_replica": True,
                "view": self.view, "primary": self.primary,
                "in_view_change": self.in_view_change,
                "target_view": self.target_view if self.in_view_change else self.view,
                "n": self.rs.n, "f": self.rs.f, "quorum": self.rs.quorum,
                "last_committed_seq": self.bc.height,
                "committed_blocks": self.committed_blocks,
                "view_changes": self.view_changes_total,
                "rejected_messages": self.rejected_messages,
                "view_timeout_s": self.view_timeout,
                "replicas": replicas,
            }

    # ── Envío ─────────────────────────────────────────────────────────────────

    def _make(self, msg_type: str, **fields) -> dict:
        return sign_message({"type": msg_type, "replica": self.id, **fields}, self._key)

    def _multicast(self, msg: dict) -> None:
        """Se entrega el mensaje a sí misma (sin red) y luego lo difunde a las demás.

        Primero el propio: así el nuevo primario instala la vista ANTES de que
        alguien reciba su NEW-VIEW y le conteste con PREPARE.
        """
        self._handle(msg)
        try:
            self._send(msg)
        except Exception:
            logger.exception(f"[{self.id}] error al enviar {msg.get('type')}")

    def _event(self, phase: str, **data) -> None:
        if self._on_event:
            try:
                self._on_event(phase, {"phase": phase, "replica": self.id, **data})
            except Exception:
                logger.exception("Error en on_event PBFT")

    # ── Recepción ─────────────────────────────────────────────────────────────

    def receive(self, msg: dict) -> bool:
        """Entrada desde la red. Descarta lo que no esté firmado por una réplica conocida."""
        if not _well_formed(msg):
            self._reject("mensaje PBFT desconocido o malformado")
            return False
        if msg.get("replica") == self.id:
            return False                     # eco de un mensaje propio
        if not self.rs.verify(msg):
            self._reject(f"firma inválida o réplica desconocida ({msg.get('replica')!r})")
            return False
        with self._lock:
            self.last_seen[msg["replica"]] = self._clock()
            self._handle(msg)
        return True

    def _reject(self, reason: str) -> None:
        with self._lock:
            self.rejected_messages += 1
        logger.warning(f"[{self.id}] mensaje PBFT descartado: {reason}")

    def _handle(self, msg: dict) -> None:
        with self._lock:
            self._sync_height()
            handler = {
                PRE_PREPARE: self._on_pre_prepare, PREPARE: self._on_prepare,
                COMMIT: self._on_commit, VIEW_CHANGE: self._on_view_change,
                NEW_VIEW: self._on_new_view,
            }[msg["type"]]
            handler(msg)

    def _equivocates(self, msg: dict) -> bool:
        """¿Misma réplica, mismo (tipo, vista, altura) y otro digest? Se alerta una vez."""
        key = (msg["type"], msg.get("view"), msg.get("seq"), msg["replica"])
        first = self._first_seen.setdefault(key, msg.get("digest"))
        if first == msg.get("digest"):
            return False
        if key not in self._equivocations:
            self._equivocations.add(key)
            logger.critical(f"[{self.id}] EQUIVOCACIÓN de {msg['replica']}: dos {msg['type']} "
                            f"en vista {msg.get('view')} altura {msg.get('seq')}")
            self._event("EQUIVOCATION", view=msg.get("view"), seq=msg.get("seq"),
                        offender=msg["replica"], kind=msg["type"])
            if self._on_equivocation:
                try:
                    self._on_equivocation(msg["replica"], msg.get("view"), msg.get("seq"),
                                          msg["type"], [first, msg.get("digest")])
                except Exception:
                    logger.exception("Error en on_equivocation")
        return True

    def _slot(self, view: int, seq: int) -> Slot:
        key = (view, seq)
        if key not in self._slots:
            self._slots[key] = Slot(view, seq)
        return self._slots[key]

    def _in_window(self, msg: dict) -> bool:
        """Vista actual, sin cambio de vista en curso y altura por encima de la cadena."""
        seq = msg.get("seq")
        if not isinstance(seq, int) or not isinstance(msg.get("view"), int):
            return False
        if msg["view"] > self.view:
            # Llegó antes que el NEW-VIEW (la red reordena): se guarda y se
            # reprocesa al instalar esa vista.
            if len(self._future) < self.MAX_FUTURE:
                self._future.append(msg)
            return False
        if self.in_view_change or msg["view"] != self.view or seq <= self._height:
            return False
        if seq > self._height + 1:
            self._maybe_sync()           # otros van adelante: pedir la cadena
        return seq <= self._height + 2   # ventana pequeña: el resto se descarta

    # Caso normal ─────────────────────────────────────────────────────────────

    def _on_pre_prepare(self, msg: dict) -> None:
        if msg["replica"] != self.rs.primary(msg.get("view", -1)):
            self._reject(f"PRE-PREPARE de {msg['replica']}, que no es el primario")
            return
        if not self._in_window(msg) or self._equivocates(msg):
            return
        slot = self._slot(msg["view"], msg["seq"])
        if slot.pre_prepare is not None:
            return
        block = block_of(msg)
        if block is None or block.header.index != msg["seq"]:
            self._reject("PRE-PREPARE con un bloque que no corresponde a su digest")
            return
        slot.pre_prepare, slot.block = msg, block
        self._try_accept(slot)

    def _try_accept(self, slot: Slot) -> None:
        """Acepta el PRE-PREPARE si el bloque es válido sobre nuestra punta y envía PREPARE."""
        if slot.accepted or slot.pre_prepare is None or slot.seq != self._height + 1:
            return
        ok, reason = self.bc.check_block(slot.block)
        if not ok:
            logger.warning(f"[{self.id}] bloque propuesto inválido (vista {slot.view}, "
                           f"altura {slot.seq}): {reason}")
            if self._on_invalid_block:
                self._on_invalid_block(f"PBFT: {reason}", slot.pre_prepare["replica"])
            slot.pre_prepare, slot.block = None, None
            return
        slot.accepted = True
        self._event(PRE_PREPARE, view=slot.view, seq=slot.seq, digest=slot.digest[:16])
        if self.id != self.rs.primary(slot.view):
            self._multicast(self._make(PREPARE, view=slot.view, seq=slot.seq,
                                       digest=slot.digest))
        self._check_prepared(slot)

    def _on_prepare(self, msg: dict) -> None:
        if msg["replica"] == self.rs.primary(msg.get("view", -1)):
            return                       # el primario no envía PREPARE (§4.2)
        if not self._in_window(msg) or self._equivocates(msg):
            return
        slot = self._slot(msg["view"], msg["seq"])
        slot.prepares.setdefault(msg["digest"], {})[msg["replica"]] = msg
        self._check_prepared(slot)

    def _check_prepared(self, slot: Slot) -> None:
        if slot.prepared or not slot.accepted:
            return
        if len(slot.prepares.get(slot.digest, {})) < self.rs.prepare_quorum:
            return
        slot.prepared = True
        self._event("PREPARED", view=slot.view, seq=slot.seq, digest=slot.digest[:16])
        if not slot.commit_sent:
            slot.commit_sent = True
            self._multicast(self._make(COMMIT, view=slot.view, seq=slot.seq,
                                       digest=slot.digest))
        self._check_committed(slot)

    def _on_commit(self, msg: dict) -> None:
        if not self._in_window(msg) or self._equivocates(msg):
            return
        slot = self._slot(msg["view"], msg["seq"])
        slot.commits.setdefault(msg["digest"], {})[msg["replica"]] = msg
        self._check_committed(slot)

    def _check_committed(self, slot: Slot) -> None:
        if slot.committed or not slot.prepared:
            return
        votes = slot.commits.get(slot.digest, {})
        if len(votes) < self.rs.quorum or slot.seq != self._height + 1:
            return
        # Certificado: 2f + 1 COMMIT ordenados por id (cualquier subconjunto sirve).
        commits = [votes[r] for r in sorted(votes)][: self.rs.quorum]
        cert = {"view": slot.view, "seq": slot.seq, "digest": slot.digest, "commits": commits}
        ok, reason = self.bc.add_block(slot.block, certificate=cert)
        if not ok:
            if self.bc.height >= slot.seq:      # ya llegó por P2P con su certificado
                self._sync_height()
                return
            logger.error(f"[{self.id}] no se pudo agregar el bloque confirmado "
                         f"{slot.seq}: {reason}")
            return
        slot.committed = True
        self.committed_blocks += 1
        self._event("COMMITTED", view=slot.view, seq=slot.seq, digest=slot.digest[:16])
        logger.info(f"[{self.id}] bloque {slot.seq} confirmado por PBFT en la vista {slot.view}")
        self._sync_height()
        if self._on_committed:
            try:
                self._on_committed(slot.block, cert)
            except Exception:
                logger.exception("Error en on_committed")

    def _sync_height(self) -> None:
        """La cadena avanzó (commit propio o bloque certificado por P2P): limpiar el log."""
        h = self.bc.height
        if h == self._height:
            return
        self._height = h
        self._slots = {k: s for k, s in self._slots.items() if s.seq > h}
        self._first_seen = {k: d for k, d in self._first_seen.items()
                            if not isinstance(k[2], int) or k[2] > h}
        self._waiting_since = None
        self._vc_attempts = 0
        self._adopt_view_from_chain()
        # ¿Había un PRE-PREPARE esperando a que llegáramos a esta altura?
        for slot in list(self._slots.values()):
            if slot.view == self.view and slot.seq == h + 1:
                self._try_accept(slot)

    def _adopt_view_from_chain(self) -> None:
        """Una réplica reiniciada o atrasada toma la vista del último certificado."""
        cert = self.bc.certificates.get(self.bc.height) if self.bc.height > 0 else None
        cv = cert.get("view", 0) if cert else 0
        # Un certificado válido de la vista cv prueba que esa vista se instaló.
        if cv > self.view and (not self.in_view_change or cv >= self.target_view):
            self.view = self.target_view = cv
            self.in_view_change = False
            logger.info(f"[{self.id}] vista {self.view} tomada del último certificado")

    def _maybe_sync(self) -> None:
        now = self._clock()
        if self._request_sync and now - self._last_sync >= 1.0:
            self._last_sync = now
            threading.Thread(target=self._request_sync, daemon=True).start()

    # Primario y temporizador ─────────────────────────────────────────────────

    def tick(self) -> None:
        """Propuestas del primario, temporizador de cambio de vista y NEW-VIEW pendiente."""
        with self._lock:
            self._sync_height()
            now = self._clock()
            if self.in_view_change and self.rs.primary(self.target_view) == self.id:
                self._try_new_view(self.target_view)
            if self.is_primary:
                self._maybe_propose(now)
            self._check_timer(now)

    def _in_flight(self) -> bool:
        slot = self._slots.get((self.view, self._height + 1))
        return slot is not None and slot.pre_prepare is not None

    def _maybe_propose(self, now: float) -> None:
        """El primario propone un bloque cuando hay TXs en el mempool (ventana de 1)."""
        if self._in_flight() or not self.bc.mempool or now - self._last_proposal < self.batch_interval:
            return
        block = self.bc.create_candidate_block()    # hasta 50 TX, dificultad 0, nonce 0
        if not block.transactions:
            return
        self._last_proposal = now
        pp = self._make(PRE_PREPARE, view=self.view, seq=block.header.index,
                        digest=block.hash)
        pp["block"] = block.to_dict()
        logger.info(f"[{self.id}] PRE-PREPARE vista {self.view} altura {block.header.index} "
                    f"({len(block.transactions)} TX)")
        self._multicast(pp)

    def _pending_work(self) -> bool:
        return bool(self.bc.mempool) or self._in_flight() or self.in_view_change

    def _check_timer(self, now: float) -> None:
        if not self._pending_work():
            self._waiting_since = None
            return
        if self._waiting_since is None:
            self._waiting_since = now
            return
        # Espera exponencial: si la vista v+1 tampoco avanza, v+2 espera el doble (§4.5.2).
        limit = self.view_timeout * (2 ** min(self._vc_attempts, 5))
        if now - self._waiting_since >= limit:
            base = self.target_view if self.in_view_change else self.view
            self._start_view_change(base + 1)

    # Cambio de vista ─────────────────────────────────────────────────────────

    def _prepared_certificates(self) -> List[dict]:
        """P: por cada altura > h, el certificado "prepared" de mayor vista."""
        best: Dict[int, Slot] = {}
        for slot in self._slots.values():
            if slot.prepared and slot.seq > self._height:
                if slot.seq not in best or slot.view > best[slot.seq].view:
                    best[slot.seq] = slot
        out = []
        for seq in sorted(best):
            slot = best[seq]
            prepares = slot.prepares[slot.digest]
            out.append({"pre_prepare": slot.pre_prepare,
                        "prepares": [prepares[r] for r in sorted(prepares)][: self.rs.prepare_quorum]})
        return out

    def _start_view_change(self, new_view: int) -> None:
        if new_view <= self.view or (self.in_view_change and new_view <= self.target_view):
            return
        if self.in_view_change:
            self._vc_attempts += 1
        self.in_view_change = True
        self.target_view = new_view
        self._waiting_since = self._clock()
        logger.warning(f"[{self.id}] VIEW-CHANGE: vista {self.view} → {new_view} "
                       f"(primario nuevo: {self.rs.primary(new_view)})")
        self._event(VIEW_CHANGE, view=new_view, new_primary=self.rs.primary(new_view))
        msg = self._make(VIEW_CHANGE, view=new_view, height=self._height,
                         tip=self.bc.last_block.hash,
                         prepared=self._prepared_certificates())
        self._multicast(msg)

    def _valid_view_change(self, msg: dict) -> bool:
        if not isinstance(msg.get("view"), int) or not isinstance(msg.get("height"), int):
            return False
        for pc in msg.get("prepared") or []:
            info = self.rs.check_prepared_certificate(pc)
            if info is None or info[1] <= msg["height"] or info[0] >= msg["view"]:
                return False
        return True

    def _on_view_change(self, msg: dict) -> None:
        v = msg.get("view")
        if not isinstance(v, int) or v <= self.view:
            return
        if not self._valid_view_change(msg):
            self._reject(f"VIEW-CHANGE inválido de {msg['replica']}")
            return
        self._view_changes.setdefault(v, {})[msg["replica"]] = msg
        # Vivacidad (§4.5.2): f + 1 réplicas piden vistas mayores → unirse a la menor.
        if not self.in_view_change or v > self.target_view:
            pedidas: Dict[str, int] = {}
            for view, msgs in self._view_changes.items():
                if view > (self.target_view if self.in_view_change else self.view):
                    for r in msgs:
                        pedidas[r] = min(pedidas.get(r, view), view)
            if len(pedidas) >= self.rs.f + 1:
                self._start_view_change(min(pedidas.values()))
        if self.rs.primary(v) == self.id:
            self._try_new_view(v)

    def _try_new_view(self, v: int) -> None:
        """Nuevo primario: con 2f VIEW-CHANGE de otras réplicas (+ el propio) envía NEW-VIEW."""
        if v in self._new_view_sent or v <= self.view:
            return
        others = {r: m for r, m in self._view_changes.get(v, {}).items() if r != self.id}
        if len(others) < 2 * self.rs.f:
            return
        if not self.in_view_change or self.target_view != v:
            self._start_view_change(v)
        own = self._view_changes.get(v, {}).get(self.id)
        if own is None:
            return
        proofs = [own] + [others[r] for r in sorted(others)][: 2 * self.rs.f]
        h_max, pc = choose_reproposal(proofs, self.rs)
        if self._height < h_max:
            self._maybe_sync()          # primero ponerse al día; se reintenta en tick()
            return
        pre_prepares = []
        if pc is not None:
            pp = self._make(PRE_PREPARE, view=v, seq=h_max + 1, digest=pc["pre_prepare"]["digest"])
            pp["block"] = pc["pre_prepare"]["block"]
            pre_prepares.append(pp)
        self._new_view_sent.add(v)
        nv = self._make(NEW_VIEW, view=v, view_changes=proofs, pre_prepares=pre_prepares)
        logger.warning(f"[{self.id}] NEW-VIEW {v} ({len(pre_prepares)} bloque(s) re-propuesto(s))")
        self._multicast(nv)

    def _on_new_view(self, msg: dict) -> None:
        v = msg.get("view")
        if not isinstance(v, int) or v <= self.view:
            return
        if msg["replica"] != self.rs.primary(v):
            self._reject(f"NEW-VIEW de {msg['replica']}, que no es el primario de la vista {v}")
            return
        proofs = msg.get("view_changes") or []
        signers = set()
        for vc in proofs:
            if (not isinstance(vc, dict) or vc.get("type") != VIEW_CHANGE or vc.get("view") != v
                    or vc.get("replica") in signers or not self.rs.verify(vc)
                    or not self._valid_view_change(vc)):
                self._reject("NEW-VIEW con una prueba VIEW-CHANGE inválida")
                return
            signers.add(vc["replica"])
        if len(signers) < self.rs.quorum:
            self._reject(f"NEW-VIEW con {len(signers)} VIEW-CHANGE; se necesitan {self.rs.quorum}")
            return
        # Recalcular O a partir de V y compararlo con lo recibido.
        h_max, pc = choose_reproposal(proofs, self.rs)
        expected = [] if pc is None else [(h_max + 1, pc["pre_prepare"]["digest"])]
        got = []
        for pp in msg.get("pre_prepares") or []:
            if (not isinstance(pp, dict) or pp.get("type") != PRE_PREPARE or pp.get("view") != v
                    or pp.get("replica") != msg["replica"] or not self.rs.verify(pp)):
                self._reject("NEW-VIEW con un PRE-PREPARE inválido")
                return
            got.append((pp.get("seq"), pp.get("digest")))
        if got != expected:
            self._reject("NEW-VIEW con un conjunto O que no coincide con sus pruebas")
            return
        self._install_view(v)
        for pp in msg.get("pre_prepares") or []:
            self._on_pre_prepare(pp)
        self._replay_future()
        if h_max > self._height:
            self._maybe_sync()

    def _install_view(self, v: int) -> None:
        self.view = self.target_view = v
        self.in_view_change = False
        self.view_changes_total += 1
        self._vc_attempts = 0
        self._waiting_since = None
        self._slots = {k: s for k, s in self._slots.items() if s.view >= v}
        self._view_changes = {k: m for k, m in self._view_changes.items() if k > v}
        logger.warning(f"[{self.id}] vista {v} instalada; primario {self.rs.primary(v)}")
        self._event(NEW_VIEW, view=v, primary=self.rs.primary(v))

    def _replay_future(self) -> None:
        """Reprocesa los mensajes guardados de la vista recién instalada."""
        pending, self._future = self._future, [m for m in self._future if m["view"] > self.view]
        for m in pending:
            if m["view"] == self.view:
                self._handle(m)


# ── Transporte ────────────────────────────────────────────────────────────────

class PBFTTransport:
    """Entrega mensajes PBFT a cada réplica por los mensajes con framing de ``node.py``.

    Una cola y un hilo por réplica destino: una réplica caída (o lenta) no
    frena a las demás ni bloquea a quien envía. Si la cola se llena se
    descarta el mensaje más viejo; PBFT tolera mensajes perdidos (en el peor
    caso, el temporizador provoca un cambio de vista).
    """

    def __init__(self, p2p, replicas: ReplicaSet, self_id: str, timeout: float = 2.0,
                 max_queue: int = 1000):
        self.p2p = p2p
        self.timeout = timeout
        self._targets = [r for r in replicas.replicas if r.id != self_id]
        self._queues: Dict[str, "queue.Queue"] = {
            r.id: queue.Queue(maxsize=max_queue) for r in self._targets}
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []

    def start(self) -> None:
        self._stop.clear()
        for r in self._targets:
            t = threading.Thread(target=self._worker, args=(r,), daemon=True,
                                 name=f"pbft-tx-{r.id}")
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self._stop.set()
        for q in self._queues.values():
            try:
                q.put_nowait(None)
            except queue.Full:
                pass
        for t in self._threads:
            # Corto: un hilo puede estar esperando a una réplica caída (en Windows
            # un connect rechazado tarda ~2 s); son hilos daemon y salen solos.
            t.join(timeout=0.2)
        self._threads = []

    def multicast(self, msg: dict) -> None:
        for q in self._queues.values():
            while True:
                try:
                    q.put_nowait(msg)
                    break
                except queue.Full:
                    try:
                        q.get_nowait()          # descarta el más viejo
                    except queue.Empty:
                        pass

    def _worker(self, replica: Replica) -> None:
        q = self._queues[replica.id]
        while not self._stop.is_set():
            msg = q.get()
            if msg is None:
                break
            try:
                self.p2p.send_pbft(replica.host, replica.port, msg, timeout=self.timeout)
            except Exception as e:
                logger.debug(f"PBFT: no se pudo entregar {msg.get('type')} a {replica.id}: {e}")


class InMemoryNetwork:
    """Red síncrona en memoria para el demo y las pruebas unitarias (sin sockets).

    ``sender(id)`` da la función ``send`` de una réplica: entrega cada mensaje,
    en el mismo hilo, a las demás réplicas que no estén en ``down``.
    """

    def __init__(self) -> None:
        self.replicas: Dict[str, "PBFTReplica"] = {}
        self.down: set = set()
        self.delivered = 0

    def sender(self, src_id: str) -> Callable[[dict], None]:
        def send(msg: dict) -> None:
            if src_id in self.down:
                return
            for rid, replica in list(self.replicas.items()):
                if rid != src_id and rid not in self.down:
                    self.delivered += 1
                    replica.receive(msg)
        return send

    def add(self, replica: "PBFTReplica") -> None:
        self.replicas[replica.id] = replica
