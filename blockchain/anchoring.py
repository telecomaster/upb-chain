"""Anclaje público de la cabeza de la cadena con OpenTimestamps (idea 3).

NO es consenso: es un trabajo local y de mejor esfuerzo. Nunca bloquea ni altera la
validación; si los calendarios no responden, se registra el fallo y se reintenta luego.

Qué se sella: cada ``ANCHOR_INTERVAL`` bloques (alturas múltiplos del intervalo) se envía
a los calendarios el **hash del bloque como 32 bytes** (el hash ya es un SHA-256, así que
se usa tal cual como "hash del archivo" del formato OTS). No hay archivo original: para
verificar con el cliente oficial se pasa el digest directamente (ver docs/arquitectura.md).

Formato .ots escrito a mano (solo escritura; no se verifica contra Bitcoin aquí).
Especificación: https://github.com/opentimestamps/python-opentimestamps
(``opentimestamps/core/timestamp.py`` y ``notary.py``) y https://opentimestamps.org.

    archivo  = MAGIC || version(varuint=1) || op_hash(0x08 = SHA-256) || digest(32) || timestamp
    timestamp con varias ramas = (0xff || rama)* || rama_final
    rama     = lo que devuelve el calendario en POST /digest (operaciones y atestación
               "pending", que apunta al calendario que luego tendrá la de Bitcoin)
"""
from __future__ import annotations

import logging
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, List, Optional, Sequence

logger = logging.getLogger(__name__)

# Cabecera fija de todo .ots: "\x00OpenTimestamps\x00\x00Proof\x00" + 8 bytes aleatorios fijos.
MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
VERSION = 1
OP_SHA256 = 0x08
TAG_FORK = 0xFF           # "hay otra rama después de esta"
MAX_INTENTOS = 5          # envíos fallidos permitidos por (bloque, calendario); luego queda failed
BACKOFF_BASE = 60.0       # segundos; tras el intento k se espera BASE * 2**(k-1)
MAX_EDAD_BLOQUE = 86_400  # no se ancla un bloque de más de un día (historia al sincronizar)
TAG_BITCOIN = bytes.fromhex("0588960d73d71901")   # atestación de Bitcoin
TAG_PENDING = bytes.fromhex("83dfe30d2ef90c8e")   # atestación pendiente en un calendario
MAX_RESPUESTA = 10_000    # un timestamp pendiente pesa unas decenas de bytes

Transport = Callable[[str, bytes], bytes]   # (url del calendario, digest) -> timestamp serializado


def digest_de_bloque(block_hash: str) -> bytes:
    """Los 32 bytes que se sellan: el hash del bloque (hex de 64 caracteres)."""
    digest = bytes.fromhex(block_hash)
    if len(digest) != 32:
        raise ValueError("el hash del bloque debe ser de 32 bytes")
    return digest


def construir_ots(digest: bytes, timestamps: Sequence[bytes]) -> bytes:
    """Arma un .ots válido con la respuesta de uno o más calendarios (una rama por calendario)."""
    if len(digest) != 32 or not timestamps:
        raise ValueError("se necesita un digest de 32 bytes y al menos un timestamp")
    cuerpo = b""
    for i, ts in enumerate(timestamps):
        if i < len(timestamps) - 1:
            cuerpo += bytes([TAG_FORK])
        cuerpo += ts
    return MAGIC + bytes([VERSION, OP_SHA256]) + digest + cuerpo


def transporte_http(calendar: str, digest: bytes, timeout: float = 10.0) -> bytes:
    """POST ``<calendario>/digest`` con el digest crudo; devuelve el timestamp serializado."""
    req = urllib.request.Request(
        calendar.rstrip("/") + "/digest", data=digest, method="POST",
        headers={"Accept": "application/vnd.opentimestamps.v1",
                 "User-Agent": "upb-chain-anchor",
                 "Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310 (URL configurada)
        cuerpo = r.read(MAX_RESPUESTA + 1)
    if not cuerpo or len(cuerpo) > MAX_RESPUESTA:
        raise ValueError("respuesta del calendario vacía o demasiado grande")
    return cuerpo


class AnchorService:
    """Decide cuándo anclar, envía a los calendarios y guarda el resultado en ``anchors``."""

    def __init__(self, store, interval: int, calendars: Sequence[str],
                 transport: Transport = transporte_http, background: bool = True,
                 tip: Callable[[], int] = lambda: 0,
                 clock: Callable[[], float] = time.time) -> None:
        self.store = store
        self.interval = interval
        self.calendars = list(calendars)
        self.transport = transport
        self.clock = clock
        self.tip = tip   # altura actual de la cadena
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="anchor") \
            if background else None
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self.interval > 0 and bool(self.calendars)

    def should_anchor(self, index: int) -> bool:
        return self.enabled and index > 0 and index % self.interval == 0

    def on_block(self, index: int, block_hash: str, timestamp: Optional[float] = None) -> None:
        """Llamado con cada bloque nuevo: si toca, sella (en segundo plano) y reintenta fallos.

        Regla contra anclar historia (sincronización, reorg larga): un bloque múltiplo de N solo
        se ancla si está a lo sumo a N bloques de la punta Y su ``timestamp`` (si se conoce) tiene
        menos de ``MAX_EDAD_BLOQUE`` segundos. Los reintentos no pasan por esta regla.
        """
        if not self.enabled:
            return
        if not self._es_reciente(index, timestamp):
            index = None
        self._run(self._work, index, block_hash)

    def _es_reciente(self, index: int, timestamp: Optional[float]) -> bool:
        if self.tip() - index > self.interval:
            return False
        return timestamp is None or self.clock() - timestamp <= MAX_EDAD_BLOQUE

    def retry_failed(self) -> None:
        """Reintenta los envíos fallidos (al arrancar y con cada bloque nuevo)."""
        if self.enabled:
            self._run(self._work, None, None)

    def close(self) -> None:
        if self._pool is not None:
            self._pool.shutdown(wait=False, cancel_futures=True)

    # ── Interno ───────────────────────────────────────────────────────────────

    def _run(self, fn, *args) -> None:
        if self._pool is None:
            self._safe(fn, *args)
        else:
            self._pool.submit(self._safe, fn, *args)

    def _safe(self, fn, *args) -> None:
        try:
            fn(*args)
        except Exception as e:   # el anclaje jamás debe afectar al nodo
            logger.warning(f"Anclaje: error inesperado: {e}")

    def _work(self, index: Optional[int], block_hash: Optional[str]) -> None:
        with self._lock:
            filas = self.store.anchors()
            if index is not None and self.should_anchor(index):
                self._enviar(index, block_hash, self.calendars, filas)
            # Reintentos: filas fallidas cuyo bloque sigue en la cadena (no huérfanas).
            ahora = self.clock()
            for f in filas:
                espera = BACKOFF_BASE * 2 ** max(f["attempts"] - 1, 0)
                if (f["status"] == "failed" and f["calendar"] in self.calendars
                        and f["attempts"] < MAX_INTENTOS
                        and ahora - f["submitted_at"] >= espera):
                    self._enviar(f["block_index"], f["block_hash"], [f["calendar"]], [],
                                 f["attempts"])

    def _enviar(self, index: int, block_hash: str, calendars: List[str], existentes: list,
                intentos: int = 0) -> None:
        digest = digest_de_bloque(block_hash)
        # Cualquier fila previa (incluida failed) la maneja el reintento con su backoff.
        hechos = {f["calendar"] for f in existentes if f["block_hash"] == block_hash}
        for cal in calendars:
            if cal in hechos:
                continue
            ahora = self.clock()
            try:
                ots = self.transport(cal, digest)
                self.store.put_anchor(index, block_hash, cal, ahora, bytes(ots), "pending", intentos)
                logger.info(f"Anclaje: bloque {index} enviado a {cal}")
            except Exception as e:
                self.store.put_anchor(index, block_hash, cal, ahora, None, "failed", intentos + 1)
                logger.warning(f"Anclaje: falló el envío del bloque {index} a {cal}: {e}")

    # ── Lectura para la API ───────────────────────────────────────────────────

    def listado(self, from_block: int = 0, include_orphaned: bool = False) -> List[dict]:
        """Un elemento por bloque anclado, con el estado de cada calendario."""
        por_bloque: dict = {}
        for f in self.store.anchors(from_block, include_orphaned):
            b = por_bloque.setdefault((f["block_index"], f["block_hash"]), [])
            b.append(f)
        orden = {"upgraded": 3, "pending": 2, "failed": 1, "orphaned": 0}
        out = []
        for (idx, h), filas in por_bloque.items():
            mejor = max((f["status"] for f in filas), key=lambda s: orden.get(s, 0))
            out.append({"block_index": idx, "block_hash": h, "status": mejor,
                        "calendars": [{"calendar": f["calendar"], "status": f["status"],
                                       "submitted_at": f["submitted_at"]} for f in filas]})
        return out

    def ots_de_bloque(self, index: int, block_hash: str) -> Optional[bytes]:
        """.ots del bloque (con todas las ramas de calendarios que respondieron) o None."""
        ramas = [f["ots_bytes"] for f in self.store.anchors(index)
                 if f["block_index"] == index and f["block_hash"] == block_hash
                 and f["ots_bytes"] and f["status"] in ("pending", "upgraded")]
        return construir_ots(digest_de_bloque(block_hash), ramas) if ramas else None


# ── Mejora de pendiente a confirmada (``scripts/actualizar_anclajes.py``) ─────

def _varuint(b: bytes, pos: int):
    n, shift = 0, 0
    while True:
        byte = b[pos]
        pos += 1
        n |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return n, pos
        shift += 7


def _varbytes(b: bytes, pos: int):
    n, pos = _varuint(b, pos)
    if pos + n > len(b):
        raise ValueError("timestamp truncado")
    return b[pos:pos + n], pos + n


def pendientes(ts: bytes, msg: bytes) -> List[tuple]:
    """Atestaciones pendientes de un timestamp serializado que parte del mensaje ``msg``.

    Devuelve ``(inicio, fin, commitment, uri)``: el rango de bytes de la atestación y el mensaje
    (resultado de aplicar las operaciones al digest) que hay que pedir al calendario.
    Solo entiende append/prepend/sha256/fork (lo que emiten los calendarios); otra op -> ValueError.
    """
    import hashlib
    out: List[tuple] = []

    def timestamp(pos: int, m: bytes) -> int:
        while ts[pos] == TAG_FORK:
            pos = item(pos + 1, m)
        return item(pos, m)

    def item(pos: int, m: bytes) -> int:
        tag = ts[pos]
        if tag == 0x00:
            tipo, p = ts[pos + 1:pos + 9], pos + 9
            carga, fin = _varbytes(ts, p)
            if tipo == TAG_PENDING:
                uri, _ = _varbytes(carga, 0)
                out.append((pos, fin, m, uri.decode("utf-8")))
            return fin
        if tag in (0xF0, 0xF1):
            arg, p = _varbytes(ts, pos + 1)
            return timestamp(p, m + arg if tag == 0xF0 else arg + m)
        if tag == OP_SHA256:
            return timestamp(pos + 1, hashlib.sha256(m).digest())
        raise ValueError(f"operación OTS no soportada: {tag:#x}")

    timestamp(0, msg)
    return out


def actualizar_pendientes(store, fetch: Callable[[str, str], bytes]) -> int:
    """Para cada anclaje ``pending``, pide a su calendario ``GET <uri>/timestamp/<commitment hex>``
    (``fetch(uri, commitment_hex)``), sustituye la atestación pendiente por la respuesta y marca
    ``upgraded`` si trae la atestación de Bitcoin. Un calendario que aún no la tiene (404, red)
    se omite. Devuelve cuántas filas pasaron a ``upgraded``."""
    mejoradas = 0
    for f in store.anchors():
        if f["status"] != "pending" or not f["ots_bytes"]:
            continue
        ots, bitcoin = f["ots_bytes"], False
        try:
            lista = pendientes(ots, digest_de_bloque(f["block_hash"]))
        except (ValueError, IndexError) as e:
            logger.warning(f"Anclaje: timestamp ilegible del bloque {f['block_index']}: {e}")
            continue
        for inicio, fin, commitment, uri in reversed(lista):
            try:
                resp = fetch(uri, commitment.hex())
            except Exception as e:
                logger.info(f"Anclaje: {uri} aún no tiene la prueba ({e})")
                continue
            if TAG_BITCOIN in resp:
                ots = ots[:inicio] + resp + ots[fin:]
                bitcoin = True
        if bitcoin:
            store.put_anchor(f["block_index"], f["block_hash"], f["calendar"],
                             f["submitted_at"], ots, "upgraded", f["attempts"])
            mejoradas += 1
    return mejoradas


def fetch_http(uri: str, commitment_hex: str, timeout: float = 10.0) -> bytes:
    req = urllib.request.Request(
        uri.rstrip("/") + "/timestamp/" + commitment_hex,
        headers={"Accept": "application/vnd.opentimestamps.v1", "User-Agent": "upb-chain-anchor"})
    with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310
        return r.read(MAX_RESPUESTA)
