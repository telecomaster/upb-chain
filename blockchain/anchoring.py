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
                 clock: Callable[[], float] = time.time) -> None:
        self.store = store
        self.interval = interval
        self.calendars = list(calendars)
        self.transport = transport
        self.clock = clock
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="anchor") \
            if background else None
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self.interval > 0 and bool(self.calendars)

    def should_anchor(self, index: int) -> bool:
        return self.enabled and index > 0 and index % self.interval == 0

    def on_block(self, index: int, block_hash: str) -> None:
        """Llamado con cada bloque nuevo: si toca, sella (en segundo plano) y reintenta fallos."""
        if not self.enabled:
            return
        self._run(self._work, index, block_hash)

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
            for f in filas:
                if f["status"] == "failed" and f["calendar"] in self.calendars:
                    self._enviar(f["block_index"], f["block_hash"], [f["calendar"]], [])

    def _enviar(self, index: int, block_hash: str, calendars: List[str], existentes: list) -> None:
        digest = digest_de_bloque(block_hash)
        hechos = {f["calendar"] for f in existentes
                  if f["block_hash"] == block_hash and f["status"] != "failed"}
        for cal in calendars:
            if cal in hechos:
                continue
            ahora = self.clock()
            try:
                ots = self.transport(cal, digest)
                self.store.put_anchor(index, block_hash, cal, ahora, bytes(ots), "pending")
                logger.info(f"Anclaje: bloque {index} enviado a {cal}")
            except Exception as e:
                self.store.put_anchor(index, block_hash, cal, ahora, None, "failed")
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
