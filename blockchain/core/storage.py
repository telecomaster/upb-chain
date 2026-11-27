"""
UPB-Chain — Almacenamiento de la cadena en SQLite (P2-4)

Reemplaza el ``chain.json`` que se reescribía ENTERO con cada bloque (P1-8).
Usa solo ``sqlite3`` de la biblioteca estándar (sin ORM) para que se pueda leer
de una sentada. Archivo: ``<DATA_DIR>/chain.db``.

Esquema (ver ``_SCHEMA``):

    meta(key PK, value)                       versión del esquema
    blocks(height PK, hash UNIQUE, prev_hash, timestamp, difficulty, n_txs, data)
                                              un bloque por fila; ``data`` es el
                                              JSON de ``Block.to_dict()``
    txs(tx_id PK, height, position, type, sender, recipient)
                                              índice de TXs: dónde está cada una
                                              (altura + posición = prueba Merkle)
                                              e índices por sender y recipient
    snapshots(height PK, block_hash, contracts, states, digest)
                                              foto del estado de los contratos en
                                              la altura ``height`` (JSON)
    certificates(height PK, block_hash, data) certificado de commit PBFT del
                                              bloque (P1-1): 2f+1 COMMIT firmados.
                                              Fuera del hash del bloque: dos
                                              réplicas pueden juntar subconjuntos
                                              distintos de firmas igual de válidos.

Operaciones y su costo:

    agregar un bloque   UNA transacción: INSERT del bloque + sus TXs (+ foto).
                        Costo O(TXs del bloque), no O(altura): nunca se
                        reescribe la cadena completa.
    reorganización      UNA transacción: DELETE de las alturas > bifurcación e
                        INSERT de los bloques nuevos.
    TX por id           búsqueda por clave primaria (B-tree): O(log N).
    TXs de una dirección, bloque por hash: índices, O(log N + resultados).

Garantías ante cortes de energía (microSD de la RPi, riesgo R-2):

    - Cada escritura es una transacción SQLite (``BEGIN IMMEDIATE`` … ``COMMIT``):
      o entra completa o no entra. Si el proceso muere a la mitad, al reabrir
      SQLite descarta lo que no llegó a ``COMMIT``. No hace falta el temporal +
      rename ni el ``.bak`` de P1-8.
    - ``journal_mode=WAL``: las escrituras van a ``chain.db-wal`` y los lectores
      no bloquean al escritor (la API lee mientras la red agrega bloques).
    - ``synchronous=FULL``: con WAL, cada ``COMMIT`` hace fsync del WAL. Es lo
      seguro en una microSD: un bloque confirmado sobrevive a un corte de luz.
      Con ``NORMAL`` la base tampoco se corrompe, pero se pueden perder los
      últimos COMMIT ante un corte (habría que volver a pedirlos a los pares).
      El costo de FULL es un fsync por bloque: despreciable a ~1 bloque / 10 s.

Si el archivo está dañado (no es SQLite o falla ``PRAGMA quick_check``) se lanza
``StorageError`` con instrucciones. Nunca se borra ni se sobrescribe nada
automáticamente: decidir qué hacer con datos dañados es del operador.
"""
import hashlib
import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Iterator, List, Optional, Sequence, Tuple

from blockchain.contracts.base import tx_type_of

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS blocks (
    height     INTEGER PRIMARY KEY,
    hash       TEXT    NOT NULL UNIQUE,
    prev_hash  TEXT    NOT NULL,
    timestamp  REAL    NOT NULL,
    difficulty INTEGER NOT NULL,
    n_txs      INTEGER NOT NULL,
    data       TEXT    NOT NULL
);
CREATE TABLE IF NOT EXISTS txs (
    tx_id     TEXT    PRIMARY KEY,
    height    INTEGER NOT NULL,
    position  INTEGER NOT NULL,
    type      TEXT,
    sender    TEXT,
    recipient TEXT
);
CREATE INDEX IF NOT EXISTS txs_height    ON txs(height);
CREATE INDEX IF NOT EXISTS txs_sender    ON txs(sender);
CREATE INDEX IF NOT EXISTS txs_recipient ON txs(recipient);
CREATE TABLE IF NOT EXISTS certificates (
    height     INTEGER PRIMARY KEY,
    block_hash TEXT NOT NULL,
    data       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS snapshots (
    height     INTEGER PRIMARY KEY,
    block_hash TEXT NOT NULL,
    contracts  TEXT NOT NULL,
    states     TEXT NOT NULL,
    digest     TEXT NOT NULL
);
-- Idea 3: anclaje público. Tabla local, fuera del consenso; ``CREATE IF NOT EXISTS``
-- la agrega a una chain.db anterior sin cambiar SCHEMA_VERSION. status: pending |
-- upgraded | failed | orphaned (el bloque salió de la cadena en una reorganización).
CREATE TABLE IF NOT EXISTS anchors (
    block_index  INTEGER NOT NULL,
    block_hash   TEXT    NOT NULL,
    calendar     TEXT    NOT NULL,
    submitted_at REAL    NOT NULL,
    ots_bytes    BLOB,
    status       TEXT    NOT NULL,
    PRIMARY KEY (block_hash, calendar)
);
"""


class StorageError(ValueError):
    """chain.db no se puede usar (dañado, versión desconocida…). Mensaje en español."""


@dataclass(frozen=True)
class Snapshot:
    """Foto del estado de los contratos tras el bloque ``height``.

    ``contracts``: nombres de los contratos en orden (si la lista cambia, la foto
    no sirve). ``states``: JSON de ``ContractRegistry.dump_states``. ``digest``:
    SHA-256 de ``states``; detecta una foto dañada en disco (no un atacante con
    acceso de escritura: ver la sección de amenazas en ``docs/arquitectura.md``).
    """
    height: int
    block_hash: str
    contracts: str
    states: str
    digest: str

    @classmethod
    def build(cls, height: int, block_hash: str, contracts: Sequence[str],
              states: str) -> "Snapshot":
        return cls(height, block_hash, ",".join(contracts), states, _sha256(states))

    def is_intact(self) -> bool:
        return _sha256(self.states) == self.digest


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _damaged(path: Path, error: Exception) -> StorageError:
    return StorageError(
        f"{path}: base de datos dañada o ilegible ({error}). No se borró nada. "
        f"Para recuperar el nodo: detenerlo, mover {path.name} (y {path.name}-wal, "
        f"{path.name}-shm) a otro nombre y reiniciar; arrancará desde el génesis y "
        f"se resincronizará con los pares. Si existe chain.json.migrated, renombrarlo "
        f"a chain.json antes de reiniciar para importarlo."
    )


class ChainStore:
    """Bloques, índice de TXs y fotos de estado en un archivo SQLite.

    Una sola conexión por instancia, compartida entre hilos (la API y la red)
    y protegida por ``_lock``. La cadena (``Blockchain``) además serializa las
    escrituras con su propio lock.
    """

    def __init__(self, path, readonly: bool = False) -> None:
        self.path = Path(path)
        self._lock = RLock()
        if readonly and not self.path.exists():
            raise StorageError(f"{self.path}: no existe")
        try:
            if readonly:
                uri = f"file:{self.path.as_posix()}?mode=ro"
                self._conn = sqlite3.connect(uri, uri=True, check_same_thread=False,
                                             isolation_level=None)
            else:
                # isolation_level=None: sin transacciones implícitas; las abrimos
                # nosotros con BEGIN/COMMIT (ver _transaction) para que se vean.
                self._conn = sqlite3.connect(str(self.path), check_same_thread=False,
                                             isolation_level=None)
            self._open(readonly)
        except sqlite3.DatabaseError as e:
            if hasattr(self, "_conn"):
                self._conn.close()
            raise _damaged(self.path, e) from e

    def _open(self, readonly: bool) -> None:
        conn = self._conn
        check = conn.execute("PRAGMA quick_check").fetchone()[0]
        if check != "ok":
            raise sqlite3.DatabaseError(f"quick_check: {check}")
        if readonly:
            return
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.executescript(_SCHEMA)
        row = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        if row is None:
            conn.execute("INSERT INTO meta(key, value) VALUES ('schema_version', ?)",
                         (str(SCHEMA_VERSION),))
        elif int(row[0]) != SCHEMA_VERSION:
            raise StorageError(f"{self.path}: versión de esquema {row[0]} desconocida "
                               f"(este código usa {SCHEMA_VERSION})")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ── Transacciones ─────────────────────────────────────────────────────────

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        """Todo lo que se ejecute dentro entra completo (COMMIT) o nada (ROLLBACK).

        ``BEGIN IMMEDIATE`` toma el candado de escritura al empezar. Si el
        proceso muere antes del COMMIT, SQLite descarta la transacción al reabrir.
        """
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")

    # ── Escritura ─────────────────────────────────────────────────────────────

    def _insert_block(self, conn: sqlite3.Connection, block) -> None:
        h = block.header
        conn.execute(
            "INSERT INTO blocks(height, hash, prev_hash, timestamp, difficulty, n_txs, data) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (h.index, block.hash, h.previous_hash, h.timestamp, h.difficulty,
             len(block.transactions),
             json.dumps(block.to_dict(), ensure_ascii=False, separators=(",", ":"))),
        )

    def _insert_txs(self, conn: sqlite3.Connection, block) -> None:
        rows = [
            (tx["tx_id"], block.header.index, position, tx_type_of(tx),
             tx.get("sender"), tx.get("recipient"))
            for position, tx in enumerate(block.transactions)
            if tx.get("tx_id")          # el génesis no lleva TXs con id
        ]
        conn.executemany(
            "INSERT INTO txs(tx_id, height, position, type, sender, recipient) "
            "VALUES (?, ?, ?, ?, ?, ?)", rows)

    @staticmethod
    def _insert_snapshot(conn: sqlite3.Connection, snap: Snapshot) -> None:
        conn.execute(
            "INSERT OR REPLACE INTO snapshots(height, block_hash, contracts, states, digest) "
            "VALUES (?, ?, ?, ?, ?)",
            (snap.height, snap.block_hash, snap.contracts, snap.states, snap.digest))

    def _add_blocks(self, conn, blocks, snapshot: Optional[Snapshot],
                    certificates: Optional[dict] = None) -> None:
        for block in blocks:
            self._insert_block(conn, block)
            self._insert_txs(conn, block)
            cert = (certificates or {}).get(block.header.index)
            if cert is not None:
                conn.execute(
                    "INSERT OR REPLACE INTO certificates(height, block_hash, data) "
                    "VALUES (?, ?, ?)",
                    (block.header.index, block.hash,
                     json.dumps(cert, ensure_ascii=False, separators=(",", ":"))))
        if snapshot is not None:
            self._insert_snapshot(conn, snapshot)

    def append_block(self, block, snapshot: Optional[Snapshot] = None,
                     certificate: Optional[dict] = None) -> None:
        """Agrega ``block`` en la punta (y opcionalmente una foto y su certificado
        PBFT): una transacción."""
        certs = {block.header.index: certificate} if certificate is not None else None
        with self._transaction() as conn:
            self._add_blocks(conn, [block], snapshot, certs)

    def replace_from(self, fork_height: int, blocks, snapshot: Optional[Snapshot] = None,
                     certificates: Optional[dict] = None) -> None:
        """Reorganización: borra las alturas > ``fork_height`` y agrega ``blocks``.

        Todo en una transacción: tras un corte queda la cadena vieja o la nueva,
        nunca una mezcla. Las fotos por encima de la bifurcación también se borran
        (describían bloques que ya no están).
        """
        with self._transaction() as conn:
            for table in ("txs", "blocks", "snapshots", "certificates"):
                conn.execute(f"DELETE FROM {table} WHERE height > ?", (fork_height,))
            # Los anclajes de los bloques descartados se conservan, marcados como huérfanos.
            conn.execute("UPDATE anchors SET status = 'orphaned' WHERE block_index > ?",
                         (fork_height,))
            self._add_blocks(conn, blocks, snapshot, certificates)

    def import_chain(self, blocks, snapshot: Optional[Snapshot] = None) -> None:
        """Carga una cadena completa (migración desde chain.json) en una transacción."""
        self.replace_from(-1, blocks, snapshot)

    def reset_snapshots(self, snapshot: Optional[Snapshot] = None) -> None:
        """Borra todas las fotos y guarda ``snapshot`` (tras una revalidación completa)."""
        with self._transaction() as conn:
            conn.execute("DELETE FROM snapshots")
            if snapshot is not None:
                self._insert_snapshot(conn, snapshot)

    def put_snapshot(self, snapshot: Snapshot, keep: int = 3) -> None:
        """Guarda una foto y conserva solo las ``keep`` más recientes."""
        with self._transaction() as conn:
            self._insert_snapshot(conn, snapshot)
            conn.execute(
                "DELETE FROM snapshots WHERE height NOT IN "
                "(SELECT height FROM snapshots ORDER BY height DESC LIMIT ?)", (keep,))

    # ── Anclajes públicos (idea 3) ────────────────────────────────────────────

    def put_anchor(self, block_index: int, block_hash: str, calendar: str,
                   submitted_at: float, ots_bytes: Optional[bytes], status: str) -> None:
        """Inserta o reemplaza la fila (``block_hash``, ``calendar``)."""
        with self._transaction() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO anchors(block_index, block_hash, calendar, "
                "submitted_at, ots_bytes, status) VALUES (?, ?, ?, ?, ?, ?)",
                (block_index, block_hash, calendar, submitted_at, ots_bytes, status))

    def anchors(self, from_block: int = 0, include_orphaned: bool = False) -> List[dict]:
        """Filas de ``anchors`` con ``block_index >= from_block``, por altura y calendario."""
        sql = ("SELECT block_index, block_hash, calendar, submitted_at, ots_bytes, status "
               "FROM anchors WHERE block_index >= ?")
        if not include_orphaned:
            sql += " AND status != 'orphaned'"
        rows = self._query(sql + " ORDER BY block_index, calendar", (from_block,))
        return [dict(zip(("block_index", "block_hash", "calendar", "submitted_at",
                          "ots_bytes", "status"), r)) for r in rows]

    # ── Lectura ───────────────────────────────────────────────────────────────

    def _query(self, sql: str, params: tuple = ()) -> list:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def tip_height(self) -> Optional[int]:
        """Altura del último bloque guardado (None si la base está vacía)."""
        return self._query("SELECT MAX(height) FROM blocks")[0][0]

    def load_blocks(self) -> List[dict]:
        """Todos los bloques (dicts de ``Block.to_dict``) en orden de altura."""
        return [json.loads(r[0]) for r in
                self._query("SELECT data FROM blocks ORDER BY height")]

    def block_dict(self, height: int) -> Optional[dict]:
        rows = self._query("SELECT data FROM blocks WHERE height = ?", (height,))
        return json.loads(rows[0][0]) if rows else None

    def height_of_hash(self, block_hash: str) -> Optional[int]:
        rows = self._query("SELECT height FROM blocks WHERE hash = ?", (block_hash,))
        return rows[0][0] if rows else None

    def find_tx(self, tx_id: str) -> Optional[Tuple[int, int]]:
        """``(altura, posición)`` de la TX confirmada ``tx_id``, o None."""
        rows = self._query("SELECT height, position FROM txs WHERE tx_id = ?", (tx_id,))
        return (rows[0][0], rows[0][1]) if rows else None

    def txs_of_address(self, address: str, role: str = "any",
                       tx_type: Optional[str] = None) -> List[Tuple[int, int]]:
        """``(altura, posición)`` de las TXs de ``address`` en orden de cadena.

        ``role``: "sender", "recipient" o "any" (cualquiera de los dos).
        """
        if role == "sender":
            where, params = "sender = ?", [address]
        elif role == "recipient":
            where, params = "recipient = ?", [address]
        elif role == "any":
            where, params = "(sender = ? OR recipient = ?)", [address, address]
        else:
            raise ValueError(f"role inválido: {role}")
        if tx_type is not None:
            where += " AND type = ?"
            params.append(tx_type)
        rows = self._query(f"SELECT height, position FROM txs WHERE {where} "
                           f"ORDER BY height, position", tuple(params))
        return [(r[0], r[1]) for r in rows]

    def count_txs(self) -> int:
        """Total de TXs en bloques (incluida la del génesis, como antes)."""
        return self._query("SELECT COALESCE(SUM(n_txs), 0) FROM blocks")[0][0]

    def load_certificates(self) -> dict:
        """Certificados de commit PBFT guardados: ``{altura: certificado}`` (P1-1)."""
        return {r[0]: json.loads(r[1]) for r in
                self._query("SELECT height, data FROM certificates ORDER BY height")}

    def snapshots(self) -> List[Snapshot]:
        """Fotos guardadas, de la más alta a la más baja."""
        rows = self._query("SELECT height, block_hash, contracts, states, digest "
                           "FROM snapshots ORDER BY height DESC")
        return [Snapshot(*r) for r in rows]
