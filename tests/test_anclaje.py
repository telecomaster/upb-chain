"""Tests de la idea 3: anclaje público con OpenTimestamps. NUNCA tocan la red:
el transporte hacia los calendarios es un doble inyectado."""
import httpx
import pytest

from blockchain.anchoring import (
    AnchorService, MAGIC, construir_ots, digest_de_bloque, transporte_http)
from blockchain.core.storage import ChainStore
from config import build_settings
from tests.helpers import make_app, mine_and_add
import hashlib
from blockchain.anchoring import (
    MAX_INTENTOS, TAG_BITCOIN, actualizar_pendientes, pendientes)
from tests.test_storage import _dos_ramas, _nuevo

CAL_A, CAL_B = "https://cal-a.test", "https://cal-b.test"
# Respuesta típica de un calendario (timestamp serializado): una atestación "pending":
#   0x00 | tag 83dfe30d2ef90c8e | varbytes( varbytes(uri) )
URI = b"https://cal-a.test"
RESP_A = (bytes.fromhex("0083dfe30d2ef90c8e") + bytes([len(URI) + 1, len(URI)]) + URI)
RESP_B = bytes.fromhex("f010") + b"\x11" * 16 + bytes.fromhex("0083dfe30d2ef90c8e0301") + b"\x02b"


class Calendarios:
    """Transporte falso: registra las llamadas y falla si el calendario está en ``caidos``."""

    def __init__(self):
        self.llamadas, self.caidos = [], set()

    def __call__(self, calendar, digest):
        self.llamadas.append((calendar, digest))
        if calendar in self.caidos:
            raise OSError("calendario caído")
        return RESP_A if calendar == CAL_A else RESP_B


def _servicio(store, fake, interval=2, cals=(CAL_A, CAL_B)):
    return AnchorService(store, interval, cals, transport=fake, background=False,
                         clock=lambda: 1000.0)


def test_apagado_por_defecto(tmp_path):
    assert build_settings(False).anchor_interval == 0
    app = make_app(tmp_path)
    assert app.state.node.anchors is None


def test_formato_ots_contra_la_especificacion():
    """Bytes esperados armados a mano desde la especificación de OpenTimestamps
    (python-opentimestamps, core/timestamp.py): magic de 31 bytes, versión 1, op SHA-256
    (0x08), digest, y el timestamp del calendario; varias ramas se separan con 0xff."""
    magic = bytes.fromhex("004f70656e54696d657374616d7073" "00" "0050726f6f6600"
                          "bf89e2e884e89294")
    assert MAGIC == magic and len(MAGIC) == 31
    digest = bytes(range(32))
    esperado = magic + b"\x01" + b"\x08" + digest + RESP_A
    assert construir_ots(digest, [RESP_A]) == esperado
    assert construir_ots(digest, [RESP_A, RESP_B]) == \
        magic + b"\x01\x08" + digest + b"\xff" + RESP_A + RESP_B
    with pytest.raises(ValueError):
        construir_ots(b"corto", [RESP_A])


def test_digest_es_el_hash_del_bloque():
    h = "ab" * 32
    assert digest_de_bloque(h) == bytes.fromhex(h)
    with pytest.raises(ValueError):
        digest_de_bloque("ab" * 16)


def test_interval_solo_sella_multiplos_y_persiste(tmp_path):
    bc = _nuevo(tmp_path / "a")
    fake = Calendarios()
    svc = _servicio(bc.store, fake, interval=2)
    for _ in range(3):
        assert mine_and_add(bc)[0]
        b = bc.chain[-1]
        svc.on_block(b.header.index, b.hash)
    assert [c for c, _ in fake.llamadas] == [CAL_A, CAL_B]       # solo el bloque 2
    assert fake.llamadas[0][1] == bytes.fromhex(bc.chain[2].hash)
    filas = bc.store.anchors()
    assert {(f["block_index"], f["calendar"], f["status"]) for f in filas} == \
        {(2, CAL_A, "pending"), (2, CAL_B, "pending")}
    bc.store.close()
    # Reinicio: la tabla sigue ahí y un bloque repetido no se vuelve a enviar.
    store = ChainStore(tmp_path / "a" / "chain.db")
    svc2 = _servicio(store, fake)
    svc2.on_block(2, bc.chain[2].hash)
    assert len(fake.llamadas) == 2
    ots = svc2.ots_de_bloque(2, bc.chain[2].hash)
    assert ots == construir_ots(bytes.fromhex(bc.chain[2].hash), [RESP_A, RESP_B])
    store.close()


def test_base_anterior_sin_tabla_anchors(tmp_path):
    """Una chain.db creada antes de la idea 3 se abre y gana la tabla."""
    import sqlite3
    bc = _nuevo(tmp_path / "v")
    bc.store.close()
    con = sqlite3.connect(tmp_path / "v" / "chain.db")
    con.execute("DROP TABLE anchors")
    con.commit(); con.close()
    store = ChainStore(tmp_path / "v" / "chain.db")
    assert store.anchors() == []
    store.close()


def test_fallo_se_registra_y_se_reintenta(tmp_path):
    bc = _nuevo(tmp_path / "a")
    fake = Calendarios()
    fake.caidos.add(CAL_B)
    svc = _servicio(bc.store, fake)
    for _ in range(2):
        assert mine_and_add(bc)[0]
    svc.on_block(2, bc.chain[2].hash)
    estados = {f["calendar"]: f["status"] for f in bc.store.anchors()}
    assert estados == {CAL_A: "pending", CAL_B: "failed"}
    fake.caidos.clear()
    svc.retry_failed()                                # sin esperar el backoff: no reintenta
    assert {f["calendar"]: f["status"] for f in bc.store.anchors()}[CAL_B] == "failed"
    svc.clock = lambda: 1000.0 + 61
    svc.retry_failed()
    assert {f["calendar"]: f["status"] for f in bc.store.anchors()} == \
        {CAL_A: "pending", CAL_B: "pending"}
    assert svc.listado()[0]["status"] == "pending"


def test_todos_caidos_no_lanza_ni_da_ots(tmp_path):
    bc = _nuevo(tmp_path / "a")
    fake = Calendarios()
    fake.caidos.update({CAL_A, CAL_B})
    svc = _servicio(bc.store, fake)
    for _ in range(2):
        assert mine_and_add(bc)[0]
    svc.on_block(2, bc.chain[2].hash)                 # no lanza
    assert svc.listado()[0]["status"] == "failed"
    assert svc.ots_de_bloque(2, bc.chain[2].hash) is None


def test_reorg_marca_huerfanos_los_anclajes(tmp_path):
    a, b = _dos_ramas(tmp_path)                       # a: 2 bloques, b: 4 bloques
    fake = Calendarios()
    svc = _servicio(a.store, fake, cals=(CAL_A,))
    hash_viejo = a.chain[2].hash
    svc.on_block(2, hash_viejo)
    assert svc.listado()[0]["status"] == "pending"
    ok, why = a.replace_chain([blk.to_dict() for blk in b.chain])
    assert ok, why
    assert svc.listado() == []                        # ignorado por defecto
    huerfano = svc.listado(include_orphaned=True)
    assert huerfano[0]["block_hash"] == hash_viejo and huerfano[0]["status"] == "orphaned"
    svc.on_block(4, a.chain[4].hash)                  # el bloque nuevo sí se ancla
    assert [x["block_index"] for x in svc.listado()] == [4]


def test_transporte_http_usa_post_a_digest(monkeypatch):
    """Sin red: se sustituye urlopen para ver la petición que se armaría."""
    vistos = {}

    class Resp:
        def read(self, n): return RESP_A
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def falso(req, timeout):
        vistos.update(url=req.full_url, metodo=req.get_method(), cuerpo=req.data,
                      accept=req.get_header("Accept"), timeout=timeout)
        return Resp()

    monkeypatch.setattr("urllib.request.urlopen", falso)
    assert transporte_http("https://x.test/", b"\x01" * 32) == RESP_A
    assert vistos == {"url": "https://x.test/digest", "metodo": "POST",
                      "cuerpo": b"\x01" * 32, "accept": "application/vnd.opentimestamps.v1",
                      "timeout": 10.0}


@pytest.mark.asyncio
async def test_api_anchors_end_to_end(tmp_path):
    app = make_app(tmp_path, anchor_interval=2, anchor_calendars=[CAL_A])
    node = app.state.node
    fake = Calendarios()
    node.anchors.transport = fake
    node.anchors._pool = None                         # envío síncrono en el test
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://127.0.0.1") as c:
        assert (await c.get("/anchors")).json()["anchors"] == []
        assert (await c.get("/anchors/2.ots")).status_code == 404
        for _ in range(2):
            assert mine_and_add(node.blockchain)[0]
            node.announce_block(node.blockchain.chain[-1].to_dict())
        lista = (await c.get("/anchors")).json()
        assert lista["enabled"] and lista["anchors"][0]["block_index"] == 2
        assert lista["anchors"][0]["status"] == "pending"
        assert (await c.get("/anchors?from_block=3")).json()["anchors"] == []
        r = await c.get("/anchors/2.ots")
        assert r.status_code == 200
        assert r.content == construir_ots(
            bytes.fromhex(node.blockchain.chain[2].hash), [RESP_A])
        assert (await c.get("/anchors/1.ots")).status_code == 404


@pytest.mark.asyncio
async def test_api_con_anclaje_apagado(tmp_path):
    app = make_app(tmp_path)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://127.0.0.1") as c:
        assert (await c.get("/anchors")).json() == {"enabled": False, "anchors": []}
        assert (await c.get("/anchors/1.ots")).status_code == 404


def test_reintentos_acotados_con_backoff_exponencial(tmp_path):
    bc = _nuevo(tmp_path / "a")
    fake = Calendarios()
    fake.caidos.add(CAL_A)
    svc = _servicio(bc.store, fake, cals=(CAL_A,))
    for _ in range(2):
        assert mine_and_add(bc)[0]
    svc.on_block(2, bc.chain[2].hash)                 # intento 1 (t=1000)
    t = 1000.0
    for k in range(1, 12):
        t += 60 * 2 ** (k - 1)                        # justo el backoff tras el intento k
        svc.clock = lambda t=t: t
        svc.retry_failed()
    fila = bc.store.anchors()[0]
    assert fila["status"] == "failed" and fila["attempts"] == MAX_INTENTOS
    assert len(fake.llamadas) == MAX_INTENTOS         # tras el tope ya no se llama


def test_no_ancla_historia_al_sincronizar(tmp_path):
    bc = _nuevo(tmp_path / "a")
    fake = Calendarios()
    svc = _servicio(bc.store, fake, cals=(CAL_A,))
    svc.tip = lambda: 50
    svc.on_block(2, "aa" * 32)                        # a 48 bloques de la punta: historia
    svc.on_block(48, "bb" * 32, timestamp=1000.0 - 3 * 86_400)   # cerca de la punta, pero viejo
    assert fake.llamadas == []
    svc.on_block(50, "cc" * 32, timestamp=990.0)      # en la punta y reciente
    assert [d for _, d in fake.llamadas] == [bytes.fromhex("cc" * 32)]


def _bloque_pendiente(tmp_path, ts_bytes):
    bc = _nuevo(tmp_path / "a")
    for _ in range(2):
        assert mine_and_add(bc)[0]
    h = bc.chain[2].hash
    bc.store.put_anchor(2, h, CAL_A, 1000.0, ts_bytes, "pending", 1)
    return bc, h


def test_pendientes_calcula_el_commitment_de_la_cadena_de_ops():
    digest = bytes(range(32))
    # append(0x0102) -> sha256 -> pending(uri): commitment = sha256(digest || 0102)
    ts = bytes([0xF0, 2, 1, 2, 0x08]) + RESP_A
    (ini, fin, com, uri), = pendientes(ts, digest)
    assert com == hashlib.sha256(digest + b"\x01\x02").digest()
    assert uri == URI.decode() and ts[ini:fin] == RESP_A and fin == len(ts)


def test_actualizar_pendientes_marca_upgraded_con_atestacion_bitcoin(tmp_path):
    bc, h = _bloque_pendiente(tmp_path, RESP_A)
    # Atestación de Bitcoin: 0x00 | tag | varbytes(varuint altura 42).
    prueba = b"\x00" + TAG_BITCOIN + b"\x01\x2a"
    vistos = []

    def fetch(uri, commitment_hex):
        vistos.append((uri, commitment_hex))
        if len(vistos) == 1:
            raise OSError("404: aún no")                # primera pasada: no listo
        return prueba

    assert actualizar_pendientes(bc.store, fetch) == 0
    assert bc.store.anchors()[0]["status"] == "pending"
    assert actualizar_pendientes(bc.store, fetch) == 1
    fila = bc.store.anchors()[0]
    assert vistos[0] == (URI.decode(), h)              # commitment = digest (sin ops)
    assert fila["status"] == "upgraded" and fila["ots_bytes"] == prueba
    assert actualizar_pendientes(bc.store, fetch) == 0  # idempotente


def test_actualizar_sin_atestacion_bitcoin_sigue_pendiente(tmp_path):
    bc, _ = _bloque_pendiente(tmp_path, RESP_A)
    assert actualizar_pendientes(bc.store, lambda u, c: RESP_B) == 0
    assert bc.store.anchors()[0]["status"] == "pending"
