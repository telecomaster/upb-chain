"""Sincronización por lotes (P0-5, auditoría: la cadena viajaba en UN mensaje).

Antes ``GET_CHAIN`` mandaba la cadena completa en un solo marco; al superar
``_MAX_PAYLOAD`` (10 MB) un nodo nuevo nunca podía sincronizar ("Longitud de
mensaje inválida" en bucle) y el nodo que servía volcaba trazas de SSLEOFError.
Ahora el cliente busca el punto de bifurcación con ``GET_HASHES`` y baja solo los
bloques posteriores con ``GET_BLOCKS``, en lotes acotados por cantidad y bytes.

El tope se reduce en cada INSTANCIA (``nodo._MAX_PAYLOAD = ...``), nunca en la
clase ni en el módulo: los demás nodos del proceso no se enteran.
"""
import json
import logging
import shutil
import socket
import struct
import time

import pytest

from blockchain.core.chain import Blockchain
from blockchain.core.transaction import Transaction, TransactionType
from blockchain.core.wallet import Wallet
from blockchain.network.node import (MSG_BLOCKS, MSG_GET_BLOCKS, MSG_GET_HASHES, MSG_HASHES,
                                     P2PNode)
from tests.helpers import mine_candidate

pytestmark = pytest.mark.integration

HOST = "127.0.0.1"
TOPE = 40_000          # bytes por mensaje en estos tests (la cadena los supera varias veces)


def _esperar(condicion, timeout=15.0, intervalo=0.05):
    limite = time.time() + timeout
    while time.time() < limite:
        if condicion():
            return True
        time.sleep(intervalo)
    return condicion()


class _Red:
    def __init__(self, tmp_path):
        self.tmp_path = tmp_path
        self.nodos = []

    def cadena(self, nombre):
        # Dificultad fija de 1 bit: cada bloque pesa lo mismo y "más bloques" = "más trabajo".
        return Blockchain(nombre, str(self.tmp_path / nombre), initial_difficulty=1,
                          min_difficulty=1, max_difficulty=1)

    def nodo(self, nombre, peers=(), bc=None, tope=TOPE, port=0, sync_interval=0.5):
        node = P2PNode(nombre, HOST, port, blockchain=bc or self.cadena(nombre),
                       sync_interval=sync_interval, retry_base=0.2, retry_max=1.0, timeout=5.0)
        node._MAX_PAYLOAD = tope          # solo esta instancia
        node.start()
        self.nodos.append(node)
        for p in peers:
            node.add_peer(HOST, p.port)
        return node

    def detener(self):
        for n in self.nodos:
            n.stop()


@pytest.fixture
def red(tmp_path):
    r = _Red(tmp_path)
    yield r
    r.detener()


def _txs(n, tam=3_000):
    salida = []
    for _ in range(n):
        w = Wallet.generate()
        t = Transaction(type=TransactionType.DATA_RECORD, sender=w.address, recipient="DEST",
                        payload={"data": "x" * tam}, nonce=1)
        t.sign(w.private_key_hex)
        salida.append(t)
    return salida


def _minar(bc, n, txs_por_bloque=0):
    for _ in range(n):
        ok, motivo = bc.add_block(mine_candidate(bc, _txs(txs_por_bloque) or None))
        assert ok, motivo


def _bytes_cadena(bc):
    return len(json.dumps({"type": "CHAIN", "data": [b.to_dict() for b in bc.chain]}))


def _espiar(node):
    """Registra los mensajes que ``node`` pide a sus pares (parche en la instancia)."""
    enviados = []
    original = node._request

    def espia(host, port, message, *args, **kwargs):
        enviados.append(dict(message))
        return original(host, port, message, *args, **kwargs)

    node._request = espia
    return enviados


def test_nodo_nuevo_sincroniza_una_cadena_mayor_que_el_tope_de_mensaje(red):
    """Regresión de la auditoría: con GET_CHAIN la respuesta superaba el tope y B no avanzaba."""
    bc_a = red.cadena("a")
    _minar(bc_a, 12, txs_por_bloque=2)
    assert _bytes_cadena(bc_a) > 2 * TOPE
    a = red.nodo("a", bc=bc_a)

    b = red.nodo("b")
    enviados = _espiar(b)
    b.add_peer(HOST, a.port)
    assert _esperar(lambda: b.blockchain.last_block.hash == a.blockchain.last_block.hash), \
        f"B quedó en la altura {b.blockchain.height} (A en {a.blockchain.height})"
    assert b.blockchain.validate_chain()[0]
    lotes = [m for m in enviados if m.get("type") == MSG_GET_BLOCKS]
    assert len(lotes) >= 3                 # la cadena no cabía en un mensaje: varios lotes
    assert lotes[0]["from"] == 1           # B solo tenía el génesis


def test_nodo_borrado_y_reiniciado_vuelve_a_sincronizar(red, tmp_path):
    bc_a = red.cadena("a")
    _minar(bc_a, 10, txs_por_bloque=2)
    a = red.nodo("a", bc=bc_a)
    b = red.nodo("b", peers=[a])
    assert _esperar(lambda: b.blockchain.height == a.blockchain.height)
    b.stop()
    b.blockchain.close()
    red.nodos.remove(b)
    shutil.rmtree(tmp_path / "b")          # DATA_DIR borrado, como en el despliegue
    b2 = red.nodo("b", peers=[a])
    assert _esperar(lambda: b2.blockchain.last_block.hash == a.blockchain.last_block.hash)


def test_cadenas_divergentes_reorganizan_bajando_solo_desde_la_bifurcacion(red):
    """B tiene 3 bloques en común con A y 2 propios; A tiene 5 propios (más trabajo)."""
    bc_a = red.cadena("a")
    _minar(bc_a, 3, txs_por_bloque=1)
    bc_b = red.cadena("b")
    assert bc_b.replace_chain([blk.to_dict() for blk in bc_a.chain])[0]
    comun = bc_a.chain[3].hash
    _minar(bc_a, 5, txs_por_bloque=2)
    _minar(bc_b, 2, txs_por_bloque=1)
    assert bc_b.chain[3].hash == comun and bc_b.chain[4].hash != bc_a.chain[4].hash

    a = red.nodo("a", bc=bc_a)
    b = red.nodo("b", bc=bc_b)
    b._HASHES_PER_MSG = 2                  # obliga a retroceder varios lotes de hashes
    enviados = _espiar(b)
    reorgs = []
    bc_b.add_reorg_listener(lambda fork, dropped, added: reorgs.append((fork, len(dropped))))
    b.add_peer(HOST, a.port)
    assert _esperar(lambda: b.blockchain.last_block.hash == a.blockchain.last_block.hash)
    # El aviso de reorganización se emite DESPUÉS de reemplazar la cadena (fuera del lock).
    assert _esperar(lambda: reorgs)
    assert reorgs[0] == (3, 2)
    hashes = [m for m in enviados if m.get("type") == MSG_GET_HASHES]
    lotes = [m for m in enviados if m.get("type") == MSG_GET_BLOCKS]
    assert len(hashes) >= 2
    assert lotes and min(m["from"] for m in lotes) == 4   # nada anterior a la bifurcación


def test_get_blocks_respeta_cantidad_y_bytes(red):
    bc_a = red.cadena("a")
    _minar(bc_a, 8, txs_por_bloque=2)
    a = red.nodo("a", bc=bc_a)
    cliente = red.nodo("c")
    r = cliente._request(HOST, a.port, {"type": MSG_GET_BLOCKS, "from": 1, "count": 10_000,
                                        "max_bytes": 10 ** 9})
    assert r["type"] == MSG_BLOCKS and r["height"] == 8
    assert 1 <= len(r["data"]) < 8         # cortado por bytes (tope del servidor)
    assert len(json.dumps(r)) <= TOPE
    assert [blk["header"]["index"] for blk in r["data"]] == list(range(1, 1 + len(r["data"])))
    # Desde más allá de la punta: lote vacío, no error.
    vacio = cliente._request(HOST, a.port, {"type": MSG_GET_BLOCKS, "from": 50, "count": 5})
    assert vacio["data"] == []
    h = cliente._request(HOST, a.port, {"type": MSG_GET_HASHES, "from": 0, "count": 10 ** 6})
    assert h["type"] == MSG_HASHES and h["data"] == [blk.hash for blk in bc_a.chain]


def test_marco_demasiado_grande_se_registra_en_una_linea_sin_traza(red, caplog):
    a = red.nodo("a")
    with caplog.at_level(logging.WARNING, logger="upb_chain.network"):
        with socket.create_connection((HOST, a.port), timeout=5) as s:
            s.sendall(struct.pack(">I", TOPE + 1) + b"{")
            s.settimeout(5)
            try:
                assert s.recv(1) == b""    # el servidor cierra la conexión
            except ConnectionResetError:
                pass                        # Windows: el cierre llega como RST
        assert _esperar(lambda: any("inválido" in r.getMessage() for r in caplog.records), 5)
    assert not any(r.exc_info for r in caplog.records)
    # El servidor sigue atendiendo.
    c = red.nodo("c")
    assert c.connect_to_peer(HOST, a.port)


def test_get_network_sync_ya_no_vuelca_la_cadena(tmp_path):
    """El volcado HTTP sin autenticación (no lo usaba nadie) se eliminó; POST sigue (admin)."""
    from fastapi.testclient import TestClient
    from tests.helpers import make_app
    app = make_app(tmp_path)
    with TestClient(app, base_url="http://127.0.0.1") as c:
        r = c.get("/network/sync")
        assert r.status_code == 405 and "chain" not in r.text
        assert c.post("/network/sync").status_code == 200


def test_puesta_al_dia_agrega_por_lotes_y_el_progreso_persiste(red, tmp_path):
    """P0-5: la altura sube lote a lote; un corte a mitad conserva lo agregado y se reanuda."""
    bc_a = red.cadena("a")
    _minar(bc_a, 9)
    a = red.nodo("a", bc=bc_a)
    # Sin sondeo periódico: con carga, el mantenimiento de B/C sincronizaba por su cuenta y
    # ``sync_with`` devolvía False porque otro hilo ya había puesto al día (comportamiento
    # correcto del producto, serializado por ``_sync_lock``; la carrera era del test).
    b = red.nodo("b", sync_interval=3600)
    b._BLOCKS_PER_MSG = 3                      # solo esta instancia pide lotes de 3
    alturas = []
    original = b.blockchain.add_block

    def espia(block, *args, **kwargs):
        alturas.append(b.blockchain.height)
        return original(block, *args, **kwargs)

    b.blockchain.add_block = espia
    assert b.sync_with(f"{HOST}:{a.port}")
    assert b.blockchain.height == 9
    assert alturas[:9] == list(range(9))       # un add_block por bloque, altura creciente

    c = red.nodo("c", sync_interval=3600)
    c._BLOCKS_PER_MSG = 3
    pedidos = []
    orig_req = c.request_blocks

    cortar = [True]

    def corta(addr, start, count):
        pedidos.append(start)
        if cortar[0] and len(pedidos) > 2:
            return None
        return orig_req(addr, start, count)

    c.request_blocks = corta
    c.sync_with(f"{HOST}:{a.port}")
    # 2 lotes persistidos pese al corte. ``>=``: tras el corte el par se reconecta (backoff de
    # 0,2 s) y ese handshake puede reanudar la sincronización por su cuenta antes de este assert.
    assert c.blockchain.height >= 6
    assert pedidos[:2] == [1, 4]               # el corte llegó en el tercer lote, no antes
    cortar[0] = False
    # La reanudación puede hacerla esta llamada o la reconexión en segundo plano (serializadas
    # por ``_sync_lock``); lo que importa es que se complete sin volver a empezar desde 0.
    c.sync_with(f"{HOST}:{a.port}")
    assert _esperar(lambda: c.blockchain.height == 9)
    assert min(pedidos[2:], default=7) >= 7    # nunca se volvió a pedir desde el principio
