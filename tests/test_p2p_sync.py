"""Tests de P0-5: sincronización P2P con sockets reales en 127.0.0.1.

Cada nodo = Blockchain (directorio propio en tmp_path) + P2PNode en un puerto
efímero (port=0). Se espera con sondeo y timeout, nunca con sleeps largos fijos.
"""
import socket
import time

import pytest

from blockchain.core.chain import Blockchain
from blockchain.core.transaction import Transaction, TransactionType
from blockchain.core.wallet import Wallet
from blockchain.network.node import MSG_GET_PEERS, MSG_SYNC_REQUEST, P2PNode
from tests.helpers import mine_candidate

pytestmark = pytest.mark.integration

HOST = "127.0.0.1"


def _esperar(condicion, timeout=10.0, intervalo=0.05):
    limite = time.time() + timeout
    while time.time() < limite:
        if condicion():
            return True
        time.sleep(intervalo)
    return condicion()


def _puerto_libre():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        return s.getsockname()[1]


class _Red:
    """Crea nodos y garantiza que todos se detengan al final del test."""

    def __init__(self, tmp_path):
        self.tmp_path = tmp_path
        self.nodos = []

    def cadena(self, nombre):
        return Blockchain(nombre, str(self.tmp_path / nombre), initial_difficulty=1, max_difficulty=2)

    def nodo(self, nombre, peers=(), bc=None, port=0, **kw):
        bc = bc or self.cadena(nombre)
        params = dict(sync_interval=0.5, retry_base=0.2, retry_max=1.0, timeout=5.0)
        params.update(kw)
        node = P2PNode(nombre, HOST, port, blockchain=bc, **params)
        node.start()
        self.nodos.append(node)
        for p in peers:
            node.add_peer(HOST, p.port if isinstance(p, P2PNode) else p)
        return node

    def detener(self):
        for n in self.nodos:
            n.stop()


@pytest.fixture
def red(tmp_path):
    r = _Red(tmp_path)
    yield r
    r.detener()


def _minar(node, n=1, txs=None):
    for _ in range(n):
        bloque = mine_candidate(node.blockchain, txs)
        ok, motivo = node.blockchain.add_block(bloque)
        assert ok, motivo
        node.broadcast_block(bloque.to_dict())


def _alcanzo(b, a):
    return lambda: b.blockchain.last_block.hash == a.blockchain.last_block.hash


def test_nodo_arrancado_despues_alcanza_al_primero(red):
    a = red.nodo("a")
    _minar(a, 5)
    b = red.nodo("b", peers=[a])
    assert _esperar(_alcanzo(b, a)), f"B quedó en altura {b.blockchain.height}"
    assert b.blockchain.height == 5
    # A aprendió a B por el handshake, con la dirección anunciada (no 0.0.0.0).
    assert _esperar(lambda: f"{HOST}:{b.port}" in a.peers and a.peers[f"{HOST}:{b.port}"].is_active)


def test_reinicio_de_b_recupera_lo_minado_mientras_estaba_caido(red, tmp_path):
    a = red.nodo("a")
    _minar(a, 2)
    b = red.nodo("b", peers=[a])
    assert _esperar(_alcanzo(b, a))
    b.stop()

    _minar(a, 3)            # B está caído: el broadcast a B falla
    assert b.blockchain.height == 2

    # B "reinicia": recarga su cadena desde disco y vuelve a conectarse a A.
    b2 = red.nodo("b", peers=[a], bc=red.cadena("b"))
    assert b2.blockchain.height == 2
    assert _esperar(_alcanzo(b2, a))
    assert b2.blockchain.height == 5


def test_reconexion_con_backoff_cuando_el_par_vuelve(red):
    puerto_a = _puerto_libre()
    b = red.nodo("b", peers=[puerto_a])          # A todavía no existe
    assert _esperar(lambda: b.peers[f"{HOST}:{puerto_a}"].failed_attempts >= 1)
    assert not b.peers[f"{HOST}:{puerto_a}"].is_active

    bc_a = red.cadena("a")
    for _ in range(3):
        bc_a.add_block(mine_candidate(bc_a))
    red.nodo("a", bc=bc_a, port=puerto_a)          # A aparece con 3 bloques
    assert _esperar(lambda: b.blockchain.height == 3)
    assert b.peers[f"{HOST}:{puerto_a}"].is_active


def test_bloque_minado_en_b_se_propaga_a_a(red):
    # sync_interval largo: sólo la propagación (push) puede explicar la llegada.
    a = red.nodo("a", sync_interval=60)
    b = red.nodo("b", peers=[a], sync_interval=60)
    assert _esperar(lambda: any(p.is_active for p in a.peers_snapshot()))
    assert _esperar(lambda: any(p.is_active for p in b.peers_snapshot()))

    _minar(b, 1)
    assert _esperar(_alcanzo(a, b))
    _minar(a, 1)
    assert _esperar(_alcanzo(b, a))
    assert a.blockchain.height == b.blockchain.height == 2


def test_bloque_que_no_extiende_la_punta_dispara_sincronizacion(red):
    a = red.nodo("a", sync_interval=60)
    b = red.nodo("b", peers=[a], sync_interval=60)
    assert _esperar(lambda: any(p.is_active for p in a.peers_snapshot()))
    # A mina 3 bloques SIN anunciarlos; luego anuncia sólo el último.
    for _ in range(3):
        a.blockchain.add_block(mine_candidate(a.blockchain))
    a.broadcast_block(a.blockchain.last_block.to_dict())
    assert _esperar(_alcanzo(b, a))


def test_bloque_invalido_se_ignora(red):
    a = red.nodo("a", sync_interval=60)
    b = red.nodo("b", peers=[a], sync_interval=60)
    assert _esperar(lambda: any(p.is_active for p in a.peers_snapshot()))
    falso = mine_candidate(a.blockchain)
    falso.header.difficulty = 0
    falso.hash = falso.compute_hash()
    a.broadcast_block(falso.to_dict())
    _minar(a, 1)                       # un bloque válido posterior sí llega
    assert _esperar(_alcanzo(b, a))
    assert b.blockchain.height == 1
    assert b.blockchain.get_block_by_hash(falso.hash) is None


def test_tx_se_propaga_al_mempool_del_par(red):
    a = red.nodo("a", sync_interval=60)
    b = red.nodo("b", peers=[a], sync_interval=60)
    assert _esperar(lambda: any(p.is_active for p in a.peers_snapshot()))
    w = Wallet.generate()
    tx = Transaction(type=TransactionType.DATA_RECORD, sender=w.address,
                     recipient="DEST", payload={"x": 1}, nonce=1)
    tx.sign(w.private_key_hex)
    assert a.blockchain.add_transaction(tx)[0]
    a.broadcast_transaction(tx.to_dict())
    assert _esperar(lambda: any(t.tx_id == tx.tx_id for t in b.blockchain.mempool))
    assert len(b.blockchain.mempool) == 1


def test_par_con_otro_genesis_es_rechazado(red):
    a = red.nodo("a")
    _minar(a, 2)
    c = red.nodo("c", sync_interval=60)
    c.genesis_hash = "f" * 64          # simula una red distinta
    assert c.connect_to_peer(HOST, a.port) is False
    assert f"{HOST}:{a.port}" not in c.peers
    assert not any(p.node_id == "c" for p in a.peers_snapshot())
    assert c.blockchain.height == 0
    # Y A tampoco acepta a C cuando es A quien marca.
    assert a.connect_to_peer(HOST, c.port) is False
    assert f"{HOST}:{c.port}" not in a.peers


def test_get_blocks_sync_request_y_peers_responden_datos_reales(red):
    """Regresión: GET_CHAIN devolvía la petición, SYNC_REQUEST altura 0, PEERS fallaba.
    (GET_CHAIN se reemplazó por GET_BLOCKS por lotes, P0-5.)"""
    a = red.nodo("a")
    _minar(a, 2)
    b = red.nodo("b", peers=[a])
    assert _esperar(_alcanzo(b, a))

    cadena = b.request_blocks(f"{HOST}:{a.port}", 0, 10)["data"]
    assert [blk["hash"] for blk in cadena] == [blk.hash for blk in a.blockchain.chain]

    estado = b._request(HOST, a.port, {"type": MSG_SYNC_REQUEST})
    assert estado["height"] == 2
    assert estado["work"] == a.blockchain.total_work
    assert estado["genesis_hash"] == a.blockchain.chain[0].hash

    peers = b._request(HOST, a.port, {"type": MSG_GET_PEERS})["data"]
    assert {"host": HOST, "port": b.port}.items() <= peers[0].items()


def test_par_que_anuncia_0000_se_registra_con_su_ip_real(red):
    a = red.nodo("a")
    x = P2PNode("x", HOST, 0, advertise_host="0.0.0.0", blockchain=red.cadena("x"),
                sync_interval=60, retry_base=0.2, retry_max=1.0)
    x.start()
    red.nodos.append(x)
    assert x.connect_to_peer(HOST, a.port)
    assert f"{HOST}:{x.port}" in a.peers
    assert not any(p.host == "0.0.0.0" for p in a.peers_snapshot())


def test_handshake_registra_al_par_antes_de_responder(red):
    """Regresión (carrera): el receptor debe registrar al par antes de enviar su HANDSHAKE;
    si no, el cliente vuelve de connect_to_peer y aún no figura en los pares del receptor."""
    a = red.nodo("a")
    b = red.nodo("b")
    visto = []
    original = a._send_framed

    def espia(conn, message):
        if message.get("type") == "HANDSHAKE":
            visto.append(f"{HOST}:{b.port}" in a.peers)
        return original(conn, message)

    a._send_framed = espia
    assert b.connect_to_peer(HOST, a.port)
    assert visto and all(visto)


def _minar_local(node, n):
    for _ in range(n):
        ok, motivo = node.blockchain.add_block(mine_candidate(node.blockchain))
        assert ok, motivo


def test_bloques_competidores_simultaneos_no_se_bloquean_mutuamente(red):
    """P0-5: dos nodos que reciben a la vez el bloque del otro no esperan al timeout.

    Antes, NEW_BLOCK llamaba a sync_with dentro del hilo que atiende la conexión:
    ambos nodos se pedían la cadena a la vez y se bloqueaban hasta el timeout (10 s).
    """
    import threading
    a = red.nodo("a", sync_interval=60, timeout=10.0)
    b = red.nodo("b", sync_interval=60, timeout=10.0)
    a.add_peer(HOST, b.port)
    b.add_peer(HOST, a.port)
    assert _esperar(lambda: all(p.is_active for n in (a, b) for p in n.peers_snapshot()))
    # Cadenas divergentes (se mina tras conectar, sin sync previo); B con más trabajo.
    _minar_local(a, 2)
    _minar_local(b, 3)
    barrera = threading.Barrier(2)

    def difundir(n):
        barrera.wait()
        n.broadcast_block(n.blockchain.last_block.to_dict())

    t0 = time.perf_counter()
    hilos = [threading.Thread(target=difundir, args=(n,)) for n in (a, b)]
    for h in hilos:
        h.start()
    for h in hilos:
        h.join(15)
    assert _esperar(_alcanzo(a, b), timeout=15)
    elapsed = time.perf_counter() - t0
    assert elapsed < 3.0, f"convergencia tardó {elapsed:.1f} s (bloqueo mutuo hasta el timeout)"
    assert a.blockchain.height == 3


def test_rafaga_de_bloques_no_lanza_hilos_de_sync_sin_limite(red, monkeypatch):
    """Una ráfaga de 50 NEW_BLOCK sobre el mismo par genera una sync en vuelo, no 50."""
    import threading
    a = red.nodo("a", sync_interval=60)
    lanzados = []
    soltar = threading.Event()

    def sync_lenta(addr):
        lanzados.append(addr)
        soltar.wait(5)
        return False

    monkeypatch.setattr(a, "sync_with", sync_lenta)
    for _ in range(50):
        a._sync_en_segundo_plano("127.0.0.1:9")
    assert _esperar(lambda: len(lanzados) == 1)
    time.sleep(0.2)
    assert len(lanzados) == 1
    soltar.set()
    # Lo coalescido produce, como mucho, una pasada adicional.
    assert _esperar(lambda: not a._sync_bg)
    assert len(lanzados) <= 2


def test_recorrer_pares_mientras_otro_hilo_los_modifica_no_falla():
    """Regresión (CI intermitente): ``dictionary changed size during iteration``.

    Los hilos de conexión agregan y quitan pares de ``node.peers`` mientras otros hilos
    (tests, API, métricas) los recorren. Un hilo alterna altas y bajas por la API del nodo y
    otro lee con los accesores públicos, que nunca deben fallar. (Con esta carga, recorrer el
    dict crudo falla miles de veces por segundo en un portátil; no se afirma aquí porque
    depende del planificador de hilos y volvería intermitente el test.)
    """
    import sys
    import threading

    previo = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)          # cambios de hilo muy frecuentes: la carrera aflora
    nodo = P2PNode("a", HOST, 0)         # sin start(): sólo la estructura de pares
    alto = threading.Event()

    def agitar():
        i = 0
        while not alto.is_set():
            i += 1
            host = f"10.0.{(i // 250) % 250}.{i % 250}"
            nodo._register_peer(host, 9000, {"node_id": host})
            if i % 2 == 0:
                nodo.remove_peer(f"10.0.{((i - 40) // 250) % 250}.{(i - 40) % 250}:9000")

    def contar_errores(leer, segundos):
        errores, limite = 0, time.perf_counter() + segundos
        while time.perf_counter() < limite:
            try:
                leer()
            except RuntimeError:
                errores += 1
        return errores

    hilo = threading.Thread(target=agitar, daemon=True)
    hilo.start()
    try:
        seguros = contar_errores(lambda: (
            any(p.is_active and False for p in nodo.peers_snapshot()),
            nodo.active_peers(),
            nodo.get_network_stats(),
            nodo._status(),
        ), 0.7)
    finally:
        alto.set()
        hilo.join(2)
        sys.setswitchinterval(previo)
    assert seguros == 0


def test_nodo_reiniciado_vuelve_a_registrar_a_sus_pares_entrantes(red):
    """A (sin PEERS) se reinicia; B (PEERS=A) le vuelve a hablar y A debe re-registrar a B.

    Sin HANDSHAKE al reabrir el enlace, A queda con 0 pares y sus bloques solo llegan a B
    por el sondeo de estado (aquí desactivado con sync_interval grande)."""
    puerto_a = _puerto_libre()
    a = red.nodo("a", port=puerto_a, sync_interval=600)
    b = red.nodo("b", peers=[a], sync_interval=600)
    assert _esperar(lambda: a.get_peer(f"{HOST}:{b.port}") is not None)

    a.stop()
    a2 = red.nodo("a", port=puerto_a, sync_interval=600)   # misma cadena en disco, sin pares
    assert a2.get_peer(f"{HOST}:{b.port}") is None

    _minar(b)                                              # B reabre el enlace hacia A
    assert _esperar(_alcanzo(a2, b))
    assert _esperar(lambda: a2.get_peer(f"{HOST}:{b.port}") is not None), "A no re-registró a B"

    _minar(a2)                                             # ahora A le empuja el bloque a B
    assert _esperar(_alcanzo(b, a2), timeout=5), "el bloque de A no llegó a B sin esperar el sondeo"
