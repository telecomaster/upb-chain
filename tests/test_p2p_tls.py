"""P2-6: TLS mutuo, lista blanca y conexiones persistentes en el P2P (sockets reales en loopback).

Los certificados se generan en ``tmp_path`` con las mismas funciones que usan los scripts.
"""
import pytest

from blockchain.network.node import MSG_PING, P2PNode
from security.pki import crear_ca, emitir_cert_nodo
from tests.test_pbft_red import RedPBFT, esperar

pytestmark = pytest.mark.integration

HOST = "127.0.0.1"


def _tls(directorio, node_id):
    return {"ca": str(directorio / "ca.crt"), "cert": str(directorio / f"{node_id}.crt"),
            "key": str(directorio / f"{node_id}.key")}


def _nodo(directorio, node_id, puerto=0, **kw):
    n = P2PNode(node_id, HOST, puerto, sync_interval=0.5, retry_base=0.1,
                tls=_tls(directorio, node_id), **kw)
    n.start()
    return n


@pytest.fixture
def pki(tmp_path):
    d = tmp_path / "tls"
    crear_ca(d)
    for nid in ("a", "b", "c"):
        emitir_cert_nodo(d, nid, [HOST])
    return d


@pytest.fixture
def nodos():
    lista = []
    yield lista
    for n in lista:
        n.stop()


def _activo(n, otro):
    return any(p.is_active and p.port == otro.port for p in n.peers_snapshot())


def test_dos_nodos_con_mtls_se_conectan_y_usan_tls_13(pki, nodos):
    a, b = _nodo(pki, "a"), _nodo(pki, "b")
    nodos += [a, b]
    assert a.connect_to_peer(HOST, b.port) is True
    assert _activo(a, b) and esperar(lambda: _activo(b, a), 5)
    enlace = a._links[(HOST, b.port, "ctl")]
    assert enlace.sock.version() == "TLSv1.3" and enlace.cn == "b"
    assert a._request(HOST, b.port, {"type": MSG_PING})["node_id"] == "b"


def test_cert_de_otra_ca_es_rechazado(pki, tmp_path, nodos):
    otra = tmp_path / "otra"
    crear_ca(otra)
    emitir_cert_nodo(otra, "x", [HOST])
    a, x = _nodo(pki, "a"), _nodo(otra, "x")
    nodos += [a, x]
    assert x.connect_to_peer(HOST, a.port) is False
    assert a.connect_to_peer(HOST, x.port) is False
    assert not _activo(a, x) and not _activo(x, a)


def test_cert_valido_fuera_de_la_lista_blanca_es_rechazado_y_alerta(pki, nodos):
    alertas = []
    a = _nodo(pki, "a", allowlist=["a", "b"], on_unknown_peer=alertas.append)
    b, c = _nodo(pki, "b"), _nodo(pki, "c")
    nodos += [a, b, c]
    # entrante: a corta la conexión de c (certificado válido, CN fuera de la lista) y avisa
    assert c.connect_to_peer(HOST, a.port) is False
    assert esperar(lambda: any(x.startswith("c@") for x in alertas), 5)
    assert not _activo(a, c)
    # saliente: a tampoco acepta hablar con c
    assert a.connect_to_peer(HOST, c.port) is False
    # b sí está permitido
    assert b.connect_to_peer(HOST, a.port) is True
    assert esperar(lambda: _activo(a, b), 5)


def test_sin_tls_la_lista_blanca_solo_avisa(nodos):
    alertas = []
    a = P2PNode("a", HOST, 0, allowlist=["a"], on_unknown_peer=alertas.append)
    z = P2PNode("zeta", HOST, 0)
    nodos += [a, z]
    a.start()
    z.start()
    assert z.connect_to_peer(HOST, a.port) is True          # no se rechaza
    assert alertas == ["zeta (no autenticado)"]


def test_node_id_anunciado_debe_coincidir_con_el_cn(pki, nodos):
    a = _nodo(pki, "a")
    impostor = P2PNode("a", HOST, 0, tls=_tls(pki, "b"))     # cert de b diciendo ser "a"
    impostor.start()
    nodos += [a, impostor]
    assert impostor.connect_to_peer(HOST, a.port) is False
    assert not _activo(a, impostor)


def test_conexion_persistente_se_reutiliza(pki, nodos):
    a, b = _nodo(pki, "a"), _nodo(pki, "b")
    nodos += [a, b]
    for _ in range(5):
        assert a._request(HOST, b.port, {"type": MSG_PING})["type"] == "PONG"
    assert len(b._inbound) == 1                              # una sola conexión para 5 mensajes


def test_reconexion_tras_reinicio_del_par(pki, nodos):
    a, b = _nodo(pki, "a"), _nodo(pki, "b")
    nodos += [a, b]
    puerto = b.port
    assert a.connect_to_peer(HOST, puerto) is True
    b.stop()
    assert esperar(lambda: not _activo(a, b), 10)            # a detecta la caída
    b2 = _nodo(pki, "b", puerto=puerto)
    nodos.append(b2)
    assert esperar(lambda: _activo(a, b2), 15)               # y reconecta con backoff
    assert a._request(HOST, puerto, {"type": MSG_PING})["node_id"] == "b"


def test_pbft_4_replicas_confirma_sobre_mtls(tmp_path):
    d = tmp_path / "tls"
    crear_ca(d)
    for rid in ("r0", "r1", "r2", "r3"):
        emitir_cert_nodo(d, rid, [HOST])
    red = RedPBFT(tmp_path / "red", p2p_tls="on", p2p_tls_dir=str(d))
    try:
        red.iniciar(*red.ids)
        red.enviar_tx("r1")
        assert esperar(lambda: all(red.altura(r) == 1 for r in red.ids), 15)
        enlaces = red.nodo("r0").p2p._links
        assert any(k[2] == "pbft" and v.sock is not None and v.sock.version() == "TLSv1.3"
                   for k, v in enlaces.items())
    finally:
        red.cerrar()


def test_tls_activado_sin_certificados_es_error_de_configuracion(tmp_path):
    from config import ConfigError
    from tests.helpers import make_app
    with pytest.raises(ConfigError, match="P2P_TLS_DIR"):
        make_app(tmp_path, "n1", p2p_tls="on", p2p_tls_dir=str(tmp_path / "no_hay"))
