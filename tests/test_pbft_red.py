"""P1-1: PBFT con 4 apps reales en el mismo proceso (app factory + P2P en loopback).

Cada prueba arranca las réplicas que necesita con ``ClienteASGI`` (lifespan: P2P,
transporte PBFT y temporizadores). Toda espera está acotada (``esperar``).
"""
import contextlib
import json
import socket
import time

import pytest
from api.cliente_asgi import ClienteASGI

from blockchain.consensus.pbft import PRE_PREPARE, sign_message
from blockchain.core.block import Block, BlockHeader
from blockchain.core.wallet import Wallet
from tests.helpers import make_app

pytestmark = pytest.mark.integration

TIMEOUT_VISTA = 1.0


def _puertos_libres(n):
    socks = []
    for _ in range(n):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        socks.append(s)
    puertos = [s.getsockname()[1] for s in socks]
    for s in socks:
        s.close()
    return puertos


def esperar(cond, limite=10.0, paso=0.05):
    fin = time.time() + limite
    while time.time() < fin:
        if cond():
            return True
        time.sleep(paso)
    return cond()


class RedPBFT:
    """4 réplicas PBFT (r0..r3) con llaves, lista de réplicas y apps sin arrancar."""

    def __init__(self, tmp_path, n=4, **extra):
        tmp_path.mkdir(parents=True, exist_ok=True)
        self.ids = [f"r{i}" for i in range(n)]
        self.puertos = _puertos_libres(n)
        self.wallets = [Wallet.generate() for _ in range(n)]
        self.lista = tmp_path / "pbft_replicas.json"
        with open(self.lista, "w", encoding="utf-8") as f:
            json.dump({"replicas": [
                {"id": rid, "address": f"127.0.0.1:{p}", "public_key": w.public_key_hex}
                for rid, p, w in zip(self.ids, self.puertos, self.wallets)]}, f)
        self.apps = {}
        for i, rid in enumerate(self.ids):
            llave = tmp_path / f"{rid}_pbft.json"
            self.wallets[i].export(str(llave))
            self.apps[rid] = make_app(
                tmp_path, rid, consensus="pbft", node_host="127.0.0.1",
                node_advertise_host="127.0.0.1", node_port=self.puertos[i],
                pbft_replicas_file=str(self.lista), pbft_key_file=str(llave),
                pbft_view_timeout=TIMEOUT_VISTA, pbft_batch_interval=0.05, **extra)
        self.clientes = {}
        self._pila = contextlib.ExitStack()

    def iniciar(self, *ids):
        for rid in ids:
            self.clientes[rid] = self._pila.enter_context(ClienteASGI(self.apps[rid]))
        for rid in ids:   # pares activos: el gossip de TXs llega a todos los vivos
            vivos = len(self.clientes) - 1
            assert esperar(lambda r=rid, v=vivos: self.nodo(r).p2p.get_network_stats()
                           ["active_peers"] >= v, 10), f"{rid} sin pares"

    def cerrar(self):
        self._pila.close()

    def nodo(self, rid):
        return self.apps[rid].state.node

    def altura(self, rid):
        return self.nodo(rid).blockchain.height

    def enviar_tx(self, rid, i=0):
        w = Wallet.generate()
        r = self.clientes[rid].post("/transactions", json={
            "type": "DATA_RECORD", "sender": w.address, "recipient": "UPB_DEST",
            "payload": {"dato": f"registro {i}"}, "private_key_hex": w.private_key_hex})
        assert r.status_code == 200, r.text
        return r.json()["tx_id"]


@pytest.fixture
def red(tmp_path):
    red = RedPBFT(tmp_path)
    yield red
    red.cerrar()


def test_caso_normal_4_replicas_consenso_api_metricas_y_eventos(red):
    eventos = []
    for rid in red.ids:
        bus = red.nodo(rid).events
        original = bus.publish
        bus.publish = lambda ev, data=None, o=original: (eventos.append((ev, data)), o(ev, data))
    red.iniciar(*red.ids)
    tx_id = red.enviar_tx("r1")
    assert esperar(lambda: all(red.altura(r) == 1 for r in red.ids), 10)
    hashes = {red.nodo(r).blockchain.last_block.hash for r in red.ids}
    assert len(hashes) == 1
    for rid in red.ids:
        bc = red.nodo(rid).blockchain
        assert bc.get_transaction(tx_id) is not None
        assert bc.check_certificate(bc.last_block, bc.certificates[1]) == (True, "OK")
    c = red.clientes["r2"]
    estado = c.get("/consensus").json()
    assert estado["mode"] == "pbft" and estado["view"] == 0 and estado["primary"] == "r0"
    assert estado["last_committed_seq"] == 1 and (estado["n"], estado["f"]) == (4, 1)
    assert [x["id"] for x in estado["replicas"]] == red.ids
    r = c.post("/blocks/mine", json={"miner_address": "M"})
    assert r.status_code == 409 and "PBFT" in r.json()["detail"]
    metricas = c.get("/metrics").text
    assert 'upb_consensus_info{mode="pbft"} 1.0' in metricas
    assert "upb_pbft_view 0.0" in metricas and "upb_pbft_committed_seq 1.0" in metricas
    fases = {d["phase"] for ev, d in eventos if ev == "pbft_phase"}
    assert {"PRE_PREPARE", "PREPARED", "COMMITTED"} <= fases


def test_una_replica_caida_confirma_y_la_tardia_sincroniza_certificados(red):
    red.iniciar("r0", "r1", "r2")
    red.enviar_tx("r0")
    assert esperar(lambda: all(red.altura(r) == 1 for r in ("r0", "r1", "r2")), 10)
    # r3 llega tarde: HANDSHAKE → GET_CHAIN con certificados → replace_chain los verifica.
    red.iniciar("r3")
    assert esperar(lambda: red.altura("r3") == 1, 10)
    bc3 = red.nodo("r3").blockchain
    assert bc3.last_block.hash == red.nodo("r0").blockchain.last_block.hash
    assert bc3.check_certificate(bc3.last_block, bc3.certificates[1]) == (True, "OK")
    # Y ya participa: el siguiente bloque se confirma en las 4.
    red.enviar_tx("r3", 1)
    assert esperar(lambda: all(red.altura(r) == 2 for r in red.ids), 10)


def test_primario_caido_cambio_de_vista_y_nuevo_primario_confirma(red):
    red.iniciar("r1", "r2", "r3")             # r0 (primario de la vista 0) no arranca
    red.enviar_tx("r2")
    assert esperar(lambda: all(red.altura(r) == 1 for r in ("r1", "r2", "r3")), 15)
    for rid in ("r1", "r2", "r3"):
        est = red.clientes[rid].get("/consensus").json()
        assert est["view"] >= 1 and est["primary"] != "r0" and est["view_changes"] >= 1
    assert "upb_pbft_view_changes_total" in red.clientes["r1"].get("/metrics").text


def test_dos_replicas_caidas_no_hay_commit(red):
    red.iniciar("r0", "r1")
    red.enviar_tx("r0")
    time.sleep(3 * TIMEOUT_VISTA)
    assert red.altura("r0") == 0 and red.altura("r1") == 0
    assert not red.nodo("r0").blockchain.certificates


def test_primario_que_equivoca_por_la_red_no_produce_dos_bloques(red):
    red.iniciar("r1", "r2", "r3")             # r0 = primario bizantino controlado por la prueba
    red.enviar_tx("r1")
    bc1 = red.nodo("r1").blockchain
    assert esperar(lambda: all(len(red.nodo(r).blockchain.mempool) == 1
                               for r in ("r1", "r2", "r3")), 5)
    a = bc1.create_candidate_block()
    b = Block(header=BlockHeader(**{**a.header.__dict__, "timestamp": a.header.timestamp + 1}),
              transactions=a.transactions)

    def pp(bloque):
        m = sign_message({"type": PRE_PREPARE, "replica": "r0", "view": 0, "seq": 1,
                          "digest": bloque.hash}, red.wallets[0].private_key_hex)
        m["block"] = bloque.to_dict()
        return m
    p2p = red.nodo("r1").p2p
    orden = {"r1": (a, b), "r2": (b, a), "r3": (b, a)}
    for rid, (primero, segundo) in orden.items():
        puerto = red.puertos[red.ids.index(rid)]
        p2p.send_pbft("127.0.0.1", puerto, pp(primero))
        time.sleep(0.15)
        p2p.send_pbft("127.0.0.1", puerto, pp(segundo))
    assert esperar(lambda: all(any(x["event_type"] == "PBFT_EQUIVOCATION"
                                   for x in red.nodo(r).security_monitor.get_alerts())
                               for r in ("r1", "r2", "r3")), 5)
    # El cambio de vista re-propone B (prepared en r2 y r3); A nunca se confirma.
    assert esperar(lambda: all(red.altura(r) == 1 for r in ("r1", "r2", "r3")), 15)
    assert {red.nodo(r).blockchain.chain[1].hash for r in ("r1", "r2", "r3")} == {b.hash}


def test_modo_de_consenso_distinto_rechaza_el_handshake(red, tmp_path):
    red.iniciar("r0")
    pow_app = make_app(tmp_path, "pow_nodo", node_host="127.0.0.1",
                       node_advertise_host="127.0.0.1")
    with ClienteASGI(pow_app) as c:
        r = c.post("/network/peers", params={"host": "127.0.0.1", "port": red.puertos[0]})
        assert r.json()["connected"] is False
        assert c.get("/consensus").json()["mode"] == "pow"
        nodo_pow = pow_app.state.node
        ok = red.nodo("r0").p2p.connect_to_peer("127.0.0.1", nodo_pow.p2p.port)
        assert ok is False
        assert nodo_pow.p2p.get_network_stats()["active_peers"] == 0


def test_llave_de_replica_que_no_coincide_da_error_de_configuracion(tmp_path):
    from config import ConfigError
    red = RedPBFT(tmp_path / "a")
    otra = tmp_path / "otra.json"
    Wallet.generate().export(str(otra))
    with pytest.raises(ConfigError, match="PBFT_KEY_FILE"):
        make_app(tmp_path, "r1", consensus="pbft", pbft_replicas_file=str(red.lista),
                 pbft_key_file=str(otra))
    with pytest.raises(ConfigError, match="PBFT_REPLICAS_FILE"):
        make_app(tmp_path, "r1b", consensus="pbft",
                 pbft_replicas_file=str(tmp_path / "no_existe.json"))


def test_primario_que_pierde_los_commit_se_pone_al_dia_por_la_red(red):
    """Regresión: el primario r0 pierde todos los COMMIT de la altura 1. Antes esperaba la
    sincronización periódica (~15 s) y lanzaba cambios de vista solitarios; ahora pide el
    certificado de commit (CERT-REQUEST) y se pone al día sin cambiar de vista."""
    p2p0 = red.nodo("r0").p2p
    entrega = p2p0.on_pbft_message

    def sin_commits(m):
        if isinstance(m, dict) and m.get("type") == "COMMIT" and m.get("seq") == 1:
            return                                   # mensaje perdido en la red
        entrega(m)
    p2p0.on_pbft_message = sin_commits
    red.iniciar(*red.ids)
    red.enviar_tx("r1")
    assert esperar(lambda: all(red.altura(r) == 1 for r in ("r1", "r2", "r3")), 10)
    inicio = time.time()
    assert esperar(lambda: red.altura("r0") == 1, 5), "r0 no se puso al día"
    assert time.time() - inicio < 3.0
    bc0 = red.nodo("r0").blockchain
    assert bc0.last_block.hash == red.nodo("r1").blockchain.last_block.hash
    assert bc0.check_certificate(bc0.last_block, bc0.certificates[1]) == (True, "OK")
    est = red.clientes["r0"].get("/consensus").json()
    assert est["view"] == 0 and not est["in_view_change"] and est["view_changes"] == 0
    assert est["caught_up_blocks"] == 1
    # Sigue siendo el primario: el siguiente bloque se confirma en las 4.
    red.enviar_tx("r2", 1)
    assert esperar(lambda: all(red.altura(r) == 2 for r in red.ids), 10)
