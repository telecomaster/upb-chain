"""Tests de P1-5: monitor de seguridad conectado y límite de TX aplicado.

Pasan por la API (httpx + ASGI) y por el manejador P2P real, no sólo por las clases.
"""
import os

os.environ.setdefault("NODE_PORT", "0")

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from blockchain.core.block import Block
from blockchain.core.chain import Blockchain
from blockchain.core.transaction import Transaction, TransactionType
from blockchain.core.wallet import Wallet
from blockchain.network.node import MSG_BLOCK, P2PNode
from security.rate_limiter import TxRateLimiter
from tests.helpers import make_app, make_settings, mine_and_add, mine_candidate
from tests.test_p2p_sync import _Red, _esperar, HOST  # noqa: F401  (fixture de red local)


class Reloj:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def fastapi(tmp_path):
    """App propia (create_app) con su cadena en tmp_path."""
    return make_app(tmp_path)


@pytest.fixture
def node(fastapi):
    return fastapi.state.node


@pytest_asyncio.fixture
async def client(fastapi):
    async with AsyncClient(transport=ASGITransport(app=fastapi), base_url="http://test") as ac:
        yield ac


def _tipos(node, desde=0):
    return [a["event_type"] for a in node.security_monitor.get_alerts(limit=10_000)[desde:]]


def _n_alertas(node):
    return len(node.security_monitor.get_alerts(limit=10_000))


def _body(wallet, n, nonce):
    """Cuerpo de POST /transactions firmado por el cliente (nonce explícito, P0-9)."""
    tx = Transaction(type=TransactionType.DATA_RECORD, sender=wallet.address,
                     recipient="DEST", payload={"n": n}, nonce=nonce)
    tx.sign(wallet.private_key_hex)
    return {
        "type": tx.type.value, "sender": tx.sender, "recipient": tx.recipient,
        "payload": tx.payload, "fee": tx.fee, "timestamp": tx.timestamp,
        "signature": tx.signature, "public_key": tx.public_key, "nonce": tx.nonce,
    }


# ── Limitador (unidad, reloj inyectado) ──────────────────────────────────────

def test_limitador_ventana_deslizante_sin_dormir():
    reloj = Reloj()
    lim = TxRateLimiter(limit=3, window=60, clock=reloj)
    assert [lim.check("a")[0] for _ in range(3)] == [True, True, True]
    assert lim.check("a") == (False, 3)
    assert lim.check("b")[0]            # otro emisor no se ve afectado
    reloj.t += 61
    assert lim.check("a")[0]            # la ventana se vació


def test_config_tx_rate_limit(monkeypatch):
    from config import load_settings
    monkeypatch.setenv("TX_RATE_LIMIT", "7")
    assert load_settings(load_env_file=False).tx_rate_limit == 7
    monkeypatch.delenv("TX_RATE_LIMIT")
    assert load_settings(load_env_file=False).tx_rate_limit == 100


# ── API: 429 + alerta ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_exceder_limite_devuelve_429_y_alerta(client, node):
    reloj = Reloj()
    node.tx_rate_limiter = TxRateLimiter(limit=2, window=60, clock=reloj)
    w = Wallet.generate()
    antes = _n_alertas(node)
    assert (await client.post("/transactions", json=_body(w, 1, 1))).status_code == 200
    assert (await client.post("/transactions", json=_body(w, 2, 2))).status_code == 200
    r = await client.post("/transactions", json=_body(w, 3, 3))
    assert r.status_code == 429, r.text
    assert "TX_RATE_LIMIT" in _tipos(node, antes)
    assert not any(t.payload.get("n") == 3 for t in node.blockchain.mempool)

    # otro emisor sigue pudiendo; y al pasar la ventana el primero también
    assert (await client.post("/transactions", json=_body(Wallet.generate(), 1, 1))).status_code == 200
    reloj.t += 61
    # la TX rechazada por el límite no consumió el nonce 3
    assert (await client.post("/transactions", json=_body(w, 4, 3))).status_code == 200

    alertas = (await client.get("/security/alerts")).json()["alerts"]
    assert any(a["event_type"] == "TX_RATE_LIMIT" and a["metadata"]["sender"] == w.address
               for a in alertas)


@pytest.mark.asyncio
async def test_limite_tambien_aplica_a_endpoints_de_credenciales(client, node):
    node.tx_rate_limiter = TxRateLimiter(limit=0, window=60, clock=Reloj())
    r = await client.post("/credentials/revoke", json={
        "revoker_address": "X", "credential_id": "c", "reason": "r",
        "private_key_hex": Wallet.generate().private_key_hex})
    assert r.status_code == 429, r.text


def test_el_limite_no_afecta_la_validacion_de_bloques(tmp_path):
    """Consenso: un bloque con más TX del límite por emisor se acepta igual."""
    bc = Blockchain("n_c", str(tmp_path / "c"), initial_difficulty=1)
    w = Wallet.generate()
    txs = []
    for n in range(make_settings(tmp_path).tx_rate_limit + 5):
        tx = Transaction(type=TransactionType.DATA_RECORD, sender=w.address,
                         recipient="DEST", payload={"n": n}, nonce=n + 1)
        tx.sign(w.private_key_hex)
        txs.append(tx)
    assert mine_and_add(bc, txs)[0]


# ── Bloques: on_block / on_invalid_block / reorg ─────────────────────────────

@pytest.mark.asyncio
async def test_bloque_minado_aparece_en_las_estadisticas_del_monitor(client, node):
    antes = len(node.security_monitor._block_times)
    r = await client.post("/blocks/mine", json={"miner_address": "M"})
    assert r.status_code == 200, r.text
    assert len(node.security_monitor._block_times) == antes + 1
    assert (await client.get("/stats")).json()["security"]["avg_block_rate_per_min"] >= 0


@pytest.mark.asyncio
async def test_bloque_invalido_recibido_por_p2p_genera_alerta(client, node):
    bc = node.blockchain
    falso = bc.create_candidate_block([])
    falso.header.difficulty = 0
    falso.hash = falso.compute_hash()
    antes = _n_alertas(node)
    node.p2p._handle_block({"type": MSG_BLOCK, "data": falso.to_dict()}, None)
    assert bc.height == 0
    assert "INVALID_BLOCK" in _tipos(node, antes)
    alerta = [a for a in node.security_monitor.get_alerts(limit=10_000)[antes:]
              if a["event_type"] == "INVALID_BLOCK"][0]
    assert alerta["metadata"]["reason"]
    assert any(a["event_type"] == "INVALID_BLOCK"
               for a in (await client.get("/security/alerts")).json()["alerts"])


def test_bloque_recibido_valido_se_registra_en_el_monitor(node):
    bc = node.blockchain
    bloque = mine_candidate(bc)
    antes = len(node.security_monitor._block_times)
    node.p2p._handle_block({"type": MSG_BLOCK, "data": bloque.to_dict()}, None)
    assert bc.height == 1
    assert len(node.security_monitor._block_times) == antes + 1


def test_reorganizacion_real_genera_alerta_con_profundidad(tmp_path, node):
    local = Blockchain("loc", str(tmp_path / "loc"), initial_difficulty=1, max_difficulty=2)
    local.add_reorg_listener(node.on_chain_reorg)
    otra = Blockchain("otra", str(tmp_path / "otra"), initial_difficulty=1, max_difficulty=2)
    assert mine_and_add(local)[0]
    assert mine_and_add(otra)[0] and mine_and_add(otra)[0]
    antes = _n_alertas(node)
    ok, motivo = local.replace_chain([b.to_dict() for b in otra.chain])
    assert ok, motivo
    nuevas = node.security_monitor.get_alerts(limit=10_000)[antes:]
    reorg = [a for a in nuevas if a["event_type"] == "CHAIN_REORG"]
    assert len(reorg) == 1 and reorg[0]["metadata"]["depth"] == 1


# ── Pares desconocidos ───────────────────────────────────────────────────────

def test_par_fuera_de_peers_genera_aviso(red):
    vistos = []
    a = red.nodo("a", sync_interval=60, on_unknown_peer=vistos.append, known_peers=["10.9.9.9:1"])
    b = red.nodo("b", peers=[a], sync_interval=60)
    assert _esperar(lambda: vistos)
    assert vistos == [f"{HOST}:{b.port}"]


def test_sin_lista_de_peers_no_hay_pares_desconocidos(red):
    vistos = []
    a = red.nodo("a", sync_interval=60, on_unknown_peer=vistos.append)
    b = red.nodo("b", peers=[a], sync_interval=60)
    assert _esperar(lambda: any(p.is_active for p in a.peers.values()))
    assert vistos == []


@pytest.fixture
def red(tmp_path):
    r = _Red(tmp_path)
    yield r
    r.detener()
