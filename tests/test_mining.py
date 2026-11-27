"""Tests de P0-4: minado fuera del event loop, un solo minado a la vez y
dificultad dictada por la regla de la cadena."""
import asyncio
import os
import time

os.environ.setdefault("NODE_PORT", "0")

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from blockchain.core.chain import Blockchain
from tests.helpers import make_app, mine_and_add


@pytest.fixture
def app(tmp_path):
    """App propia (create_app), dificultad 1 y datos en tmp_path."""
    return make_app(tmp_path)


@pytest_asyncio.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app),
                           base_url="http://127.0.0.1") as ac:
        yield ac


def _lento(app, monkeypatch, segundos):
    """Hace que el PoW tarde `segundos` (dentro del thread de minado)."""
    real = app.state.node.pow_engine.mine

    def mine(block, **kw):
        time.sleep(segundos)
        return real(block, **kw)

    monkeypatch.setattr(app.state.node.pow_engine, "mine", mine)


@pytest.mark.asyncio
async def test_minar_sin_cuerpo_como_en_el_readme(client):
    """Regresión: el README documenta ``curl -X POST .../blocks/mine`` sin cuerpo y la API
    respondía 422 (cuerpo obligatorio)."""
    r = await client.post("/blocks/mine")
    assert r.status_code == 200, r.text
    assert r.json()["block"]["header"]["index"] == 1


@pytest.mark.asyncio
async def test_health_responde_durante_el_minado(client, app, monkeypatch):
    _lento(app, monkeypatch, 1.0)
    minado = asyncio.create_task(
        client.post("/blocks/mine", json={"miner_address": "M"}))
    await asyncio.sleep(0.2)
    t0 = time.perf_counter()
    r = await client.get("/health")
    assert r.status_code == 200
    assert time.perf_counter() - t0 < 0.5
    assert not minado.done()  # el minado seguía en curso
    assert (await minado).status_code == 200


@pytest.mark.asyncio
async def test_dos_minados_concurrentes_uno_409(client, app, monkeypatch):
    bc = app.state.node.blockchain
    _lento(app, monkeypatch, 0.6)
    t1 = asyncio.create_task(client.post("/blocks/mine", json={"miner_address": "M"}))
    await asyncio.sleep(0.2)
    r2 = await client.post("/blocks/mine", json={"miner_address": "M"})
    assert r2.status_code == 409
    assert (await t1).status_code == 200
    assert len(bc.chain) == 2


@pytest.mark.asyncio
async def test_punta_cambia_durante_minado_da_409(client, app, monkeypatch):
    bc = app.state.node.blockchain
    real = app.state.node.pow_engine.mine

    def mine(block, **kw):
        res = real(block, **kw)
        mine_and_add(bc)  # "llega un bloque de un peer" mientras se minaba
        return res

    monkeypatch.setattr(app.state.node.pow_engine, "mine", mine)
    r = await client.post("/blocks/mine", json={"miner_address": "M"})
    assert r.status_code == 409


@pytest.mark.asyncio
async def test_minado_usa_dificultad_de_la_cadena(tmp_path):
    app = make_app(tmp_path, "dif2", mining_difficulty=2)
    bc = app.state.node.blockchain
    # Un valor fijo distinto en el motor no debe influir.
    app.state.node.pow_engine.difficulty = 5
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://127.0.0.1") as client:
        r = await client.post("/blocks/mine", json={"miner_address": "M"})
    assert r.status_code == 200
    blk = r.json()["block"]
    assert blk["header"]["difficulty"] == bc.expected_difficulty(bc.chain[:-1]) == 2
    assert int(blk["hash"], 16) < 2 ** 254  # 2 bits iniciales en cero (P2-5)


def _cadena_con_intervalos(tmp_path, nombre, intervalo, n=12):
    """Cadena de `n` bloques con timestamps construidos (sin esperas reales)."""
    bc = Blockchain("n", str(tmp_path / nombre), initial_difficulty=3,
                    min_difficulty=1, max_difficulty=8, difficulty_window=10,
                    target_block_time=10)
    t = bc.chain[0].header.timestamp
    for _ in range(n):
        t += intervalo
        blk = bc.create_candidate_block()
        blk.header.timestamp = t
        blk.header.difficulty = bc.expected_difficulty(bc.chain)
        blk.hash = blk.compute_hash()
        bc.chain.append(blk)  # sólo se mide la regla; no se valida PoW aquí
    return bc


def test_dificultad_sube_con_bloques_rapidos_y_baja_con_lentos(tmp_path):
    rapida = _cadena_con_intervalos(tmp_path, "r", 1)
    lenta = _cadena_con_intervalos(tmp_path, "l", 60)
    assert rapida._calculate_difficulty() > rapida.initial_difficulty
    assert lenta._calculate_difficulty() < lenta.initial_difficulty
    ok = _cadena_con_intervalos(tmp_path, "o", 10)
    assert ok._calculate_difficulty() == ok.chain[-1].header.difficulty
