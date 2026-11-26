"""Campos que el JS del dashboard lee de las respuestas de la API (no solo que la ruta exista).

Cada test llama al endpoint con el nodo real y comprueba que el campo que el JS espera está en la
respuesta; antes de cada arreglo, el JS leía un nombre que la API nunca devuelve.
"""
import re
from pathlib import Path

import pytest

from api.cliente_asgi import ClienteASGI
from tests.helpers import make_app

INDEX = (Path(__file__).resolve().parent.parent / "dashboard" / "templates" / "index.html"
         ).read_text(encoding="utf-8")


def _funcion_js(nombre: str) -> str:
    """Cuerpo de ``async function nombre`` del dashboard (hasta la siguiente función de nivel 0)."""
    inicio = INDEX.index(f"async function {nombre}(")
    fin = INDEX.find("\n}\n", inicio)
    return INDEX[inicio:fin]


@pytest.fixture
def cliente(tmp_path):
    return ClienteASGI(make_app(tmp_path, mining_difficulty=1))


def test_metricas_de_minado_usan_los_campos_de_stats(cliente):
    """loadConsensusMetrics debe leer de ``/stats.mining`` campos que existen tras minar un bloque."""
    assert cliente.post("/blocks/mine", json={"miner_address": "DASHBOARD_UPB"}).status_code == 200
    mining = cliente.get("/stats").json()["mining"]
    cuerpo = _funcion_js("loadConsensusMetrics")
    leidos = set(re.findall(r"mining\.(\w+)", cuerpo)) - {"difficulty_bits"}
    assert leidos, "el JS no lee métricas de minado"
    assert leidos <= set(mining), f"el JS lee campos que /stats no devuelve: {leidos - set(mining)}"


def test_topologia_de_red_lee_campos_que_devuelve_network(cliente):
    """loadNetwork: todo ``data.X`` existe en ``/network`` y el par activo se lee de ``peers[]``."""
    from blockchain.network.node import Peer
    red = cliente.get("/network").json()
    cuerpo = _funcion_js("loadNetwork")
    leidos = set(re.findall(r"\bdata\.(\w+)", cuerpo))
    assert leidos <= set(red), f"/network no devuelve: {leidos - set(red)}"
    par = Peer("10.0.0.2", 8001, is_active=True).to_dict()
    for campo in set(re.findall(r"\bp\.(\w+)", cuerpo)):
        assert campo in par, f"el par de /network.peers[] no trae {campo!r}"

