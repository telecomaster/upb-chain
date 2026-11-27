"""Tests de P0-1: génesis determinista y rechazo de cadenas con otro génesis."""
import json
import os

os.environ.setdefault("NODE_PORT", "0")

import httpx
import pytest

from blockchain.core.block import GENESIS_HASH, Block, BlockHeader
from blockchain.core.chain import Blockchain

# Literal fijado a mano: detecta cambios accidentales de las constantes.
HASH_ESPERADO = "5aaf08e12cacfc76329174fe7ac6d8348e2665df3e6fef2037aae5fa5dfb262f"


def test_constante_fijada():
    assert GENESIS_HASH == HASH_ESPERADO


def test_dos_nodos_mismo_genesis(tmp_path):
    a = Blockchain("nodo-a", str(tmp_path / "a"))
    b = Blockchain("nodo-b", str(tmp_path / "b"))
    assert a.chain[0].hash == b.chain[0].hash == GENESIS_HASH
    assert a.chain[0].to_dict() == b.chain[0].to_dict()


def _cadena_ajena(n=3):
    """Cadena válida internamente pero con otro génesis."""
    g = Block.create_genesis()
    g.transactions[0]["data"] = "otra red"
    g.header.merkle_root = Block.compute_merkle_root(g.transactions)
    g.hash = g.compute_hash()
    chain = [g]
    for i in range(1, n):
        h = BlockHeader(index=i, timestamp=1.0 + i, previous_hash=chain[-1].hash,
                        merkle_root=Block.compute_merkle_root([]), node_id="x")
        chain.append(Block(header=h, transactions=[]))
    return [b.to_dict() for b in chain]


def test_replace_chain_rechaza_otro_genesis(tmp_path):
    bc = Blockchain("n", str(tmp_path))
    ok, reason = bc.replace_chain(_cadena_ajena())
    assert not ok and "Génesis" in reason
    assert bc.chain[0].hash == GENESIS_HASH


def test_carga_rechaza_otro_genesis(tmp_path):
    (tmp_path / "chain.json").write_text(json.dumps(_cadena_ajena()), encoding="utf-8")
    with pytest.raises(ValueError, match="Génesis"):
        Blockchain("n", str(tmp_path))


@pytest.mark.asyncio
async def test_api_bloque_0_es_el_genesis_constante():
    from api.app import app
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as c:
        r = await c.get("/blocks/0")
    assert r.status_code == 200
    assert r.json()["hash"] == GENESIS_HASH
