"""Tests de P2-2: pruebas de inclusión Merkle y verificador liviano."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from blockchain.core.block import Block
from blockchain.core.merkle import build_proof, leaf_hash, verify_proof
from blockchain.core.wallet import Wallet
from tests.test_credentials_chain import (  # noqa: F401  (fixtures y ayudantes)
    _datos, _emitir, _minar_api, _registrar, client, nodo,
)


def _txs(n):
    return [{"tx_id": f"t{i}", "payload": {"n": i}} for i in range(n)]


def _raiz_referencia(transactions):
    """Copia literal del algoritmo original de Block (antes de P2-2)."""
    if not transactions:
        return hashlib.sha256(b"").hexdigest()
    hs = [hashlib.sha256(json.dumps(t, sort_keys=True).encode()).hexdigest() for t in transactions]
    while len(hs) > 1:
        if len(hs) % 2 != 0:
            hs.append(hs[-1])
        hs = [hashlib.sha256((hs[i] + hs[i + 1]).encode()).hexdigest() for i in range(0, len(hs), 2)]
    return hs[0]


@pytest.mark.parametrize("n", range(1, 18))
def test_prueba_cada_indice_y_raiz_identica(n):
    txs = _txs(n)
    raiz = Block.compute_merkle_root(txs)
    assert raiz == _raiz_referencia(txs)
    hojas = [leaf_hash(t) for t in txs]
    for i in range(n):
        assert verify_proof(hojas[i], build_proof(hojas, i), raiz)


def test_vacio_identico():
    assert Block.compute_merkle_root([]) == _raiz_referencia([])


def test_manipulacion_falla():
    txs = _txs(7)
    raiz = Block.compute_merkle_root(txs)
    hojas = [leaf_hash(t) for t in txs]
    prueba = build_proof(hojas, 3)
    assert not verify_proof(leaf_hash({"tx_id": "falsa"}), prueba, raiz)
    mala = copy.deepcopy(prueba)
    mala[0]["hash"] = "0" * 64
    assert not verify_proof(hojas[3], mala, raiz)
    volteada = copy.deepcopy(prueba)
    volteada[1]["position"] = "left" if volteada[1]["position"] == "right" else "right"
    assert not verify_proof(hojas[3], volteada, raiz)
    assert not verify_proof(hojas[3], prueba, "f" * 64)
    with pytest.raises(IndexError):
        build_proof(hojas, 7)


@pytest.mark.asyncio
async def test_api_prueba_verifica_y_verificador_liviano(client):
    emisor, estudiante = Wallet.generate(), Wallet.generate()
    await _registrar(client, emisor)
    r = await _emitir(client, emisor, estudiante, _datos())
    assert r.status_code == 200, r.text
    pend = (await client.get("/transactions/pending")).json()["transactions"]
    tx_id = pend[0]["tx_id"]

    r = await client.get(f"/tx/{tx_id}/proof")
    assert r.status_code == 404 and "pendiente" in r.json()["detail"].lower()

    idx = await _minar_api(client)
    p = (await client.get(f"/tx/{tx_id}/proof")).json()
    assert p["block_index"] == idx and p["tx_id"] == tx_id
    assert verify_proof(p["leaf"], p["proof"], p["merkle_root"])

    # El verificador liviano (sin importar `blockchain`) acepta y detecta fraude.
    ruta = Path(__file__).resolve().parent.parent / "scripts" / "verificar_prueba.py"
    codigo = ruta.read_text(encoding="utf-8")
    assert "import blockchain" not in codigo and "from blockchain" not in codigo
    spec = importlib.util.spec_from_file_location("verificar_prueba", ruta)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    bloque = (await client.get(f"/blocks/{idx}")).json()
    assert mod.verificar(p, bloque) == []
    falso = copy.deepcopy(p)
    falso["leaf"] = "0" * 64
    assert mod.verificar(falso, bloque) != []


@pytest.mark.asyncio
async def test_desconocida_404(client):
    assert (await client.get("/tx/" + "0" * 64 + "/proof")).status_code == 404


def _modulo_verificador():
    ruta = Path(__file__).resolve().parent.parent / "scripts" / "verificar_prueba.py"
    spec = importlib.util.spec_from_file_location("verificar_prueba", ruta)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_verificador_certificado_pbft_cuorum_firmas_y_repetidos():
    from blockchain.consensus.pbft import COMMIT, sign_message
    mod = _modulo_verificador()
    reps = [Wallet.generate() for _ in range(4)]
    replicas = [{"id": f"r{i}", "public_key": w.public_key_hex} for i, w in enumerate(reps)]
    bloque = {"header": {"index": 5}, "hash": "ab" * 32}

    def commit(i, **extra):
        m = {"type": COMMIT, "view": 0, "seq": 5, "digest": "ab" * 32, "replica": f"r{i}", **extra}
        return sign_message(m, reps[i].private_key_hex)

    def cert(commits, **extra):
        return {"view": 0, "seq": 5, "digest": "ab" * 32, "commits": commits, **extra}

    assert mod.verificar_certificado(cert([commit(0), commit(1), commit(2)]), bloque, replicas)[0]
    ok, motivo = mod.verificar_certificado(cert([commit(0), commit(1)]), bloque, replicas)
    assert not ok and "necesitan 3" in motivo
    assert not mod.verificar_certificado(cert([commit(0), commit(1), commit(1)]), bloque, replicas)[0]
    falso = commit(2)
    falso["replica"] = "r3"                                  # firma de r2 atribuida a r3
    assert not mod.verificar_certificado(cert([commit(0), commit(1), falso]), bloque, replicas)[0]
    assert not mod.verificar_certificado(cert([commit(0), commit(1), commit(2)], digest="cd" * 32),
                                         bloque, replicas)[0]
    assert not mod.verificar_certificado(None, bloque, replicas)[0]
    # Llaves de otras réplicas (conjunto distinto): ninguna firma vale.
    ajenas = [{"id": f"r{i}", "public_key": Wallet.generate().public_key_hex} for i in range(4)]
    assert not mod.verificar_certificado(cert([commit(0), commit(1), commit(2)]), bloque, ajenas)[0]


def test_verificador_no_exige_trabajo_en_pbft_pero_si_en_pow():
    from blockchain.core.block import Block, BlockHeader
    mod = _modulo_verificador()
    bloque = Block(BlockHeader(index=1, timestamp=1.5, previous_hash="0" * 64,
                               merkle_root=Block.compute_merkle_root([{"tx_id": "t"}]),
                               difficulty=200), [{"tx_id": "t"}]).to_dict()
    p = {"tx_id": "t", "leaf": mod._h(json.dumps({"tx_id": "t"}, sort_keys=True)), "proof": [],
         "merkle_root": bloque["header"]["merkle_root"], "block_hash": bloque["hash"]}
    assert any("prueba de trabajo" in f for f in mod.verificar(p, bloque))
    assert mod.verificar(p, bloque, pbft=True) == []
