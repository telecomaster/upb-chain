"""Tests de P1-13: interfaz única de contratos, registro y contrato de votación.

- El registro enruta cada tipo de TX a sus contratos (cuentas recibe todas).
- Determinismo: misma cadena ⇒ mismo estado en nodos nuevos, al recargar y
  tras replace_chain.
- Política única: una TX inválida para cualquier contrato invalida el bloque
  entero; en el mempool la misma regla responde 400.
- Votación: un voto por dirección y elección, por la API y dentro de un bloque.
"""
import ast
import inspect
import os
import textwrap
from types import SimpleNamespace

os.environ.setdefault("NODE_PORT", "0")

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from blockchain.contracts import accounts, badges, base, registry, tokens, voting
from blockchain.contracts.accounts import AccountContract
from blockchain.contracts.base import MEMPOOL, Contract, TxContext
from blockchain.contracts.credential import CredentialContract
from blockchain.contracts.registry import ContractRegistry
from blockchain.contracts.voting import VotingContract
from blockchain.core.chain import Blockchain
from blockchain.core.transaction import (
    create_credential_transaction,
    create_issuer_register_transaction,
    create_mint_transaction,
    create_transfer_transaction,
    create_vote_transaction,
)
from blockchain.core.wallet import Wallet
from tests.helpers import make_app, mine_and_add, mine_candidate

DIFICULTAD = 1


def _cadena(directorio, autoridad) -> Blockchain:
    return Blockchain(f"nodo_{directorio.name}", str(directorio),
                      initial_difficulty=DIFICULTAD, authority_address=autoridad.address)


def _minar(bc):
    ok, why = mine_and_add(bc)
    assert ok, why


def _foto(bc: Blockchain) -> dict:
    """Estado de todos los contratos en una forma comparable."""
    cuentas = bc.contract_state("accounts")
    creds = bc.contract_state("credentials")
    return {
        "altura": bc.contracts.height,
        "cuentas": (cuentas.balances, cuentas.nonces, cuentas.total_supply, cuentas.burned_fees),
        "emisores": dict(creds._issuer_registry),
        "credenciales": sorted((c["credential_id"], c["status"], c["block_number"])
                               for c in creds.get_all_credentials()),
        "votos": bc.contract_state("voting").elections,
    }


# ── Registro: enrutamiento ───────────────────────────────────────────────────

@pytest.mark.unit
def test_registro_enruta_cada_tipo_a_sus_contratos():
    reg = ContractRegistry([AccountContract(), CredentialContract(), VotingContract()])
    nombres = lambda tipo: [c.NAME for c in reg.handlers({"type": tipo})]  # noqa: E731
    assert reg.names == ["accounts", "credentials", "voting"]
    assert nombres("VOTE") == ["accounts", "voting"]
    assert nombres("CREDENTIAL_ISSUE") == ["accounts", "credentials"]
    assert nombres("ISSUER_REGISTER") == ["accounts", "credentials"]
    assert nombres("DATA_RECORD") == ["accounts"]
    assert nombres("TOKEN_TRANSFER") == ["accounts"]


@pytest.mark.unit
def test_registro_rechaza_nombres_duplicados_o_vacios():
    with pytest.raises(ValueError):
        ContractRegistry([VotingContract(), VotingContract()])
    with pytest.raises(ValueError):
        ContractRegistry([Contract()])


@pytest.mark.unit
def test_la_cadena_pone_siempre_las_cuentas_primero(tmp_path):
    bc = Blockchain("n", str(tmp_path / "n"), contracts=[VotingContract()])
    assert bc.contracts.names == ["accounts", "voting"]
    assert Blockchain("m", str(tmp_path / "m")).contracts.names == \
        ["accounts", "credentials", "voting", "tokens", "badges", "vm"]


@pytest.mark.unit
def test_contexto_viene_del_bloque_y_el_mempool_no_tiene_bloque(tmp_path):
    autoridad = Wallet.generate()
    bc = _cadena(tmp_path / "a", autoridad)
    _minar(bc)
    ctx = TxContext.of_block(bc.last_block)
    assert (ctx.block_index, ctx.block_hash) == (1, bc.last_block.hash)
    assert ctx.block_timestamp == bc.last_block.header.timestamp
    assert MEMPOOL == TxContext(None, None, None)


@pytest.mark.unit
def test_contratos_sin_reloj_ni_azar():
    """Regla de determinismo: las reglas de consenso no leen el reloj ni usan azar."""
    prohibidos = {"time", "random", "uuid", "datetime", "secrets", "os"}
    fuentes = [inspect.getsource(m) for m in (base, registry, accounts, voting, tokens, badges)]
    fuentes.append(textwrap.dedent(inspect.getsource(CredentialContract)))
    for fuente in fuentes:
        for nodo in ast.walk(ast.parse(fuente)):
            if isinstance(nodo, ast.Import):
                assert not {a.name.split(".")[0] for a in nodo.names} & prohibidos
            elif isinstance(nodo, ast.ImportFrom):
                assert (nodo.module or "").split(".")[0] not in prohibidos
            elif isinstance(nodo, ast.Name):
                assert nodo.id not in prohibidos, nodo.id
            elif isinstance(nodo, ast.Call) and isinstance(nodo.func, ast.Name):
                assert nodo.func.id != "float", "conversión a float"
            elif isinstance(nodo, ast.Constant):
                assert not isinstance(nodo.value, float), nodo.value


# ── Determinismo ─────────────────────────────────────────────────────────────

def _cadena_con_actividad(directorio, autoridad):
    emisor, ana, beto = Wallet.generate(), Wallet.generate(), Wallet.generate()
    a = _cadena(directorio, autoridad)
    txs = [
        create_issuer_register_transaction(autoridad.address, emisor.address, "UPB",
                                           autoridad.private_key_hex, nonce=1),
        create_mint_transaction(autoridad.address, ana.address, 10,
                                autoridad.private_key_hex, nonce=2),
        create_credential_transaction(emisor.address, ana.address,
                                      {"student_name": "Ana", "program": "IA",
                                       "degree": "Lic. IA", "issue_date": "2026-01-01",
                                       "credential_type": "DEGREE"},
                                      emisor.private_key_hex, nonce=1),
        create_vote_transaction(ana.address, "consejo", "lista-A", ana.private_key_hex, nonce=1),
    ]
    for tx in txs:
        ok, why = a.add_transaction(tx)
        assert ok, why
    _minar(a)
    for tx in [
        create_transfer_transaction(ana.address, beto.address, 3, ana.private_key_hex,
                                    nonce=2, fee=1),
        create_vote_transaction(beto.address, "consejo", "lista-B", beto.private_key_hex, nonce=1),
        create_vote_transaction(ana.address, "rector", "si", ana.private_key_hex, nonce=3),
    ]:
        ok, why = a.add_transaction(tx)
        assert ok, why
    _minar(a)
    return a


@pytest.mark.integration
def test_misma_cadena_mismo_estado_en_nodos_nuevos_y_tras_reorg(tmp_path):
    autoridad = Wallet.generate()
    a = _cadena_con_actividad(tmp_path / "a", autoridad)
    foto = _foto(a)
    votos = a.contract_state("voting")
    assert votos.tally("consejo") == {"lista-A": 1, "lista-B": 1}
    assert votos.tally("rector") == {"si": 1}
    assert foto["cuentas"][2] == 9 and foto["cuentas"][3] == 1   # 10 minados − 1 de fee

    # Dos nodos nuevos que reciben la cadena por replace_chain.
    for nombre in ("b", "c"):
        nodo = _cadena(tmp_path / nombre, autoridad)
        ok, why = nodo.replace_chain([blk.to_dict() for blk in a.chain])
        assert ok, why
        assert _foto(nodo) == foto

    # Recarga desde disco.
    assert _foto(_cadena(tmp_path / "a", autoridad)) == foto

    # Reorg: D mina más trabajo sin esa actividad; A se reorganiza y luego vuelve.
    d = _cadena(tmp_path / "d", autoridad)
    for _ in range(3):
        _minar(d)
    ok, why = a.replace_chain([blk.to_dict() for blk in d.chain])
    assert ok, why
    assert _foto(a) == _foto(d)
    assert a.contract_state("voting").elections == {}
    assert a.contract_state("accounts").balances == {}

    # Rebuild explícito del registro sobre la cadena actual: mismo resultado.
    reg = ContractRegistry([AccountContract(autoridad.address),
                            CredentialContract(autoridad.address), VotingContract()])
    reg.rebuild(a.chain)
    assert reg.state("voting").elections == a.contract_state("voting").elections
    assert reg.state("accounts") == a.contract_state("accounts")


# ── Votación ─────────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_votacion_reglas_puras():
    c = VotingContract()
    voto = {"type": "VOTE", "sender": "UPBana", "tx_id": "1",
            "payload": {"election_id": "e1", "choice": "si"}}
    ok, _, s = c.execute(c.initial_state(), voto)
    assert ok and s.tally("e1") == {"si": 1}
    ok, why, s2 = c.execute(s, {**voto, "tx_id": "2", "payload": {"election_id": "e1",
                                                                  "choice": "no"}})
    assert not ok and "Ya votó" in why and s2 is s
    ok, _, s = c.execute(s, {**voto, "payload": {"election_id": "e2", "choice": "no"}})
    assert ok and s.tally("e2") == {"no": 1}
    for malo in [{}, {"election_id": "", "choice": "x"}, {"election_id": "e", "choice": 1},
                 {"election_id": "e" * 65, "choice": "x"}, "no-es-dict"]:
        ok, _, _ = c.execute(c.initial_state(), {**voto, "payload": malo})
        assert not ok, malo


@pytest.mark.integration
def test_doble_voto_en_un_bloque_invalida_el_bloque(tmp_path):
    autoridad, ana = Wallet.generate(), Wallet.generate()
    bc = _cadena(tmp_path / "a", autoridad)
    v1 = create_vote_transaction(ana.address, "e1", "si", ana.private_key_hex, nonce=1)
    v2 = create_vote_transaction(ana.address, "e1", "no", ana.private_key_hex, nonce=2)
    estado_antes = bc.contract_state("voting")

    ok, why = bc.add_block(mine_candidate(bc, [v1, v2]))
    assert not ok and "Ya votó" in why and bc.height == 0
    # Copia al escribir: el estado confirmado ni siquiera se tocó.
    assert bc.contract_state("voting") is estado_antes and estado_antes.elections == {}
    assert bc.accounts.nonce_of(ana.address) == 0

    ok, why = bc.add_block(mine_candidate(bc, [v1]))
    assert ok, why
    ok, why = bc.add_block(mine_candidate(bc, [v2]))
    assert not ok and "Ya votó" in why
    assert bc.contract_state("voting").tally("e1") == {"si": 1}


# ── Votación por la API ──────────────────────────────────────────────────────

@pytest.fixture
def nodo(tmp_path):
    autoridad = Wallet.generate()
    fastapi = make_app(tmp_path, autoridad=autoridad, mining_difficulty=DIFICULTAD)
    return SimpleNamespace(fastapi=fastapi, node=fastapi.state.node, autoridad=autoridad)


@pytest_asyncio.fixture
async def client(nodo):
    async with AsyncClient(transport=ASGITransport(app=nodo.fastapi),
                           base_url="http://127.0.0.1") as ac:
        yield ac


async def _votar(client, quien, eleccion, opcion):
    return await client.post("/transactions", json={
        "type": "VOTE", "sender": quien.address, "recipient": "VOTING_CONTRACT",
        "payload": {"election_id": eleccion, "choice": opcion},
        "private_key_hex": quien.private_key_hex,
    })


@pytest.mark.integration
@pytest.mark.asyncio
async def test_api_votacion_doble_voto_400_y_recuento(client):
    ana, beto = Wallet.generate(), Wallet.generate()
    assert (await client.get("/contracts/voting/consejo")).status_code == 404

    r = await _votar(client, ana, "consejo", "lista-A")
    assert r.status_code == 200, r.text
    # Segundo voto mientras el primero está pendiente: 400 (estado especulativo).
    r = await _votar(client, ana, "consejo", "lista-B")
    assert r.status_code == 400 and "Ya votó" in r.json()["detail"]

    r = (await client.get("/contracts/voting/consejo")).json()
    assert r["total_votes"] == 0 and r["pending_votes"] == 1

    assert (await _votar(client, beto, "consejo", "lista-A")).status_code == 200
    assert (await client.post("/blocks/mine", json={})).status_code == 200
    r = (await client.get("/contracts/voting/consejo")).json()
    assert r["total_votes"] == 2 and r["tally"] == {"lista-A": 2}
    assert set(r["voters"]) == {ana.address, beto.address} and r["pending_votes"] == 0

    # Ya confirmado: 400 igual. En otra elección sí puede votar.
    r = await _votar(client, ana, "consejo", "lista-B")
    assert r.status_code == 400 and "Ya votó" in r.json()["detail"]
    assert (await _votar(client, ana, "rector", "si")).status_code == 200
    r = await _votar(client, ana, "rector", "")
    assert r.status_code == 400


@pytest.mark.integration
@pytest.mark.asyncio
async def test_api_lista_contratos(client):
    r = (await client.get("/contracts")).json()
    assert [c["name"] for c in r["contracts"]] == ["accounts", "credentials", "voting",
                                                   "tokens", "badges", "vm"]
    assert r["contracts"][0]["handled_types"] is None
    assert r["contracts"][2]["handled_types"] == ["ELECTION_CREATE", "VOTE"]
