"""Tests de P1-12: tokens e insignias para estudiantes.

- Presupuesto semestral por emisor: mint por encima → 400 en la API y bloque
  rechazado si se mina a mano.
- Solo emisores registrados emiten premios e insignias (lectura entre
  contratos: ``ctx.view("credentials")``).
- Insignias intransferibles y sin duplicados; canje que quema la oferta solo en
  direcciones registradas.
- Semestre derivado de la hora de los bloques (frontera en hora de Bolivia) y
  determinismo tras replace_chain / recarga.
- Carga CSV: todo o nada.
"""
import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

os.environ.setdefault("NODE_PORT", "0")

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from blockchain.consensus.proof_of_work import ProofOfWork
from blockchain.contracts.tokens import is_semester, semester_of
from blockchain.contracts.voting import VotingContract
from blockchain.core.chain import Blockchain
from blockchain.core.transaction import (
    TransactionType,
    create_badge_award_transaction,
    create_issuer_budget_transaction,
    create_issuer_register_transaction,
    create_mint_transaction,
)
from blockchain.core.wallet import Wallet
from security.rate_limiter import TxRateLimiter
from tests.helpers import make_app, mine_candidate

DIFICULTAD = 1
BOLIVIA = timezone(timedelta(hours=-4))


def _ts(*fecha) -> float:
    """Timestamp de una fecha en hora de Bolivia."""
    return datetime(*fecha, tzinfo=BOLIVIA).timestamp()


# ── Semestre ─────────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_semestre_coincide_con_el_calendario_y_respeta_la_frontera():
    assert semester_of(_ts(2026, 6, 30, 23, 59, 59)) == "2026-1"
    assert semester_of(_ts(2026, 7, 1, 0, 0, 0)) == "2026-2"
    assert semester_of(_ts(2026, 12, 31, 23, 59, 59)) == "2026-2"
    assert semester_of(_ts(2027, 1, 1)) == "2027-1"
    assert semester_of(_ts(2026, 7, 1) - 0.5) == "2026-1"   # se trunca a segundos
    # Contra datetime en muchos puntos (incluye bisiestos y fechas viejas).
    for ts in range(-86400 * 400, 86400 * 365 * 90, 86400 * 7 + 3601):
        mes = (datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=ts)).astimezone(BOLIVIA)
        assert semester_of(ts) == f"{mes.year}-{1 if mes.month <= 6 else 2}", ts
    assert is_semester("2026-2") and not is_semester("2026-3") and not is_semester("26-1")
    assert not is_semester(20261)


# ── A nivel de cadena: semestres por hora de bloque y determinismo ───────────

def _cadena(directorio, autoridad, contracts=None) -> Blockchain:
    return Blockchain(f"nodo_{directorio.name}", str(directorio),
                      initial_difficulty=DIFICULTAD, authority_address=autoridad.address,
                      contracts=contracts)


def _bloque_en(bc, txs, timestamp):
    """Mina un bloque con ``txs`` y la hora de encabezado ``timestamp``."""
    candidato = bc.create_candidate_block(txs)
    candidato.header.timestamp = timestamp
    resultado = ProofOfWork(difficulty=candidato.header.difficulty).mine(
        candidato, timeout=60.0, difficulty=candidato.header.difficulty)
    assert resultado is not None
    return resultado.block


def _foto(bc):
    t, b, c = (bc.contract_state(n) for n in ("tokens", "badges", "accounts"))
    return (t.budgets, t.minted, t.awards, t.redeem_addresses, t.redeemed,
            b.holders, c.balances, c.total_supply)


@pytest.mark.integration
def test_cambio_de_semestre_por_hora_de_bloque_y_determinismo(tmp_path):
    autoridad, emisor, ana = Wallet.generate(), Wallet.generate(), Wallet.generate()
    a = _cadena(tmp_path / "a", autoridad)
    k = autoridad.private_key_hex
    alta = [
        create_issuer_register_transaction(autoridad.address, emisor.address, "UPB", k, nonce=1),
        create_issuer_budget_transaction(autoridad.address, emisor.address, "2026-1", 10, k,
                                         nonce=2),
        create_issuer_budget_transaction(autoridad.address, emisor.address, "2026-2", 5, k,
                                         nonce=3),
    ]
    ok, why = a.add_block(_bloque_en(a, alta, _ts(2026, 3, 1)))
    assert ok, why

    def premio(monto, nonce):
        return create_mint_transaction(emisor.address, ana.address, monto,
                                       emisor.private_key_hex, nonce=nonce, reason="taller")

    # Último segundo del semestre 1: entra con el presupuesto de 2026-1.
    ok, why = a.add_block(_bloque_en(a, [premio(10, 1)], _ts(2026, 6, 30, 23, 59, 59)))
    assert ok, why
    # Primer segundo del semestre 2: 6 > 5 → bloque inválido; 5 sí entra.
    ok, why = a.add_block(_bloque_en(a, [premio(6, 2)], _ts(2026, 7, 1)))
    assert not ok and "Presupuesto insuficiente en 2026-2" in why
    ok, why = a.add_block(_bloque_en(a, [premio(5, 2)], _ts(2026, 7, 1)))
    assert ok, why
    tokens = a.contract_state("tokens")
    assert tokens.minted[emisor.address] == {"2026-1": 10, "2026-2": 5}
    assert a.get_balance(ana.address) == 15
    assert [p["semester"] for p in tokens.awards[ana.address]] == ["2026-1", "2026-2"]

    # Un presupuesto no puede bajar por debajo de lo emitido.
    menor = create_issuer_budget_transaction(autoridad.address, emisor.address, "2026-2", 4, k,
                                             nonce=4)
    ok, why = a.add_block(_bloque_en(a, [menor], _ts(2026, 8, 1)))
    assert not ok and "menor a lo ya emitido" in why

    # Determinismo: nodo nuevo por replace_chain y recarga desde disco.
    b = _cadena(tmp_path / "b", autoridad)
    ok, why = b.replace_chain([blk.to_dict() for blk in a.chain])
    assert ok, why
    assert _foto(b) == _foto(a)
    assert _foto(_cadena(tmp_path / "a", autoridad)) == _foto(a)
    # Reorg a una cadena con más trabajo sin esa actividad: todo vuelve a cero.
    d = _cadena(tmp_path / "d", autoridad)
    for _ in range(len(a.chain) + 1):
        ok, why = d.add_block(mine_candidate(d, None))
        assert ok, why
    ok, why = a.replace_chain([blk.to_dict() for blk in d.chain])
    assert ok, why
    assert a.contract_state("tokens").minted == {} and a.get_balance(ana.address) == 0


@pytest.mark.integration
def test_sin_contrato_de_tokens_solo_la_autoridad_emite(tmp_path):
    """Regresión: con un registro sin "tokens", cuentas sigue exigiendo la autoridad."""
    autoridad, otro = Wallet.generate(), Wallet.generate()
    bc = _cadena(tmp_path / "a", autoridad, contracts=[VotingContract()])
    tx = create_mint_transaction(otro.address, otro.address, 5, otro.private_key_hex,
                                 nonce=1, reason="x")
    ok, why = bc.add_transaction(tx)
    assert not ok and "Solo la autoridad" in why


@pytest.mark.unit
def test_no_hay_tx_para_mover_insignias():
    assert not [t for t in TransactionType.__members__ if t.startswith("BADGE_")
                and t != "BADGE_AWARD"]


# ── Por la API ───────────────────────────────────────────────────────────────

@pytest.fixture
def nodo(tmp_path):
    autoridad = Wallet.generate()
    fastapi = make_app(tmp_path, autoridad=autoridad, mining_difficulty=DIFICULTAD,
                       tx_rate_limit=1000)
    bc = fastapi.state.node.blockchain
    return SimpleNamespace(fastapi=fastapi, node=fastapi.state.node, bc=bc, autoridad=autoridad,
                           emisor=Wallet.generate(), ana=Wallet.generate(),
                           beto=Wallet.generate())


@pytest_asyncio.fixture
async def client(nodo):
    async with AsyncClient(transport=ASGITransport(app=nodo.fastapi),
                           base_url="http://test") as ac:
        yield ac


async def _ok(r):
    assert r.status_code == 200, r.text
    return r.json()


async def _minar(client):
    await _ok(await client.post("/blocks/mine", json={}))


async def _emisor_con_presupuesto(client, nodo, monto):
    await _ok(await client.post("/credentials/issuers", json={
        "issuer_address": nodo.emisor.address, "institution_code": "UPB"}))
    await _minar(client)
    await _ok(await client.post("/tokens/budget", json={
        "issuer_address": nodo.emisor.address, "amount": monto}))
    await _minar(client)


def _premio(nodo, destino, monto, motivo="participación"):
    return {"issuer_address": nodo.emisor.address,
            "private_key_hex": nodo.emisor.private_key_hex,
            "recipient": destino.address, "amount": monto, "reason": motivo}


def _insignia(quien, destino, badge_id="hackaton-2026"):
    return {"issuer_address": quien.address, "private_key_hex": quien.private_key_hex,
            "recipient": destino.address, "badge_id": badge_id, "name": "Hackatón 2026",
            "reason": "primer lugar"}


@pytest.mark.integration
@pytest.mark.asyncio
async def test_api_presupuesto_limita_los_premios(client, nodo):
    # Sin registro ni presupuesto: 400.
    r = await client.post("/tokens/award", json=_premio(nodo, nodo.ana, 1))
    assert r.status_code == 400 and "emisor registrado" in r.json()["detail"]
    await _emisor_con_presupuesto(client, nodo, 10)
    presupuesto = await _ok(await client.get(f"/issuers/{nodo.emisor.address}/budget"))
    assert presupuesto["is_issuer"] and presupuesto["budget"] == 10
    assert presupuesto["remaining"] == 10

    r = await client.post("/tokens/award", json=_premio(nodo, nodo.ana, 11))
    assert r.status_code == 400 and "Presupuesto insuficiente" in r.json()["detail"]
    await _ok(await client.post("/tokens/award", json=_premio(nodo, nodo.ana, 7)))
    # Lo pendiente ya cuenta (estado especulativo).
    r = await client.post("/tokens/award", json=_premio(nodo, nodo.beto, 4))
    assert r.status_code == 400 and "quedan 3" in r.json()["detail"]
    for malo in [_premio(nodo, nodo.beto, 1, motivo=""),          # sin motivo
                 _premio(nodo, nodo.emisor, 1)]:                  # a sí mismo
        assert (await client.post("/tokens/award", json=malo)).status_code == 400
    await _minar(client)

    saldo = await _ok(await client.get(f"/tokens/{nodo.ana.address}"))
    assert saldo["balance"] == 7 and saldo["symbol"] == "PUPB"
    assert saldo["awards"][0]["reason"] == "participación"
    presupuesto = await _ok(await client.get(f"/issuers/{nodo.emisor.address}/budget"))
    assert (presupuesto["minted"], presupuesto["remaining"]) == (7, 3)

    # Un bloque minado a mano con un premio por encima del presupuesto se rechaza.
    exceso = create_mint_transaction(nodo.emisor.address, nodo.beto.address, 4,
                                     nodo.emisor.private_key_hex,
                                     nonce=nodo.bc.next_nonce(nodo.emisor.address),
                                     reason="extra")
    ok, why = nodo.bc.add_block(mine_candidate(nodo.bc, [exceso]))
    assert not ok and "Presupuesto insuficiente" in why


@pytest.mark.integration
@pytest.mark.asyncio
async def test_api_insignias_solo_emisores_sin_duplicados(client, nodo):
    r = await client.post("/badges/award", json=_insignia(nodo.ana, nodo.beto))
    assert r.status_code == 400 and "emisor registrado" in r.json()["detail"]
    await _emisor_con_presupuesto(client, nodo, 0)
    await _ok(await client.post("/badges/award", json=_insignia(nodo.emisor, nodo.ana)))
    r = await client.post("/badges/award", json=_insignia(nodo.emisor, nodo.ana))
    assert r.status_code == 400 and "ya tiene la insignia" in r.json()["detail"]
    await _minar(client)
    r = await client.post("/badges/award", json=_insignia(nodo.emisor, nodo.ana))
    assert r.status_code == 400
    # Intransferible: Ana (no emisora) no puede "pasarla" a Beto.
    r = await client.post("/badges/award", json=_insignia(nodo.ana, nodo.beto))
    assert r.status_code == 400
    await _ok(await client.post("/badges/award", json=_insignia(nodo.emisor, nodo.beto)))
    await _minar(client)
    ana = await _ok(await client.get(f"/badges/{nodo.ana.address}"))
    assert [b["badge_id"] for b in ana["badges"]] == ["hackaton-2026"]
    assert ana["badges"][0]["issuer"] == nodo.emisor.address
    assert len((await _ok(await client.get(f"/badges/{nodo.beto.address}")))["badges"]) == 1

    # Un bloque con la misma insignia dos veces se rechaza entero.
    dup = [create_badge_award_transaction(nodo.emisor.address, nodo.ana.address, "x", "X",
                                          "r", nodo.emisor.private_key_hex,
                                          nonce=nodo.bc.next_nonce(nodo.emisor.address) + i)
           for i in range(2)]
    ok, why = nodo.bc.add_block(mine_candidate(nodo.bc, dup))
    assert not ok and "ya tiene la insignia" in why


@pytest.mark.integration
@pytest.mark.asyncio
async def test_api_canje_quema_solo_en_direcciones_registradas(client, nodo):
    cafeteria = Wallet.generate()
    await _ok(await client.post("/tokens/mint", json={"recipient": nodo.ana.address,
                                                     "amount": 10}))
    await _minar(client)
    canje = {"sender": nodo.ana.address, "private_key_hex": nodo.ana.private_key_hex,
             "redeem_address": cafeteria.address, "amount": 4, "item": "café"}
    r = await client.post("/tokens/redeem", json=canje)
    assert r.status_code == 400 and "dirección de canje" in r.json()["detail"]
    await _ok(await client.post("/tokens/redeem-addresses", json={
        "redeem_address": cafeteria.address, "label": "Cafetería"}))
    await _minar(client)
    await _ok(await client.post("/tokens/redeem", json=canje))
    r = await client.post("/tokens/redeem", json={**canje, "amount": 7})
    assert r.status_code == 400 and "Saldo insuficiente" in r.json()["detail"]
    await _minar(client)

    assert nodo.bc.get_balance(nodo.ana.address) == 6
    assert nodo.bc.get_balance(cafeteria.address) == 0          # quemado, no acreditado
    assert nodo.bc.accounts.total_supply == 6
    lista = await _ok(await client.get("/tokens/redeem-addresses"))
    assert lista["redeem_addresses"] == [{"address": cafeteria.address,
                                          "label": "Cafetería", "redeemed": 4}]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_api_csv_todo_o_nada(client, nodo):
    await _emisor_con_presupuesto(client, nodo, 10)
    base = {"issuer_address": nodo.emisor.address,
            "private_key_hex": nodo.emisor.private_key_hex}
    a, b = nodo.ana.address, nodo.beto.address

    # Fila con formato malo: 400, ninguna enviada.
    csv_malo = f"address,amount,reason\n{a},3,taller\n{b},abc,taller\n"
    r = await client.post("/tokens/award/csv", json={**base, "csv": csv_malo})
    assert r.status_code == 400
    assert r.json()["detail"]["errors"] == [{"row": 3, "error": "amount debe ser un entero > 0"}]
    assert nodo.bc.mempool == []

    # Formato bien pero la última fila excede el presupuesto (contando las anteriores).
    csv_exceso = f"address,amount,reason\n{a},6,taller\n{b},5,taller\n"
    r = await client.post("/tokens/award/csv", json={**base, "csv": csv_exceso})
    assert r.status_code == 400
    errores = r.json()["detail"]["errors"]
    assert len(errores) == 1 and errores[0]["row"] == 3
    assert "Presupuesto insuficiente" in errores[0]["error"]
    assert nodo.bc.mempool == []

    r = await _ok(await client.post("/tokens/award/csv", json={
        **base, "csv": f"address,amount,reason\n{a},6,taller\n{b},3,taller\n{b},1,feria\n"}))
    assert r["count"] == 3 and [s["row"] for s in r["submitted"]] == [2, 3, 4]
    assert [t.nonce for t in nodo.bc.mempool] == [1, 2, 3]
    await _minar(client)
    assert (nodo.bc.get_balance(a), nodo.bc.get_balance(b)) == (6, 4)

    r = await client.post("/tokens/award/csv", json={**base, "csv": "dir,monto\nx,1\n"})
    assert r.status_code == 400


@pytest.mark.integration
@pytest.mark.asyncio
async def test_api_csv_respeta_el_limite_de_tasa(client, nodo):
    await _emisor_con_presupuesto(client, nodo, 10)
    nodo.node.tx_rate_limiter = TxRateLimiter(limit=2)
    filas = "".join(f"{nodo.ana.address},1,taller\n" for _ in range(3))
    r = await client.post("/tokens/award/csv", json={
        "issuer_address": nodo.emisor.address, "private_key_hex": nodo.emisor.private_key_hex,
        "csv": "address,amount,reason\n" + filas})
    assert r.status_code == 429
    assert len(r.json()["detail"]["submitted"]) == 2 and len(nodo.bc.mempool) == 2


@pytest.mark.integration
@pytest.mark.asyncio
async def test_api_presupuesto_exige_admin(client, nodo):
    nodo.node.settings = nodo.node.settings.model_copy(update={"admin_api_key": "secreta"})
    cuerpo = {"issuer_address": nodo.emisor.address, "amount": 5}
    assert (await client.post("/tokens/budget", json=cuerpo)).status_code == 401
    assert (await client.post("/tokens/redeem-addresses", json={
        "redeem_address": "x", "label": "y"})).status_code == 401
    r = await client.post("/tokens/budget", json={**cuerpo, "semester": "2026-3"},
                          headers={"X-API-Key": "secreta"})
    assert r.status_code == 400
