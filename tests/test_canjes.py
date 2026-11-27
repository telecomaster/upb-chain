"""Tests de P2-12: catálogo de canjes, premios automáticos por contrato y votación ponderada.

- Catálogo: la compra descuenta stock y deja recibo; precio distinto o agotado → 400
  y bloque rechazado si se mina a mano.
- Premio automático al emitir credencial: se acredita dentro del presupuesto; sin
  presupuesto se OMITE y la credencial se emite igual (decisión documentada).
- Elecciones ponderadas (una por dirección, por insignia, por saldo con foto y tope),
  ventana por altura de bloque, y determinismo tras replace_chain / recarga.
"""
import os
import time
from types import SimpleNamespace

os.environ.setdefault("NODE_PORT", "0")

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from blockchain.contracts.tokens import auto_award, receipt_id_of, semester_of
from blockchain.core.chain import Blockchain
from blockchain.core.transaction import (
    create_award_rule_transaction,
    create_badge_award_transaction,
    create_catalog_item_transaction,
    create_credential_transaction,
    create_election_transaction,
    create_issuer_budget_transaction,
    create_issuer_register_transaction,
    create_mint_transaction,
    create_redeem_address_transaction,
    create_redeem_transaction,
    create_vote_transaction,
)
from blockchain.core.wallet import Wallet
from tests.helpers import make_app, mine_and_add, mine_candidate
from tests.test_tokens import _bloque_en

DIFICULTAD = 1
AHORA = int(time.time())          # los bloques de prueba deben quedar cerca de la hora real
SEM = semester_of(AHORA)


def _cadena(directorio, autoridad) -> Blockchain:
    return Blockchain(f"nodo_{directorio.name}", str(directorio), initial_difficulty=DIFICULTAD,
                      authority_address=autoridad.address)


def _ok(bc, txs):
    ok, why = mine_and_add(bc, txs)
    assert ok, why


def _datos(tipo="DEGREE", n=0):
    return {"student_name": "Ana", "program": "IA", "degree": f"Lic {tipo} {n}",
            "issue_date": "2026-06-10", "credential_type": tipo}


@pytest.fixture
def mundo(tmp_path):
    """Cadena con emisor registrado, dirección de canje y saldo para la estudiante."""
    a, e, ana, beto, caja = (Wallet.generate() for _ in range(5))
    bc = _cadena(tmp_path / "a", a)
    k = a.private_key_hex
    _ok(bc, [
        create_issuer_register_transaction(a.address, e.address, "UPB", k, nonce=1),
        create_redeem_address_transaction(a.address, caja.address, "Cafetería", k, nonce=2),
        create_mint_transaction(a.address, ana.address, 100, k, nonce=3),
    ])
    return SimpleNamespace(bc=bc, a=a, k=k, e=e, ana=ana, beto=beto, caja=caja, tmp=tmp_path)


def _item(m, nonce, item_id="entrada", price=30, stock=2):
    return create_catalog_item_transaction(m.a.address, item_id, "Entrada al evento", price, stock,
                                           m.caja.address, m.k, nonce=nonce)


def _canje(m, nonce, monto=30, item_id="entrada", wallet=None):
    w = wallet or m.ana
    return create_redeem_transaction(w.address, m.caja.address, monto, w.private_key_hex,
                                     nonce=nonce, item_id=item_id)


# ── Catálogo ─────────────────────────────────────────────────────────────────

@pytest.mark.integration
def test_compra_descuenta_stock_y_deja_recibo(mundo):
    m = mundo
    _ok(m.bc, [_item(m, 4)])
    canje = _canje(m, 1)
    _ok(m.bc, [canje])
    tokens = m.bc.contract_state("tokens")
    assert tokens.catalog["entrada"]["stock"] == 1
    assert m.bc.get_balance(m.ana.address) == 70
    recibo = tokens.receipts[receipt_id_of(canje.tx_id)]
    assert recibo["buyer"] == m.ana.address and recibo["price"] == 30
    assert receipt_id_of(canje.tx_id) == "R-" + canje.tx_id[:16]


@pytest.mark.integration
def test_canje_sin_item_id_sigue_como_p1_12(mundo):
    m = mundo
    tx = create_redeem_transaction(m.ana.address, m.caja.address, 7, m.ana.private_key_hex,
                                   nonce=1, item="café")
    _ok(m.bc, [tx])
    tokens = m.bc.contract_state("tokens")
    assert tokens.redeemed[m.caja.address] == 7 and tokens.receipts == {}


@pytest.mark.integration
def test_precio_distinto_agotado_o_inexistente_se_rechaza(mundo):
    m = mundo
    _ok(m.bc, [_item(m, 4, stock=1)])
    ok, why = m.bc.add_transaction(_canje(m, 1, monto=29))
    assert not ok and "precio" in why
    ok, why = m.bc.add_transaction(_canje(m, 1, item_id="otra"))
    assert not ok and "no existe" in why
    # Mina a mano un bloque con precio equivocado: la red lo rechaza entero.
    ok, why = m.bc.add_block(mine_candidate(m.bc, [_canje(m, 1, monto=31)]))
    assert not ok
    _ok(m.bc, [_canje(m, 1)])
    ok, why = m.bc.add_transaction(_canje(m, 2))
    assert not ok and "agotado" in why
    # Dos compras en el MISMO bloque con una sola unidad: el segundo se rechaza.
    ok, why = m.bc.add_block(mine_candidate(m.bc, [_canje(m, 2)]))
    assert not ok


@pytest.mark.integration
def test_dos_compras_en_un_bloque_agotan_el_stock(mundo):
    m = mundo
    _ok(m.bc, [_item(m, 4, stock=1)])
    _ok(m.bc, [create_mint_transaction(m.a.address, m.beto.address, 50, m.k, nonce=5)])
    # Las dos son válidas por separado; juntas en un bloque la segunda ve stock 0.
    juntas = [_canje(m, 1), _canje(m, 1, wallet=m.beto)]
    ok, why = m.bc.add_block(mine_candidate(m.bc, juntas))
    assert not ok and "agotado" in why


@pytest.mark.integration
def test_solo_la_autoridad_publica_items_y_no_se_repiten(mundo):
    m = mundo
    falso = create_catalog_item_transaction(m.ana.address, "x", "X", 1, 1, m.caja.address,
                                            m.ana.private_key_hex, nonce=1)
    ok, why = m.bc.add_transaction(falso)
    assert not ok and "autoridad" in why
    _ok(m.bc, [_item(m, 4)])
    ok, why = m.bc.add_transaction(_item(m, 5))
    assert not ok and "ya está" in why
    sin_dir = create_catalog_item_transaction(m.a.address, "y", "Y", 1, 1, m.beto.address, m.k,
                                              nonce=5)
    ok, why = m.bc.add_transaction(sin_dir)
    assert not ok and "canje" in why


# ── Premios automáticos ──────────────────────────────────────────────────────

def _con_regla(m, presupuesto, premio=10, nonce=4):
    k = m.k
    _ok(m.bc, [
        create_issuer_budget_transaction(m.a.address, m.e.address, SEM, presupuesto, k,
                                         nonce=nonce),
        create_award_rule_transaction(m.a.address, "regla-grado", "DEGREE", m.e.address, premio,
                                      k, nonce=nonce + 1),
    ])


def _emitir(m, nonce, n=0, tipo="DEGREE", estudiante=None):
    return create_credential_transaction(m.e.address, (estudiante or m.ana).address,
                                         _datos(tipo, n), m.e.private_key_hex, nonce=nonce)


@pytest.mark.integration
def test_premio_automatico_dentro_del_presupuesto(mundo):
    m = mundo
    _con_regla(m, 15)
    antes = m.bc.contract_state("accounts").total_supply
    ok, why = m.bc.add_block(_bloque_en(m.bc, [_emitir(m, 1)], int(time.time()) + 1))
    assert ok, why
    tokens = m.bc.contract_state("tokens")
    assert m.bc.get_balance(m.ana.address) == 110
    assert tokens.minted[m.e.address] == {SEM: 10}
    assert tokens.awards[m.ana.address][-1]["rule_id"] == "regla-grado"
    assert m.bc.contract_state("accounts").total_supply == antes + 10
    # Otro tipo de credencial: sin regla, sin premio.
    ok, why = m.bc.add_block(_bloque_en(m.bc, [_emitir(m, 2, 1, "CERTIFICATION")], int(time.time()) + 2))
    assert ok, why
    assert m.bc.get_balance(m.ana.address) == 110


@pytest.mark.integration
def test_sin_presupuesto_se_omite_el_premio_y_la_credencial_se_emite(mundo):
    m = mundo
    _con_regla(m, 15)
    ok, why = m.bc.add_block(_bloque_en(m.bc, [_emitir(m, 1)], int(time.time()) + 1))   # 10 de 15
    assert ok, why
    # La segunda necesita 10 pero quedan 5: el bloque ENTRA, sin premio.
    ok, why = m.bc.add_block(_bloque_en(m.bc, [_emitir(m, 2, 1)], int(time.time()) + 2))
    assert ok, why
    assert m.bc.get_balance(m.ana.address) == 110
    assert m.bc.contract_state("tokens").minted[m.e.address] == {SEM: 10}
    assert len(m.bc.contract_state("credentials").issuer_credential_ids(m.e.address)) == 2


@pytest.mark.unit
def test_auto_award_es_pura_y_no_exige_regla():
    from blockchain.contracts.base import TxContext
    from blockchain.contracts.tokens import TokenState
    tx = {"type": "CREDENTIAL_ISSUE", "sender": "E", "recipient": "S",
          "payload": {"credential_type": "DEGREE"}}
    assert auto_award(TokenState(), tx, TxContext(1, "h", int(time.time()) + 1)) is None
    assert auto_award(TokenState(), tx, TxContext(1, "h", None)) is None


@pytest.mark.integration
def test_reglas_solo_autoridad_y_una_por_tipo_y_emisor(mundo):
    m = mundo
    _con_regla(m, 15)
    de_ana = create_award_rule_transaction(m.ana.address, "r", "DEGREE", m.e.address, 1,
                                           m.ana.private_key_hex, nonce=2)
    assert not m.bc.add_transaction(de_ana)[0]
    dup = create_award_rule_transaction(m.a.address, "otra", "DEGREE", m.e.address, 3, m.k,
                                        nonce=6)
    ok, why = m.bc.add_transaction(dup)
    assert not ok and "Ya hay una regla" in why
    sin_emisor = create_award_rule_transaction(m.a.address, "z", "X", m.beto.address, 3, m.k,
                                               nonce=6)
    assert not m.bc.add_transaction(sin_emisor)[0]


# ── Votación ponderada ───────────────────────────────────────────────────────

def _eleccion(m, nonce, regla, inicio, fin, eid="el1", creador=None, **extra):
    c = creador or m.a
    return create_election_transaction(c.address, eid, ["si", "no"], regla, inicio, fin,
                                       c.private_key_hex, nonce=nonce, **extra)


def _voto(w, opcion, nonce, eid="el1"):
    return create_vote_transaction(w.address, eid, opcion, w.private_key_hex, nonce=nonce)


@pytest.mark.integration
def test_una_por_direccion_y_ventana_por_altura(mundo):
    m = mundo
    h = m.bc.contracts.height            # el bloque siguiente es h+1
    _ok(m.bc, [_eleccion(m, 4, "one_per_address", h + 3, h + 3)])   # abre en el bloque h+3
    ok, why = m.bc.add_transaction(_voto(m.ana, "si", 1))
    assert not ok and "cerrada" in why
    _ok(m.bc, [])                         # bloque h+2
    ok, why = m.bc.add_block(mine_candidate(m.bc, [_voto(m.ana, "si", 1)]))   # h+3: dentro
    assert ok, why
    ok, why = m.bc.add_transaction(_voto(m.beto, "si", 1))        # próximo bloque h+4: cerrada
    assert not ok and "cerrada" in why
    estado = m.bc.contract_state("voting")
    assert estado.tally("el1") == {"no": 0, "si": 1}
    ok, why = m.bc.add_transaction(_voto(m.ana, "si", 2))
    assert not ok


@pytest.mark.integration
def test_votar_opcion_invalida_o_sin_peso(mundo):
    m = mundo
    h = m.bc.contracts.height
    _ok(m.bc, [_eleccion(m, 4, "by_badge", 0, h + 50, badge_weights={"mentor": 3})])
    ok, why = m.bc.add_transaction(_voto(m.ana, "quizás", 1))
    assert not ok and "Opción" in why
    ok, why = m.bc.add_transaction(_voto(m.ana, "si", 1))        # sin insignia: peso 0
    assert not ok and "peso" in why


@pytest.mark.integration
def test_voto_por_insignia(mundo):
    m = mundo
    h = m.bc.contracts.height
    k = m.e.private_key_hex
    _ok(m.bc, [create_badge_award_transaction(m.e.address, m.ana.address, "mentor", "Mentor",
                                              "ayuda", k, nonce=1),
               create_badge_award_transaction(m.e.address, m.beto.address, "curioso", "Curioso",
                                              "asiste", k, nonce=2)])
    _ok(m.bc, [_eleccion(m, 4, "by_badge", 0, h + 50,
                         badge_weights={"mentor": 5, "curioso": 2})])
    _ok(m.bc, [_voto(m.ana, "si", 1), _voto(m.beto, "no", 1)])
    assert m.bc.contract_state("voting").tally("el1") == {"no": 2, "si": 5}


@pytest.mark.integration
def test_voto_por_saldo_con_foto_y_tope(mundo):
    m = mundo
    h = m.bc.contracts.height
    _ok(m.bc, [create_mint_transaction(m.a.address, m.beto.address, 10, m.k, nonce=4)])
    _ok(m.bc, [_eleccion(m, 5, "by_pupb_balance_snapshot", 0, h + 50, cap=40)])
    # Después de la foto, beto recibe saldo: NO cuenta; ana tiene 100 → tope 40.
    _ok(m.bc, [create_mint_transaction(m.a.address, m.beto.address, 500, m.k, nonce=6)])
    _ok(m.bc, [_voto(m.ana, "si", 1), _voto(m.beto, "no", 1)])
    voting = m.bc.contract_state("voting")
    assert voting.tally("el1") == {"no": 10, "si": 40}
    assert voting.configs["el1"]["snapshot"][m.ana.address] == 40
    # Alguien sin saldo en la foto no puede votar.
    nadie = Wallet.generate()
    ok, why = m.bc.add_transaction(_voto(nadie, "si", 1))
    assert not ok and "peso" in why


@pytest.mark.integration
def test_eleccion_sin_config_conserva_el_voto_unico_y_ids_no_se_repiten(mundo):
    m = mundo
    _ok(m.bc, [_voto(m.ana, "a", 1, eid="vieja"), _voto(m.beto, "a", 1, eid="vieja")])
    assert m.bc.contract_state("voting").tally("vieja") == {"a": 2}
    assert not m.bc.add_transaction(_voto(m.ana, "b", 2, eid="vieja"))[0]
    # P2-12: los votos libres no ocupan el id; crearla los descarta (una configurada sí es única).
    ok, why = m.bc.add_transaction(_eleccion(m, 4, "one_per_address", 0, 9, eid="vieja"))
    assert ok, why
    _ok(m.bc, [])
    assert not m.bc.add_transaction(_eleccion(m, 5, "one_per_address", 0, 9, eid="vieja"))[0]
    # Solo autoridad o emisor la crean.
    ok, why = m.bc.add_transaction(_eleccion(m, 2, "one_per_address", 0, 9, creador=m.ana))
    assert not ok and "autoridad o un emisor" in why


@pytest.mark.integration
def test_config_de_eleccion_invalida(mundo):
    m = mundo
    for kwargs in (
        dict(regla="otra", inicio=0, fin=5),
        dict(regla="one_per_address", inicio=5, fin=1),
        dict(regla="by_badge", inicio=0, fin=5),
        dict(regla="by_pupb_balance_snapshot", inicio=0, fin=5),
        dict(regla="by_pupb_balance_snapshot", inicio=0, fin=5, cap=0),
    ):
        regla = kwargs.pop("regla")
        inicio, fin = kwargs.pop("inicio"), kwargs.pop("fin")
        assert not m.bc.add_transaction(_eleccion(m, 4, regla, inicio, fin, **kwargs))[0], regla


# ── Determinismo ─────────────────────────────────────────────────────────────

def _foto(bc):
    t, v, c = (bc.contract_state(n) for n in ("tokens", "voting", "accounts"))
    return (t.catalog, t.receipts, t.rules, t.minted, t.awards, v.configs, v.weights,
            v.elections, c.balances, c.total_supply)


@pytest.mark.integration
def test_determinismo_replace_chain_y_recarga(mundo):
    m = mundo
    h = m.bc.contracts.height
    _ok(m.bc, [_item(m, 4)])
    _ok(m.bc, [_canje(m, 1)])
    _con_regla(m, 15, nonce=5)
    _ok(m.bc, [_eleccion(m, 7, "by_pupb_balance_snapshot", 0, h + 50, cap=40)])
    _ok(m.bc, [_voto(m.ana, "si", 2)])
    ok, why = m.bc.add_block(_bloque_en(m.bc, [_emitir(m, 1)], int(time.time()) + 2))
    assert ok, why
    assert m.bc.get_balance(m.ana.address) == 80      # 100 - 30 + 10 del premio automático
    b =_cadena(m.tmp / "b", m.a)
    ok, why = b.replace_chain([blk.to_dict() for blk in m.bc.chain])
    assert ok, why
    assert _foto(b) == _foto(m.bc)
    assert _foto(_cadena(m.tmp / "a", m.a)) == _foto(m.bc)
    assert m.bc.contract_state("voting").tally("el1") == {"no": 0, "si": 40}


# ── API ──────────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def api(tmp_path):
    autoridad, caja, ana = Wallet.generate(), Wallet.generate(), Wallet.generate()
    app = make_app(tmp_path, autoridad=autoridad, mining_difficulty=DIFICULTAD, tx_rate_limit=1000)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield SimpleNamespace(c=client, a=autoridad, caja=caja, ana=ana,
                              bc=app.state.node.blockchain)


async def _minar(api):
    r = await api.c.post("/blocks/mine", json={})
    assert r.status_code == 200, r.text


@pytest.mark.integration
async def test_api_catalogo_canje_y_elecciones(api):
    c = api.c
    assert (await c.post("/tokens/redeem-addresses", json={
        "redeem_address": api.caja.address, "label": "Imprenta"})).status_code == 200
    await _minar(api)
    assert (await c.post("/catalog", json={
        "item_id": "impresiones", "title": "50 impresiones", "price": 5, "stock": 1,
        "redeem_address": api.caja.address})).status_code == 200
    await _minar(api)
    ok, why = api.bc.add_transaction(create_mint_transaction(
        api.a.address, api.ana.address, 20, api.a.private_key_hex,
        nonce=api.bc.next_nonce(api.a.address), ))
    assert ok, why
    await _minar(api)
    items = (await c.get("/catalog")).json()["items"]
    assert items[0]["item_id"] == "impresiones" and items[0]["stock"] == 1

    malo = {"sender": api.ana.address, "private_key_hex": api.ana.private_key_hex,
            "redeem_address": api.caja.address, "amount": 4, "item_id": "impresiones"}
    r = await c.post("/tokens/redeem", json=malo)
    assert r.status_code == 400 and "precio" in r.text
    r = await c.post("/tokens/redeem", json={**malo, "amount": 5})
    assert r.status_code == 200, r.text
    await _minar(api)
    assert (await c.get("/catalog")).json()["items"][0]["stock"] == 0
    assert len((await c.get(f"/catalog/receipts/{api.ana.address}")).json()["receipts"]) == 1
    r = await c.post("/tokens/redeem", json={**malo, "amount": 5})
    assert r.status_code == 400 and "agotado" in r.text

    # Elección ponderada por la API: se crea, se vota y el recuento es ponderado.
    r = await c.post("/elections", json={
        "creator_address": api.a.address, "private_key_hex": api.a.private_key_hex,
        "election_id": "rep", "options": ["A", "B"], "weight_rule": "by_pupb_balance_snapshot",
        "start_height": 0, "end_height": 100, "cap": 10})
    assert r.status_code == 200, r.text
    await _minar(api)
    ok, why = api.bc.add_transaction(create_vote_transaction(
        api.ana.address, "rep", "A", api.ana.private_key_hex,
        nonce=api.bc.next_nonce(api.ana.address)))
    assert ok, why
    await _minar(api)
    info = (await c.get("/contracts/voting/rep")).json()
    assert info["weighted"] and info["tally"] == {"A": 10, "B": 0}
    lista = (await c.get("/elections")).json()["elections"]
    assert lista[0]["open"] and lista[0]["tally"] == {"A": 10, "B": 0}
    assert "snapshot" not in lista[0]
    assert (await c.get("/tokens/award-rules")).json()["rules"] == []
