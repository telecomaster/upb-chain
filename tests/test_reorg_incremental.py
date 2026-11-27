"""P2-4: la reorganización valida solo desde el punto de bifurcación.

Prueba diferencial: para escenarios de bifurcación aleatorios (semilla fija),
``replace_chain`` por el camino completo (``full_validation=True``, desde el
génesis) y por el incremental (por defecto) deben coincidir en aceptar/rechazar,
en el motivo y en el estado final (cadena, contratos, IDs confirmados, mempool,
disco, avisos de reorg). Se fuerzan los tres orígenes del estado en la
bifurcación: anillo en memoria, foto de chain.db y reproducción desde el génesis.
"""
import copy
import json
import random

import pytest

from blockchain.consensus.pbft import COMMIT, sign_message
from blockchain.core.chain import Blockchain
from blockchain.core.transaction import Transaction, TransactionType
from blockchain.core.wallet import Wallet
from tests.helpers import bloques_en_disco, mine_and_add, mine_candidate

pytestmark = pytest.mark.unit

_PARAMS = dict(initial_difficulty=1, max_difficulty=1, min_difficulty=1)


def _nodo(tmp_path, nombre, **kw):
    params = dict(_PARAMS)
    params.update(kw)
    return Blockchain(nombre, str(tmp_path / nombre), **params)


def _tx(wallet, nonce, n):
    tx = Transaction(type=TransactionType.DATA_RECORD, sender=wallet.address,
                     recipient="DEST", payload={"n": n}, nonce=nonce)
    tx.sign(wallet.private_key_hex)
    return tx


def _minar(bc, rng, wallets, etiqueta):
    """Mina un bloque con 0..2 TXs nuevas de remitentes al azar."""
    txs = []
    usados = set()
    for k in range(rng.randint(0, 2)):
        w = rng.choice(wallets)
        if w.address in usados:
            continue
        usados.add(w.address)
        tx = _tx(w, bc.next_nonce(w.address), f"{etiqueta}-{k}-{rng.random()}")
        assert bc.add_transaction(tx)[0]
        txs.append(tx)
    ok, motivo = mine_and_add(bc, txs or None)
    assert ok, motivo


def _alterar(rng, cadena, fork):
    """Devuelve (nombre, cadena posiblemente alterada) como lista de dicts."""
    datos = copy.deepcopy(cadena)
    if rng.random() < 0.5:
        return "ninguna", datos
    tipo = rng.choice(["sufijo_tx", "sufijo_nonce_float",
                       "prefijo_tx", "prefijo_nonce_float", "genesis", "prefijo_propio",
                       "sufijo_hash"])
    sufijo = list(range(fork + 1, len(datos)))
    prefijo = list(range(1, fork + 1))
    con_txs = [i for i in prefijo if datos[i]["transactions"]]
    if tipo == "sufijo_tx" and sufijo:
        i = rng.choice(sufijo)
        if datos[i]["transactions"]:
            datos[i]["transactions"][0]["payload"]["n"] = "alterado"
        else:
            datos[i]["transactions"].append({"basura": True})
    elif tipo == "sufijo_nonce_float" and sufijo:
        datos[rng.choice(sufijo)]["header"]["nonce"] += 0.0
    elif tipo == "sufijo_hash" and sufijo:
        datos[rng.choice(sufijo)]["hash"] = "0" * 64
    elif tipo == "prefijo_tx" and con_txs:
        # Mismo campo "hash" que nuestro bloque pero contenido distinto.
        datos[rng.choice(con_txs)]["transactions"][0]["payload"]["n"] = "alterado"
    elif tipo == "prefijo_nonce_float" and prefijo:
        datos[rng.choice(prefijo)]["header"]["nonce"] += 0.0
    elif tipo == "genesis":
        datos[0]["header"]["node_id"] = "otro"
    elif tipo == "prefijo_propio":
        datos = datos[:max(1, fork)]
    else:
        tipo = "ninguna"
    return tipo, datos


def _estado(bc, eventos):
    return {
        "cadena": [b.hash for b in bc.chain],
        "contratos": bc.contracts.dump_states(bc.contracts._states),
        "altura_contratos": bc.contracts.height,
        "ids": sorted(map(str, bc._confirmed_ids)),
        "mempool": [t.tx_id for t in bc.mempool],
        "disco": [b["hash"] for b in bloques_en_disco(bc.data_dir)],
        "eventos": [(f, [b.hash for b in d], [b.hash for b in a]) for f, d, a in eventos],
    }


@pytest.mark.parametrize("anillo,fotos", [(16, 3), (0, 3), (0, 0), (2, 0)])
def test_diferencial_completo_vs_incremental(tmp_path, anillo, fotos):
    rng = random.Random(1234 + anillo * 7 + fotos)
    wallets = [Wallet.generate() for _ in range(3)]
    vistos = set()
    for caso in range(12):
        base = tmp_path / f"c{caso}"
        a = _nodo(base, "a", snapshot_interval=fotos)
        for k in range(rng.randint(1, 7)):
            _minar(a, rng, wallets, f"a{caso}-{k}")
        # B comparte un prefijo de A y luego diverge.
        fork = rng.randint(0, a.height)
        b = _nodo(base, "b", snapshot_interval=fotos)
        for blk in a.chain[1:fork + 1]:
            assert b.add_block(blk)[0]
        for k in range(rng.randint(0, 4)):
            _minar(a, rng, wallets, f"a2{caso}-{k}")
        # A veces B confirma TXs que A tiene en los bloques que se descartarán
        # (la misma TX en ambas ramas: no es duplicado en la cadena nueva).
        if rng.random() < 0.5:
            compartidas = [Transaction.from_dict(t) for blk in a.chain[fork + 1:]
                           for t in blk.transactions]
            elegidas = [t for t in compartidas if b.add_transaction(t)[0]]
            if elegidas:
                assert mine_and_add(b, elegidas)[0]
        # Casi siempre B alcanza o supera el trabajo de A (empates y menos, a veces).
        for k in range(max(1, a.height - fork + rng.randint(-1, 2))):
            _minar(b, rng, wallets, f"b{caso}-{k}")
        tipo, candidata = _alterar(rng, [blk.to_dict() for blk in b.chain], fork)
        # Pendientes comunes en ambos receptores (algunas quedarán confirmadas).
        pendientes = [_tx(Wallet.generate(), 1, f"p{caso}-{k}") for k in range(2)]

        resultados = {}
        for modo in ("completo", "incremental"):
            r = _nodo(base, modo, snapshot_interval=fotos)
            r.recent_states_kept = anillo
            for blk in a.chain[1:]:
                assert r.add_block(blk)[0]
            for t in pendientes:
                assert r.add_transaction(t)[0]
            eventos = []
            r.add_reorg_listener(lambda f, d, ad, ev=eventos: ev.append((f, d, ad)))
            res = r.replace_chain(candidata, full_validation=(modo == "completo"))
            resultados[modo] = (res, _estado(r, eventos))
        assert resultados["completo"] == resultados["incremental"], (caso, tipo)
        vistos.add((tipo, resultados["completo"][0][0]))
    # El generador recorrió casos aceptados y rechazados.
    assert {ok for _, ok in vistos} == {True, False}


def test_reorg_cercano_valida_solo_el_sufijo(tmp_path):
    """Reorg de 2 bloques sobre una cadena larga: solo se validan los 2 nuevos
    y el estado sale del anillo en memoria (sin reproducir desde el génesis)."""
    w = Wallet.generate()
    a = _nodo(tmp_path, "a", snapshot_interval=0)
    for k in range(30):
        assert mine_and_add(a, [_tx(w, k + 1, k)])[0]
    b = _nodo(tmp_path, "b", snapshot_interval=0)
    for blk in a.chain[1:-1]:
        assert b.add_block(blk)[0]
    mine_and_add(b)
    mine_and_add(b)                 # B: 29 comunes + 2 propios > A: 30
    reproducidos = []
    original = a.contracts.run_block
    a.contracts.run_block = lambda st, blk: (reproducidos.append(blk.header.index),
                                             original(st, blk))[1]
    eventos = []
    a.add_reorg_listener(lambda f, d, ad: eventos.append((f, d, ad)))
    ok, motivo = a.replace_chain([blk.to_dict() for blk in b.chain])
    assert ok, motivo
    assert a.last_replace_validated == 2
    assert reproducidos == [30, 31]
    # La TX del bloque 30 descartado vuelve al mempool; el aviso se emitió.
    assert [t.payload["n"] for t in a.mempool] == [29]
    assert eventos and eventos[0][0] == 29 and len(eventos[0][1]) == 1
    # Mismo estado que un nodo nuevo que valida todo desde el génesis.
    c = _nodo(tmp_path, "c")
    assert c.replace_chain([blk.to_dict() for blk in b.chain], full_validation=True)[0]
    assert c.contracts.dump_states(c.contracts._states) == \
        a.contracts.dump_states(a.contracts._states)


def test_estado_en_la_bifurcacion_desde_foto(tmp_path):
    """Sin anillo: el estado en la bifurcación sale de la foto de chain.db y se
    reproducen solo los bloques locales entre la foto y la bifurcación."""
    w = Wallet.generate()
    a = _nodo(tmp_path, "a", snapshot_interval=5)
    a.recent_states_kept = 0
    for k in range(12):
        assert mine_and_add(a, [_tx(w, k + 1, k)])[0]
    b = _nodo(tmp_path, "b")
    for blk in a.chain[1:8]:
        assert b.add_block(blk)[0]
    for _ in range(6):
        mine_and_add(b)
    reproducidos = []
    original = a.contracts.run_block
    a.contracts.run_block = lambda st, blk: (reproducidos.append(blk.header.index),
                                             original(st, blk))[1]
    ok, motivo = a.replace_chain([blk.to_dict() for blk in b.chain])
    assert ok, motivo
    # Foto en la altura 5 → reproducir 6 y 7 (locales) y validar 8..13 (nuevos).
    assert reproducidos == [6, 7, 8, 9, 10, 11, 12, 13]
    assert a.last_replace_validated == 6


# ── PBFT: los certificados del sufijo se siguen exigiendo ─────────────────────

class _Replicas:
    def __init__(self):
        from blockchain.consensus.pbft import ReplicaSet
        self.wallets = [Wallet.generate() for _ in range(4)]
        self.rs = ReplicaSet.from_list([
            {"id": f"r{i}", "address": f"127.0.0.1:{9000 + i}", "public_key": w.public_key_hex}
            for i, w in enumerate(self.wallets)])

    def cert(self, block, firmantes=(0, 1, 2)):
        h = block.header.index
        return {"view": 0, "seq": h, "digest": block.hash,
                "commits": [sign_message({"replica": f"r{i}", "type": COMMIT, "view": 0,
                                          "seq": h, "digest": block.hash},
                                         self.wallets[i].private_key_hex)
                            for i in firmantes]}


def _pbft(tmp_path, nombre, rep):
    return Blockchain(node_id=nombre, data_dir=str(tmp_path / nombre), consensus="pbft",
                      replica_set=rep.rs)


def _certs_variantes(fuente, rep):
    todos = {str(h): c for h, c in fuente.certificates.items()}
    sin_prefijo = {k: v for k, v in todos.items() if k != "1"}
    sin_sufijo = {k: v for k, v in todos.items() if k != "3"}
    malo = dict(todos)
    malo["3"] = {**todos["3"], "commits": todos["3"]["commits"][:2]}
    otro_prefijo = dict(todos)
    otro_prefijo["1"] = rep.cert(fuente.chain[1], (1, 2, 3))   # válido, otras firmas
    malo_prefijo = dict(todos)
    malo_prefijo["1"] = {**todos["1"], "commits": todos["1"]["commits"][:1]}
    return [todos, sin_prefijo, sin_sufijo, malo, otro_prefijo, malo_prefijo]


def test_pbft_diferencial_certificados(tmp_path):
    rep = _Replicas()
    fuente = _pbft(tmp_path, "fuente", rep)
    for k in range(3):
        blk = mine_candidate(fuente, [_tx(Wallet.generate(), 1, k)])
        assert fuente.add_block(blk, rep.cert(blk))[0]
    datos = [b.to_dict() for b in fuente.chain]
    aceptadas = []
    for j, certs in enumerate(_certs_variantes(fuente, rep)):
        resultados = {}
        for modo in ("completo", "incremental"):
            r = _pbft(tmp_path / f"v{j}", modo, rep)
            assert r.add_block(fuente.chain[1], fuente.certificates[1])[0]
            res = r.replace_chain(datos, certs, full_validation=(modo == "completo"))
            resultados[modo] = (res, [b.hash for b in r.chain], dict(r.certificates))
        assert resultados["completo"] == resultados["incremental"], j
        aceptadas.append(resultados["completo"][0][0])
    # Entran: todos los certificados y un prefijo con otras firmas válidas.
    assert aceptadas == [True, False, False, False, True, False]


def test_pbft_sufijo_sin_certificado_se_rechaza(tmp_path):
    rep = _Replicas()
    fuente = _pbft(tmp_path, "fuente", rep)
    for k in range(3):
        blk = mine_candidate(fuente, [_tx(Wallet.generate(), 1, k)])
        assert fuente.add_block(blk, rep.cert(blk))[0]
    r = _pbft(tmp_path, "r", rep)
    assert r.add_block(fuente.chain[1], fuente.certificates[1])[0]
    datos = [b.to_dict() for b in fuente.chain]
    ok, motivo = r.replace_chain(datos, {1: fuente.certificates[1], 2: fuente.certificates[2]})
    assert not ok and "Bloque 3" in motivo and "certificados" in motivo
    assert r.height == 1
    ok, motivo = r.replace_chain(datos, {h: fuente.certificates[h] for h in (1, 2, 3)})
    assert ok, motivo
    assert r.last_replace_validated == 2
    assert json.dumps(r.certificates, sort_keys=True) == \
        json.dumps(fuente.certificates, sort_keys=True)
