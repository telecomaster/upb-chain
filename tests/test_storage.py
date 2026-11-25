"""Almacenamiento de la cadena en SQLite (P2-4; reemplaza las pruebas de chain.json de P1-8).

- Agregar un bloque y reorganizar son UNA transacción: un fallo o un corte a
  la mitad deja chain.db (y la memoria) como estaban.
- Arrancar desde una foto de estado da los mismos contratos que reproducir
  desde el génesis; una foto dañada se ignora.
- Migración desde chain.json (sin borrar el original).
- Búsquedas por índice iguales a un recorrido por fuerza bruta.
- chain.db dañado: error claro, nada se borra.
"""
import json
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

from blockchain.contracts.tokens import semester_of
from blockchain.core.chain import Blockchain
from blockchain.core.storage import ChainStore, StorageError
from blockchain.core.transaction import (Transaction, TransactionType,
                                         create_badge_award_transaction,
                                         create_credential_transaction,
                                         create_issuer_budget_transaction,
                                         create_issuer_register_transaction,
                                         create_mint_transaction, create_revoke_transaction,
                                         create_transfer_transaction, create_vote_transaction)
from blockchain.core.wallet import Wallet
from tests.helpers import mine_and_add, mine_candidate

RAIZ = Path(__file__).resolve().parent.parent


def _nuevo(directorio, **kw):
    kw.setdefault("initial_difficulty", 1)
    return Blockchain("store_node", str(directorio), **kw)


def _tx(wallet, n=0, nonce=1, recipient="DEST"):
    tx = Transaction(type=TransactionType.DATA_RECORD, sender=wallet.address,
                     recipient=recipient, payload={"n": n}, nonce=nonce)
    tx.sign(wallet.private_key_hex)
    return tx


def _hashes_en_disco(directorio):
    store = ChainStore(Path(directorio) / "chain.db", readonly=True)
    try:
        return [b["hash"] for b in store.load_blocks()]
    finally:
        store.close()


def _falla_al_insertar_txs(monkeypatch):
    """Simula un error de disco DESPUÉS de insertar la fila del bloque."""
    def roto(self, conn, block):
        raise sqlite3.OperationalError("disco lleno (simulado)")
    monkeypatch.setattr(ChainStore, "_insert_txs", roto)


# ── Escritura atómica ────────────────────────────────────────────────────────

def test_genesis_y_bloques_van_a_chain_db_sin_chain_json(tmp_path):
    bc = _nuevo(tmp_path / "s")
    assert (tmp_path / "s" / "chain.db").exists()
    assert not (tmp_path / "s" / "chain.json").exists()
    assert mine_and_add(bc, [_tx(Wallet.generate())])[0]
    assert _hashes_en_disco(tmp_path / "s") == [b.hash for b in bc.chain]
    assert _nuevo(tmp_path / "s").height == 1


def test_fallo_a_mitad_del_append_no_deja_nada(tmp_path, monkeypatch):
    """El bloque ya se insertó cuando fallan las TXs: el ROLLBACK lo quita."""
    bc = _nuevo(tmp_path / "s")
    assert mine_and_add(bc, [_tx(Wallet.generate())])[0]
    antes = _hashes_en_disco(tmp_path / "s")
    bloque = mine_candidate(bc, [_tx(Wallet.generate())])

    _falla_al_insertar_txs(monkeypatch)
    ok, motivo = bc.add_block(bloque)
    monkeypatch.undo()

    assert not ok and "almacenamiento" in motivo
    assert bc.height == 1                                   # memoria sin cambios
    assert _hashes_en_disco(tmp_path / "s") == antes        # disco sin cambios
    assert bc.add_block(bloque)[0]                          # y el mismo bloque entra después
    assert _nuevo(tmp_path / "s").height == 2


def test_proceso_muerto_a_mitad_del_append_deja_la_base_consistente(tmp_path):
    """Corte real: el proceso muere (os._exit) dentro de la transacción, sin COMMIT."""
    bc = _nuevo(tmp_path / "s")
    assert mine_and_add(bc, [_tx(Wallet.generate())])[0]
    bc.close()
    antes = _hashes_en_disco(tmp_path / "s")
    codigo = f"""
import os, sys
sys.path.insert(0, {str(RAIZ)!r})
from blockchain.core.chain import Blockchain
from blockchain.core.storage import ChainStore
from blockchain.core.transaction import Transaction, TransactionType
from blockchain.core.wallet import Wallet
from tests.helpers import mine_candidate
bc = Blockchain("store_node", {str(tmp_path / "s")!r}, initial_difficulty=1)
w = Wallet.generate()
tx = Transaction(type=TransactionType.DATA_RECORD, sender=w.address, recipient="D",
                 payload={{"n": 1}}, nonce=1)
tx.sign(w.private_key_hex)
bloque = mine_candidate(bc, [tx])
def morir(self, conn, block):
    os._exit(7)          # el bloque ya está insertado en la transacción abierta
ChainStore._insert_txs = morir
bc.add_block(bloque)
"""
    r = subprocess.run([sys.executable, "-c", codigo], cwd=str(RAIZ), timeout=120,
                       capture_output=True, text=True)
    assert r.returncode == 7, r.stderr
    assert _hashes_en_disco(tmp_path / "s") == antes
    recargada = _nuevo(tmp_path / "s")
    assert recargada.height == 1
    assert mine_and_add(recargada, [_tx(Wallet.generate())])[0]


def _dos_ramas(tmp_path):
    """``a`` con 2 bloques propios; ``b`` (otra rama desde el génesis) con 4."""
    a, b = _nuevo(tmp_path / "a"), _nuevo(tmp_path / "b")
    for _ in range(2):
        assert mine_and_add(a, [_tx(Wallet.generate())])[0]
    for _ in range(4):
        assert mine_and_add(b, [_tx(Wallet.generate())])[0]
    return a, b


def test_fallo_a_mitad_del_reorg_no_deja_nada(tmp_path, monkeypatch):
    a, b = _dos_ramas(tmp_path)
    antes = [blk.hash for blk in a.chain]
    assert _hashes_en_disco(tmp_path / "a") == antes

    _falla_al_insertar_txs(monkeypatch)
    ok, motivo = a.replace_chain([blk.to_dict() for blk in b.chain])
    monkeypatch.undo()

    assert not ok and "almacenamiento" in motivo
    assert [blk.hash for blk in a.chain] == antes            # memoria: la vieja
    assert _hashes_en_disco(tmp_path / "a") == antes         # disco: el DELETE se deshizo
    ok, motivo = a.replace_chain([blk.to_dict() for blk in b.chain])
    assert ok, motivo
    assert _hashes_en_disco(tmp_path / "a") == [blk.hash for blk in b.chain]
    assert [blk.hash for blk in _nuevo(tmp_path / "a").chain] == [blk.hash for blk in b.chain]


def test_chain_db_danado_da_error_claro_y_no_borra_nada(tmp_path):
    d = tmp_path / "s"
    d.mkdir()
    basura = b"esto no es una base SQLite" * 100
    (d / "chain.db").write_bytes(basura)
    with pytest.raises(StorageError) as e:
        _nuevo(d)
    assert "chain.db" in str(e.value) and "No se borró nada" in str(e.value)
    assert (d / "chain.db").read_bytes() == basura


# ── Fotos de estado ──────────────────────────────────────────────────────────

def _cadena_rica(directorio, autoridad, **kw):
    """Cadena con emisores, credenciales (una revocada), tokens, insignias y votos."""
    bc = Blockchain("rica", str(directorio), initial_difficulty=1,
                    authority_address=autoridad.address, **kw)
    emisor, ana, beto = Wallet.generate(), Wallet.generate(), Wallet.generate()
    k, ke = autoridad.private_key_hex, emisor.private_key_hex
    semestre = semester_of(time.time())
    lotes = [
        [create_issuer_register_transaction(autoridad.address, emisor.address, "UPB", k, nonce=1),
         create_issuer_budget_transaction(autoridad.address, emisor.address, semestre, 100, k,
                                          nonce=2),
         create_mint_transaction(autoridad.address, ana.address, 50, k, nonce=3)],
        [create_credential_transaction(emisor.address, ana.address, _datos("A"), ke, nonce=1),
         create_credential_transaction(emisor.address, beto.address, _datos("B"), ke, nonce=2)],
        [create_badge_award_transaction(emisor.address, ana.address, "hackaton", "Hackatón",
                                        "ganó", ke, nonce=3),
         create_vote_transaction(ana.address, "eleccion-1", "si", ana.private_key_hex, nonce=1)],
        [create_transfer_transaction(ana.address, beto.address, 7, ana.private_key_hex,
                                     nonce=2, fee=1),
         create_vote_transaction(beto.address, "eleccion-1", "no", beto.private_key_hex, nonce=1)],
    ]
    for lote in lotes:
        ok, why = mine_and_add(bc, lote)
        assert ok, why
    from blockchain.contracts.credential import CredentialContract
    cid = CredentialContract.credential_id_of_tx(lotes[1][1].to_dict())
    ok, why = mine_and_add(bc, [create_revoke_transaction(emisor.address, cid, "error", ke,
                                                          nonce=4)])
    assert ok, why
    ok, why = mine_and_add(bc, [create_mint_transaction(emisor.address, beto.address, 9, ke,
                                                        nonce=5, reason="taller")])
    assert ok, why
    for _ in range(2):
        assert mine_and_add(bc)[0]
    return bc


def _datos(sufijo):
    return {"program": "Ingeniería en IA", "degree": f"Licenciatura {sufijo}",
            "issue_date": "2026-06-10", "credential_type": "DEGREE", "student_name": "X"}


def _estado(bc):
    return bc.contracts.dump_states({n: bc.contract_state(n) for n in bc.contracts.names})


def test_reinicio_desde_foto_igual_a_reproduccion_completa(tmp_path):
    autoridad = Wallet.generate()
    a = _cadena_rica(tmp_path / "a", autoridad, snapshot_interval=3)
    assert a.height == 8
    alturas = [s.height for s in a.store.snapshots()]
    assert alturas == [6, 3]

    rapida = Blockchain("r", str(tmp_path / "a"), initial_difficulty=1,
                        authority_address=autoridad.address, snapshot_interval=3)
    completa = Blockchain("c", str(tmp_path / "a"), initial_difficulty=1,
                          authority_address=autoridad.address, snapshot_interval=3,
                          revalidate_on_start="full")
    assert rapida.replayed_on_start == 2            # solo los bloques 7 y 8
    assert completa.replayed_on_start == 8
    assert _estado(rapida) == _estado(completa) == _estado(a)
    # Las consultas de la API ven lo mismo (orden de dicts incluido).
    cred_r, cred_c = rapida.contract_state("credentials"), completa.contract_state("credentials")
    assert cred_r.get_all_credentials() == cred_c.get_all_credentials()
    assert cred_r.get_stats() == cred_c.get_stats() == {
        "total_credentials": 2, "active": 1, "revoked": 1, "registered_issuers": 1,
        "students_with_credentials": 2}
    assert rapida.contract_state("voting").tally("eleccion-1") == {"no": 1, "si": 1}
    # El arranque completo rehace las fotos: solo queda la de la punta.
    assert [s.height for s in completa.store.snapshots()] == [8]


def test_foto_danada_se_ignora_y_se_reproduce_desde_la_anterior(tmp_path, caplog):
    autoridad = Wallet.generate()
    a = _cadena_rica(tmp_path / "a", autoridad, snapshot_interval=3)
    esperado = _estado(a)
    a.close()
    conn = sqlite3.connect(str(tmp_path / "a" / "chain.db"))
    with conn:
        conn.execute("UPDATE snapshots SET states = replace(states, '\"si\"', '\"no\"') "
                     "WHERE height = 6")
    conn.close()
    with caplog.at_level("WARNING", logger="upb_chain.core"):
        b = Blockchain("b", str(tmp_path / "a"), initial_difficulty=1,
                       authority_address=autoridad.address, snapshot_interval=3)
    assert any("dañada" in r.getMessage() for r in caplog.records)
    assert b.replayed_on_start == 5                 # desde la foto de la altura 3
    assert _estado(b) == esperado


def test_reorg_borra_las_fotos_de_la_rama_descartada(tmp_path):
    a = _nuevo(tmp_path / "a", snapshot_interval=2)
    b = _nuevo(tmp_path / "b", snapshot_interval=2)
    for _ in range(4):
        assert mine_and_add(a, [_tx(Wallet.generate())])[0]
    for _ in range(5):
        assert mine_and_add(b, [_tx(Wallet.generate())])[0]
    assert [s.height for s in a.store.snapshots()] == [4, 2]
    ok, why = a.replace_chain([blk.to_dict() for blk in b.chain])
    assert ok, why
    fotos = a.store.snapshots()
    assert [s.height for s in fotos] == [5]         # las de la rama vieja no quedan
    assert all(a.chain[s.height].hash == s.block_hash for s in fotos)
    assert _estado(_nuevo(tmp_path / "a", snapshot_interval=2)) == _estado(b)


@pytest.mark.slow
def test_arranque_rapido_mucho_menor_que_revalidacion_completa(tmp_path):
    """300 bloques con TXs firmadas: el arranque rápido no verifica firmas ni
    reproduce contratos (foto en la altura 300). Se compara relativo, no absoluto."""
    bc = _nuevo(tmp_path / "p", max_difficulty=1, snapshot_interval=100)
    w = Wallet.generate()
    for i in range(300):
        assert mine_and_add(bc, [_tx(w, n=i, nonce=i + 1)])[0]
    bc.close()

    def medir(modo):
        t0 = time.perf_counter()
        c = _nuevo(tmp_path / "p", max_difficulty=1, snapshot_interval=100,
                   revalidate_on_start=modo)
        dt = time.perf_counter() - t0
        assert c.height == 300
        c.close()
        return dt, c

    # "full" primero: además rehace la foto en la punta, que usará "fast".
    t_full, completa = medir("full")
    t_fast, rapida = medir("fast")
    assert rapida.replayed_on_start == 0
    assert _estado(rapida) == _estado(completa)
    assert t_fast < t_full / 2, (t_fast, t_full)


# ── Migración desde chain.json y exportación ─────────────────────────────────

def _exportar(directorio):
    sys.path.insert(0, str(RAIZ / "scripts"))
    try:
        import exportar_cadena
    finally:
        sys.path.pop(0)
    return exportar_cadena.exportar(Path(directorio))


def test_migracion_desde_chain_json_conserva_el_original(tmp_path):
    autoridad = Wallet.generate()
    a = _cadena_rica(tmp_path / "a", autoridad)
    datos = _exportar(tmp_path / "a")
    assert datos == [blk.to_dict() for blk in a.chain]
    viejo = tmp_path / "viejo"
    viejo.mkdir()
    texto = json.dumps(datos, indent=2)
    (viejo / "chain.json").write_text(texto, encoding="utf-8")

    m = Blockchain("m", str(viejo), initial_difficulty=1, authority_address=autoridad.address)
    assert m.replayed_on_start == a.height          # importación con validación completa
    assert [blk.hash for blk in m.chain] == [blk.hash for blk in a.chain]
    assert _estado(m) == _estado(a)
    assert not (viejo / "chain.json").exists()
    assert (viejo / "chain.json.migrated").read_text(encoding="utf-8") == texto
    assert _hashes_en_disco(viejo) == [blk.hash for blk in a.chain]
    # Siguiente arranque: desde chain.db.
    assert _nuevo(viejo, authority_address=autoridad.address).height == a.height


def test_migracion_con_chain_json_truncado_usa_el_respaldo(tmp_path, caplog):
    bc = _nuevo(tmp_path / "a")
    assert mine_and_add(bc, [_tx(Wallet.generate())])[0]
    datos = _exportar(tmp_path / "a")
    viejo = tmp_path / "viejo"
    viejo.mkdir()
    (viejo / "chain.json").write_text('[{"header": ', encoding="utf-8")   # corte de P1-8
    (viejo / "chain.json.bak").write_text(json.dumps(datos), encoding="utf-8")
    with caplog.at_level("WARNING", logger="upb_chain.core"):
        m = _nuevo(viejo)
    assert m.height == 1
    assert any("respaldo" in r.getMessage() for r in caplog.records)
    # Ni el truncado ni el respaldo se borran.
    assert (viejo / "chain.json.migrated").read_text(encoding="utf-8") == '[{"header": '
    assert (viejo / "chain.json.bak.migrated").exists()


def test_migracion_de_cadena_invalida_falla_y_no_toca_chain_json(tmp_path):
    bc = _nuevo(tmp_path / "a")
    assert mine_and_add(bc, [_tx(Wallet.generate())])[0]
    datos = _exportar(tmp_path / "a")
    datos[1]["header"]["difficulty"] = 0
    viejo = tmp_path / "viejo"
    viejo.mkdir()
    (viejo / "chain.json").write_text(json.dumps(datos), encoding="utf-8")
    with pytest.raises(ValueError):
        _nuevo(viejo)
    assert (viejo / "chain.json").exists()
    assert not (viejo / "chain.json.migrated").exists()


def test_script_de_exportacion_escribe_json(tmp_path):
    bc = _nuevo(tmp_path / "a")
    assert mine_and_add(bc, [_tx(Wallet.generate())])[0]
    salida = tmp_path / "export.json"
    r = subprocess.run([sys.executable, str(RAIZ / "scripts" / "exportar_cadena.py"),
                        str(tmp_path / "a"), "-o", str(salida)],
                       cwd=str(RAIZ), timeout=60, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert json.loads(salida.read_text(encoding="utf-8")) == [b.to_dict() for b in bc.chain]


# ── Búsquedas por índice vs. fuerza bruta ─────────────────────────────────────

def _fuerza_bruta_tx(bc, tx_id):
    for block in bc.chain:
        for tx in block.transactions:
            if tx.get("tx_id") == tx_id:
                return {**tx, "block": block.header.index, "confirmed": True}
    return None


def _fuerza_bruta_direccion(bc, address):
    return [{**tx, "block": b.header.index} for b in bc.chain for tx in b.transactions
            if tx.get("tx_id") and address in (tx.get("sender"), tx.get("recipient"))]


def test_busquedas_por_indice_iguales_a_fuerza_bruta(tmp_path):
    autoridad = Wallet.generate()
    bc = _cadena_rica(tmp_path / "a", autoridad)
    direcciones = {tx.get("sender") for b in bc.chain for tx in b.transactions}
    direcciones |= {tx.get("recipient") for b in bc.chain for tx in b.transactions}
    direcciones.discard(None)
    assert len(direcciones) >= 4
    for b in bc.chain:
        assert bc.get_block_by_hash(b.hash) is b
        for i, tx in enumerate(b.transactions):
            if not tx.get("tx_id"):
                continue
            assert bc.get_transaction(tx["tx_id"]) == _fuerza_bruta_tx(bc, tx["tx_id"])
            assert bc.locate_transaction(tx["tx_id"]) == (b, i)
    for d in direcciones:
        assert bc.transactions_of(d) == _fuerza_bruta_direccion(bc, d)
        esperadas = [{**tx["payload"], "block": b.header.index} for b in bc.chain
                     for tx in b.transactions
                     if tx.get("type") == "CREDENTIAL_ISSUE" and tx.get("recipient") == d]
        assert bc.get_credentials_for(d) == esperadas
    assert bc.get_transaction("no-existe") is None
    assert bc.get_block_by_hash("0" * 64) is None
    assert bc.get_stats()["total_transactions"] == sum(len(b.transactions) for b in bc.chain)


def test_busquedas_tras_reorg_ven_la_cadena_nueva(tmp_path):
    a, b = _dos_ramas(tmp_path)
    viejas = [tx["tx_id"] for blk in a.chain[1:] for tx in blk.transactions]
    viejo_hash = a.chain[1].hash
    ok, why = a.replace_chain([blk.to_dict() for blk in b.chain])
    assert ok, why
    for tx_id in viejas:            # volvieron al mempool, no están confirmadas
        assert a.get_transaction(tx_id) is None
    assert a.get_block_by_hash(viejo_hash) is None
    for blk in b.chain[1:]:
        assert a.get_block_by_hash(blk.hash).hash == blk.hash
        for tx in blk.transactions:
            assert a.get_transaction(tx["tx_id"])["block"] == blk.header.index
