"""Almacenamiento a prueba de cortes de chain.json (P1-8).

Escritura atómica (temporal + fsync + reemplazo) y respaldo chain.json.bak
que se usa al cargar si chain.json está ausente o truncado.
"""
import json

import pytest

from blockchain.core.chain import Blockchain
from blockchain.core.transaction import Transaction, TransactionType
from blockchain.core.wallet import Wallet
from tests.helpers import mine_and_add


def _nuevo(tmp_path, nombre="store"):
    return Blockchain("store_node", str(tmp_path / nombre), initial_difficulty=1)


def _tx(wallet, n=0):
    tx = Transaction(
        type=TransactionType.DATA_RECORD,
        sender=wallet.address,
        recipient="DEST",
        payload={"n": n},
    )
    tx.sign(wallet.private_key_hex)
    return tx


def test_guardar_crea_chain_json_sin_tmp_y_respaldo_tras_segundo_guardado(tmp_path):
    """Tras guardar no queda el temporal; el .bak aparece al reemplazar chain.json."""
    bc = _nuevo(tmp_path)
    data_dir = tmp_path / "store"
    assert (data_dir / "chain.json").exists()
    assert not (data_dir / "chain.json.tmp").exists()
    assert not (data_dir / "chain.json.bak").exists()

    assert mine_and_add(bc, [_tx(Wallet.generate())])[0]

    assert (data_dir / "chain.json").exists()
    assert not (data_dir / "chain.json.tmp").exists()
    assert (data_dir / "chain.json.bak").exists()
    recargada = _nuevo(tmp_path)
    assert recargada.height == bc.height == 1


def test_fallo_a_medio_escribir_deja_chain_json_intacto(tmp_path, monkeypatch):
    """Si json.dump falla a medias, chain.json original sigue cargando."""
    bc = _nuevo(tmp_path)
    assert mine_and_add(bc, [_tx(Wallet.generate())])[0]
    data_dir = tmp_path / "store"
    original = (data_dir / "chain.json").read_bytes()

    def dump_roto(obj, f, **kwargs):
        f.write('[{"header": ')  # escritura parcial
        raise OSError("corte simulado")

    monkeypatch.setattr("blockchain.core.chain.json.dump", dump_roto)
    with pytest.raises(OSError):
        bc._save_to_disk()
    monkeypatch.undo()

    assert (data_dir / "chain.json").read_bytes() == original
    assert not (data_dir / "chain.json.tmp").exists()
    recargada = _nuevo(tmp_path)
    assert recargada.height == 1


def test_chain_json_truncado_carga_desde_respaldo(tmp_path, caplog):
    """chain.json truncado + .bak válido → se carga la cadena desde el .bak."""
    bc = _nuevo(tmp_path)
    assert mine_and_add(bc, [_tx(Wallet.generate())])[0]
    assert mine_and_add(bc, [_tx(Wallet.generate())])[0]
    data_dir = tmp_path / "store"
    # El .bak contiene la versión anterior (altura 1); chain.json la actual (altura 2).
    # Truncamos chain.json para simular un corte durante la escritura.
    texto = (data_dir / "chain.json").read_text(encoding="utf-8")
    (data_dir / "chain.json").write_text(texto[: len(texto) // 2], encoding="utf-8")

    with caplog.at_level("WARNING", logger="upb_chain.core"):
        recuperada = _nuevo(tmp_path)

    assert recuperada.height == 1
    assert any("respaldo" in r.getMessage() for r in caplog.records)
    # La cadena recuperada queda escrita de nuevo como chain.json válido.
    json.loads((data_dir / "chain.json").read_text(encoding="utf-8"))


def test_chain_json_valido_pero_cadena_invalida_no_usa_respaldo(tmp_path):
    """JSON válido con cadena inválida sigue lanzando ValueError (no se oculta con el .bak)."""
    bc = _nuevo(tmp_path)
    assert mine_and_add(bc, [_tx(Wallet.generate())])[0]
    data_dir = tmp_path / "store"
    data = json.loads((data_dir / "chain.json").read_text(encoding="utf-8"))
    data[1]["header"]["difficulty"] = 0
    (data_dir / "chain.json").write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError):
        _nuevo(tmp_path)
