"""Auditoría de seguridad: tipos de los campos en la validación de consenso.

``Blockchain._validate_block_at`` (``blockchain/core/chain.py``) y
``Transaction.is_consensus_valid`` (``blockchain/core/transaction.py``) comparan los
campos sin comprobar su tipo. JSON (``json.loads`` de Python, que usan P2P y la API)
admite ``NaN``, ``true`` y ``1.0``, así que un bloque recibido puede traer:

- ``header.timestamp = NaN``: ``NaN <= mediana`` y ``NaN > ahora + 2 h`` son ambos
  False, así que pasa la regla de la mediana y la del futuro. Hoy solo lo frena por
  casualidad el ``NOT NULL`` de SQLite al guardar; ``check_block`` (lo que una réplica
  PBFT revisa antes de su PREPARE) lo da por bueno: un primario bizantino consigue
  un certificado para un bloque que luego ninguna réplica puede guardar.
- ``header.index = True`` (o ``1.0``): ``True == 1``, el bloque es válido con otro hash
  (maleabilidad: dos codificaciones válidas del mismo bloque).
- TX con ``timestamp = "abc"``: válida dentro de un bloque; en el mempool la misma TX
  revienta con TypeError, y ``nan`` en ``POST /transactions`` da un 500.

Arreglo mínimo: en el bloque, ``index``/``nonce``/``difficulty`` enteros no-bool y
``timestamp`` int/float finito (``math.isfinite``); en la TX, ``timestamp`` int/float
finito, ``sender``/``recipient`` str y ``payload`` dict dentro de ``is_consensus_valid``.
"""
import json
import math

import pytest

from api.cliente_asgi import ClienteASGI
from blockchain.consensus.proof_of_work import ProofOfWork
from blockchain.core.chain import Blockchain
from blockchain.core.transaction import Transaction, TransactionType
from blockchain.core.wallet import Wallet
from tests.helpers import make_app, mine_and_add, mine_candidate


def _nueva(tmp_path):
    return Blockchain("n", str(tmp_path / "c"), initial_difficulty=1)


def _minar(bloque):
    d = bloque.header.difficulty
    res = ProofOfWork(difficulty=d).mine(bloque, timeout=60, difficulty=d)
    assert res is not None
    return res.block


def _tx(wallet, timestamp, nonce=1):
    tx = Transaction(type=TransactionType.DATA_RECORD, sender=wallet.address, recipient="DEST",
                     payload={"n": 1}, nonce=nonce, timestamp=timestamp)
    tx.sign(wallet.private_key_hex)
    return tx


@pytest.mark.xfail(strict=True, reason="timestamp NaN del encabezado pasa la validación de consenso")
def test_bloque_con_timestamp_nan_es_invalido(tmp_path):
    bc = _nueva(tmp_path)
    assert mine_and_add(bc)[0]
    cand = bc.create_candidate_block()
    cand.header.timestamp = float("nan")
    cand.hash = cand.compute_hash()
    bloque = _minar(cand)
    assert math.isnan(bloque.header.timestamp)
    ok, motivo = bc.check_block(bloque)
    assert not ok, "check_block aceptó un bloque con timestamp NaN"


@pytest.mark.xfail(strict=True, reason="header.index=True (bool) se acepta como 1: maleabilidad")
def test_bloque_con_indice_booleano_es_invalido(tmp_path):
    bc = _nueva(tmp_path)
    cand = bc.create_candidate_block()
    cand.header.index = True
    cand.hash = cand.compute_hash()
    ok, motivo = bc.add_block(_minar(cand))
    assert not ok, "se aceptó un bloque con índice True"


@pytest.mark.xfail(strict=True, reason="TX con timestamp no numérico es válida dentro de un bloque")
def test_tx_con_timestamp_no_numerico_invalida_el_bloque(tmp_path):
    bc = _nueva(tmp_path)
    tx = _tx(Wallet.generate(), "abc")
    bloque = mine_candidate(bc, [tx])
    ok, motivo = bc.check_block(bloque)
    assert not ok, "un bloque con una TX de timestamp 'abc' fue aceptado"


@pytest.mark.xfail(strict=True, reason="POST /transactions con timestamp NaN termina en 500")
def test_api_tx_con_timestamp_nan_responde_4xx(tmp_path):
    app = make_app(tmp_path)
    w = Wallet.generate()
    tx = _tx(w, float("nan"))
    d = tx.to_dict()
    cuerpo = json.dumps({"type": d["type"], "sender": d["sender"], "recipient": d["recipient"],
                         "payload": d["payload"], "nonce": 1, "signature": d["signature"],
                         "public_key": d["public_key"], "timestamp": float("nan")})
    r = ClienteASGI(app).post("/transactions", content=cuerpo,
                              headers={"content-type": "application/json"})
    assert 400 <= r.status_code < 500
