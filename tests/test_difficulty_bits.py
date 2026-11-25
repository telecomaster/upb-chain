"""Tests de P2-5: dificultad en bits, reajuste entero por épocas y trabajo Σ 2**bits."""
import ast
import importlib.util
import inspect
import textwrap
import time
from pathlib import Path

import pytest

from blockchain.consensus.proof_of_work import ProofOfWork
from blockchain.core import block as block_mod
from blockchain.core.block import (GENESIS_HASH, Block, BlockHeader, hash_meets_bits,
                                   target_for_bits, work_for_bits)
from blockchain.core.chain import Blockchain, _ms, retarget_step

pytestmark = pytest.mark.unit

RAIZ = Path(__file__).resolve().parent.parent


# ── Semántica de los bits ────────────────────────────────────────────────────

def test_objetivo_y_trabajo_en_bits():
    assert target_for_bits(0) == 2 ** 256
    assert target_for_bits(8) == 2 ** 248
    assert work_for_bits(16) == 65_536
    limite = format(target_for_bits(10), "064x")          # el primer hash que NO cumple
    justo = format(target_for_bits(10) - 1, "064x")       # el mayor hash que cumple
    assert hash_meets_bits(justo, 10) and not hash_meets_bits(limite, 10)
    # 4 bits ⇔ primer carácter hex "0"; 6 bits exige además segundo carácter < 4.
    assert hash_meets_bits("0f" + "f" * 62, 4)
    assert not hash_meets_bits("0f" + "f" * 62, 6)
    assert hash_meets_bits("03" + "f" * 62, 6)
    # entradas malformadas nunca cumplen
    for malo in [("zz" * 32, 1), ("0" * 63, 1), ("0" * 64, -1), ("0" * 64, 257), ("0" * 64, True)]:
        assert not hash_meets_bits(*malo)


def test_genesis_sigue_valido_con_0_bits():
    g = Block.create_genesis()
    assert g.header.difficulty == 0 and g.hash == GENESIS_HASH
    assert hash_meets_bits(g.hash, 0)


def test_bloque_con_bits_insuficientes_rechazado(tmp_path):
    """Un hash con 4 bits en cero (un '0' hex) no basta si la cadena exige 6 bits."""
    bc = Blockchain("n", str(tmp_path / "c"), initial_difficulty=6)
    cand = bc.create_candidate_block([])
    assert cand.header.difficulty == 6
    n = 0
    while True:  # nonce con exactamente 4 o 5 bits en cero: cumple el viejo "0", no 6 bits
        cand.header.nonce = n
        cand.hash = cand.compute_hash()
        if hash_meets_bits(cand.hash, 4) and not hash_meets_bits(cand.hash, 6):
            break
        n += 1
    ok, motivo = bc.add_block(cand)
    assert not ok and "Proof of Work" in motivo
    assert bc.height == 0
    # Minado de verdad con 6 bits: se acepta.
    res = ProofOfWork().mine(cand, difficulty=6, timeout=60.0)
    assert int(res.hash, 16) < 2 ** 250
    assert bc.add_block(res.block)[0]


def test_verificador_liviano_comprueba_bits():
    spec = importlib.util.spec_from_file_location(
        "verificar_prueba", RAIZ / "scripts" / "verificar_prueba.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    casos = ["0f" + "f" * 62, "03" + "f" * 62, "0" * 64, "f" * 64]
    for h in casos:
        for bits in (0, 1, 4, 6, 8, 256):
            assert mod.cumple_bits(h, bits) == hash_meets_bits(h, bits), (h, bits)
    assert not mod.cumple_bits("0" * 64, 300)


# ── Regla de reajuste ────────────────────────────────────────────────────────

@pytest.mark.parametrize("esperado, real, paso", [
    (1000, 1000, 0),      # en objetivo
    (1000, 500, 1),       # el doble de rápido → +1 bit
    (1000, 250, 2),       # 4× más rápido → +2
    (1000, 100, 2),       # 10× → log2 ≈ 3,3, acotado a +2
    (1000, 2000, -1),     # el doble de lento → -1
    (1000, 4000, -2),
    (1000, 10_000, -2),   # acotado a -2
    (1000, 709, 0),       # razón 1,41 < √2 → 0
    (1000, 707, 1),       # razón 1,414… ≥ √2 → +1
    (1000, 1414, 0),      # razón 0,7072 > 1/√2 → 0
    (1000, 1415, -1),     # razón 0,7067 < 1/√2 → -1
    (1000, 0, 2),         # timestamps iguales: "muy rápido"
    (1000, -5, 2),
])
def test_retarget_step_redondea_log2_y_acota(esperado, real, paso):
    assert retarget_step(esperado, real, 2) == paso


def test_retarget_step_con_paso_maximo_mayor():
    assert retarget_step(1000, 100, 4) == 3      # round(3,32) = 3
    assert retarget_step(1000, 10, 8) == 7       # round(6,64) = 7
    assert retarget_step(10, 1000, 8) == -7


def _cadena_sintetica(bc, intervalos):
    """Bloques sin PoW real con los intervalos dados; la dificultad la dicta la regla."""
    chain = [bc.chain[0]]
    t = 1_800_000_000.0
    for i, dt in enumerate(intervalos, start=1):
        t += dt
        hdr = BlockHeader(index=i, timestamp=t, previous_hash=chain[-1].hash, merkle_root="x",
                          difficulty=bc.expected_difficulty(chain), node_id="n")
        chain.append(Block(header=hdr, transactions=[]))
    return chain


def _bits(chain):
    return [b.header.difficulty for b in chain[1:]]


def test_reajuste_por_epocas_rapida_lenta_y_estable(tmp_path):
    bc = Blockchain("n", str(tmp_path / "c"), initial_difficulty=10, min_difficulty=1,
                    max_difficulty=20, difficulty_window=4, target_block_time=10)
    # Época = 4 bloques; se reajusta en h = 5, 9, 13 midiendo la época anterior.
    rapida = _cadena_sintetica(bc, [2.5] * 12)   # 4× más rápido → +2 por época
    assert _bits(rapida) == [10] * 4 + [12] * 4 + [14] * 4
    assert bc.expected_difficulty(rapida) == 16
    lenta = _cadena_sintetica(bc, [20] * 12)     # el doble de lento → -1 por época
    assert _bits(lenta) == [10] * 4 + [9] * 4 + [8] * 4
    estable = _cadena_sintetica(bc, [10] * 12)
    assert _bits(estable) == [10] * 12
    assert bc.expected_difficulty(estable) == 10


def test_reajuste_acotado_a_min_y_max(tmp_path):
    bc = Blockchain("n", str(tmp_path / "c"), initial_difficulty=3, min_difficulty=2,
                    max_difficulty=5, difficulty_window=3, target_block_time=10)
    assert _bits(_cadena_sintetica(bc, [0.1] * 9)) == [3] * 3 + [5] * 6
    assert _bits(_cadena_sintetica(bc, [1000] * 9)) == [3] * 3 + [2] * 6


# ── Trabajo acumulado ────────────────────────────────────────────────────────

_REGLAS = dict(initial_difficulty=4, min_difficulty=1, max_difficulty=10,
               target_block_time=10.0, difficulty_window=2)


def _minar(bc, n, espaciado):
    base = time.time() - 1000
    for i in range(n):
        cand = bc.create_candidate_block([])
        cand.header.timestamp = max(base + (i + 1) * espaciado,
                                    bc.last_block.header.timestamp + 0.001)
        res = ProofOfWork().mine(cand, timeout=60.0, difficulty=cand.header.difficulty)
        ok, motivo = bc.add_block(res.block)
        assert ok, motivo


def test_gana_la_cadena_corta_con_mas_suma_de_2_a_los_bits(tmp_path):
    pesada = Blockchain("p", str(tmp_path / "p"), **_REGLAS)
    liviana = Blockchain("l", str(tmp_path / "l"), **_REGLAS)
    _minar(pesada, 4, 0.01)     # bits 4,4 y luego +2 → 6,6
    _minar(liviana, 6, 100.0)   # bits 4,4 y luego -2 → 2,2, luego -2 → 1,1 (mínimo)
    assert _bits(pesada.chain) == [4, 4, 6, 6]
    assert _bits(liviana.chain) == [4, 4, 2, 2, 1, 1]
    assert pesada.total_work == 1 + 16 + 16 + 64 + 64
    assert liviana.total_work == 1 + 16 + 16 + 4 + 4 + 2 + 2
    assert isinstance(pesada.total_work, int)

    ok, motivo = pesada.replace_chain([b.to_dict() for b in liviana.chain])
    assert not ok and "trabajo" in motivo
    ok, motivo = liviana.replace_chain([b.to_dict() for b in pesada.chain])
    assert ok, motivo
    assert liviana.height == 4 and liviana.last_block.hash == pesada.last_block.hash


# ── Determinismo ─────────────────────────────────────────────────────────────

def test_regla_de_dificultad_solo_con_enteros():
    """Sin floats, sin división real y sin reloj/azar en la regla de bits y de trabajo."""
    prohibidos = {"time", "random", "uuid", "datetime", "secrets", "os", "math", "float"}
    funciones = [retarget_step, _ms, block_mod.target_for_bits, block_mod.hash_meets_bits,
                 block_mod.work_for_bits, Blockchain.expected_difficulty,
                 Blockchain.block_work, Blockchain.cumulative_work]
    for f in funciones:
        arbol = ast.parse(textwrap.dedent(inspect.getsource(f)))
        for nodo in ast.walk(arbol):
            if isinstance(nodo, ast.Name):
                assert nodo.id not in prohibidos, (f.__name__, nodo.id)
            elif isinstance(nodo, ast.Constant):
                assert not isinstance(nodo.value, float), (f.__name__, nodo.value)
            elif isinstance(nodo, (ast.BinOp, ast.AugAssign)):
                assert not isinstance(nodo.op, (ast.Div, ast.Pow)), (f.__name__, ast.dump(nodo))
