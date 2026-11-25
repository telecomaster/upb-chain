"""Cobertura de `blockchain/consensus/proof_of_work.py`.

Dificultades bajas (1-14 bits) y bloques con timestamp fijo: el resultado del minado es
determinista. Los casos de timeout usan un reloj falso (sólo en el módulo bajo prueba)
para no depender del hardware.
"""
import pytest

from blockchain.consensus import proof_of_work as pow_mod
from blockchain.consensus.proof_of_work import (ProofOfWork, difficulty_to_expected_time)
from blockchain.core.block import Block, BlockHeader, hash_meets_bits

pytestmark = pytest.mark.unit

TIMESTAMP = 1_700_000_000.0


def _bloque(difficulty=1):
    """Candidato determinista (timestamp fijo, sin transacciones)."""
    previo = Block.create_genesis("cobertura-pow").hash
    return Block(
        header=BlockHeader(
            index=1,
            timestamp=TIMESTAMP,
            previous_hash=previo,
            merkle_root=Block.compute_merkle_root([]),
            difficulty=difficulty,
        ),
        transactions=[],
    )


class _RelojFalso:
    """Sustituye al módulo `time` del motor: `perf_counter()` avanza `paso` por llamada."""

    def __init__(self, paso=0.0):
        self.t = 0.0
        self.paso = paso

    def perf_counter(self):
        self.t += self.paso
        return self.t


@pytest.fixture
def reloj(monkeypatch):
    rj = _RelojFalso(paso=0.0)
    monkeypatch.setattr(pow_mod, "time", rj)
    return rj


# ── mine(): éxito, estadísticas y dificultad ─────────────────────────────────

def test_mine_devuelve_hash_que_cumple_los_bits_y_coherente():
    resultado = ProofOfWork(difficulty=6).mine(_bloque(), timeout=30.0)
    assert resultado is not None
    assert hash_meets_bits(resultado.hash, 6)
    assert resultado.block.hash == resultado.hash
    assert resultado.block.header.nonce == resultado.nonce
    assert resultado.attempts == resultado.nonce + 1
    assert resultado.block.header.difficulty == 6


def test_mine_es_determinista_para_el_mismo_bloque():
    a = ProofOfWork(difficulty=8).mine(_bloque(), timeout=30.0)
    b = ProofOfWork(difficulty=8).mine(_bloque(), timeout=30.0)
    assert (a.nonce, a.hash) == (b.nonce, b.hash)


def test_dificultad_explicita_sobrescribe_la_del_constructor_sin_mutar_el_motor():
    motor = ProofOfWork(difficulty=1)
    resultado = motor.mine(_bloque(), difficulty=3, timeout=30.0)
    assert resultado.block.header.difficulty == 3
    assert motor.last_difficulty == 3
    assert motor.difficulty == 1  # el estado del motor no cambia
    assert hash_meets_bits(resultado.hash, 3)


def test_sin_dificultad_explicita_usa_la_del_constructor():
    motor = ProofOfWork(difficulty=4)
    resultado = motor.mine(_bloque(), timeout=30.0)
    assert resultado.block.header.difficulty == 4
    assert motor.last_difficulty == 4


def test_limite_de_bits_frontera_cumple_y_no_cumple():
    """Con 0 bits cualquier hash sirve (nonce 0); con 1 bit el hash debe empezar en '0'."""
    resultado = ProofOfWork(difficulty=0).mine(_bloque(), timeout=30.0)
    assert resultado.nonce == 0
    r1 = ProofOfWork(difficulty=1).mine(_bloque(), timeout=30.0)
    assert int(r1.hash, 16) < 2 ** 255
    assert not hash_meets_bits(format(2 ** 255, "064x"), 1)


def test_max_nonce_agotado_devuelve_none():
    # 30 bits: la probabilidad de hallar solución en 100 nonces es despreciable (y fija).
    assert ProofOfWork(difficulty=30).mine(_bloque(), max_nonce=100, timeout=None) is None


def test_max_nonce_cero_no_intenta_ninguno():
    assert ProofOfWork(difficulty=0).mine(_bloque(), max_nonce=0, timeout=None) is None


def test_timeout_con_reloj_que_avanza_aborta(reloj):
    reloj.paso = 1.0  # cada consulta al reloj suma 1 s
    assert ProofOfWork(difficulty=30).mine(_bloque(), timeout=0.5) is None


def test_timeout_none_no_aborta_aunque_el_reloj_avance(reloj):
    reloj.paso = 1e6
    resultado = ProofOfWork(difficulty=2).mine(_bloque(), timeout=None)
    assert resultado is not None and hash_meets_bits(resultado.hash, 2)


def test_hash_rate_cero_cuando_el_tiempo_transcurrido_es_cero(reloj):
    """Rama `elapsed > 0` falsa: reloj congelado, hash_rate se reporta como 0."""
    resultado = ProofOfWork(difficulty=2).mine(_bloque(), timeout=10.0)
    assert resultado.time_elapsed == 0.0
    assert resultado.hash_rate == 0


# ── mine(): stop_event y on_progress ─────────────────────────────────────────

def test_stop_event_ya_activo_aborta_sin_resultado():
    import threading
    evento = threading.Event()
    evento.set()
    motor = ProofOfWork(difficulty=20)
    assert motor.mine(_bloque(), stop_event=evento, timeout=None) is None
    assert motor.get_mining_stats() == {}  # no se registró ningún bloque


def test_stop_event_activado_por_progreso_aborta_en_el_siguiente_control():
    """El control de stop_event es cada 256 nonces; el progreso llega a 4096. Con 24 bits
    el bloque fijo no se resuelve en 4096 intentos, así que el minado debe abortar."""
    import threading
    evento = threading.Event()
    llamadas = []

    def progreso(nonce, _segundos):
        llamadas.append(nonce)
        evento.set()

    assert ProofOfWork(difficulty=24).mine(
        _bloque(), stop_event=evento, on_progress=progreso, timeout=None) is None
    assert llamadas == [4096]


def test_on_progress_no_altera_el_resultado_y_se_invoca_cada_4096():
    sin_callback = ProofOfWork(difficulty=14).mine(_bloque(), timeout=60.0)
    assert sin_callback.nonce > 4096, "el bloque fijo debe requerir más de un tramo de 4096"
    llamadas = []
    con_callback = ProofOfWork(difficulty=14).mine(
        _bloque(), timeout=60.0, on_progress=lambda n, s: llamadas.append(n))
    assert (con_callback.nonce, con_callback.hash) == (sin_callback.nonce, sin_callback.hash)
    assert llamadas == list(range(4096, sin_callback.nonce + 1, 4096))
    assert all(n % 4096 == 0 and n > 0 for n in llamadas)


# ── mine_async_friendly() ────────────────────────────────────────────────────

def test_mine_async_friendly_notifica_progreso_y_cierre_con_el_nonce_hallado():
    llamadas = []
    resultado = ProofOfWork(difficulty=14).mine_async_friendly(
        _bloque(), on_progress=lambda n, s: llamadas.append(n), timeout=60.0,
        progress_interval=4096)
    assert resultado is not None and hash_meets_bits(resultado.hash, 14)
    assert llamadas[-1] == resultado.nonce          # el último aviso es el del hallazgo
    intermedios = llamadas[:-1]
    assert all(n % 4096 == 0 and n > 0 for n in intermedios)
    assert intermedios == list(range(4096, resultado.nonce, 4096))


def test_mine_async_friendly_fija_la_dificultad_del_motor_no_otra():
    bloque = _bloque(difficulty=99)
    resultado = ProofOfWork(difficulty=2).mine_async_friendly(
        bloque, on_progress=lambda n, s: None, timeout=30.0)
    assert resultado.block.header.difficulty == 2


def test_mine_async_friendly_timeout_devuelve_none(reloj):
    reloj.paso = 1.0
    assert ProofOfWork(difficulty=30).mine_async_friendly(
        _bloque(), on_progress=lambda n, s: None, timeout=0.5) is None


def test_mine_async_friendly_agota_max_nonce_sin_solucion():
    assert ProofOfWork(difficulty=30).mine_async_friendly(
        _bloque(), on_progress=lambda n, s: None, max_nonce=50, timeout=None) is None


# ── validate_proof() ─────────────────────────────────────────────────────────

def test_validate_proof_acepta_bloque_minado():
    motor = ProofOfWork(difficulty=5)
    resultado = motor.mine(_bloque(), timeout=30.0)
    assert motor.validate_proof(resultado.block)


def test_validate_proof_rechaza_nonce_alterado_sin_recalcular_hash():
    motor = ProofOfWork(difficulty=5)
    bloque = motor.mine(_bloque(), timeout=30.0).block
    bloque.header.nonce += 1
    assert not motor.validate_proof(bloque)


def test_validate_proof_rechaza_hash_recalculado_que_no_cumple_los_bits():
    """Hash coherente con el contenido, pero sin los bits exigidos por la cabecera."""
    motor = ProofOfWork(difficulty=1)
    bloque = motor.mine(_bloque(), timeout=30.0).block
    bloque.header.difficulty = 60
    bloque.hash = bloque.compute_hash()
    assert bloque.hash == bloque.compute_hash()
    assert not motor.validate_proof(bloque)


# ── estadísticas ─────────────────────────────────────────────────────────────

def test_get_avg_hash_rate_cero_sin_minados():
    assert ProofOfWork(difficulty=2).get_avg_hash_rate() == 0.0


def test_get_mining_stats_agrega_dos_minados():
    motor = ProofOfWork(difficulty=2)
    r1 = motor.mine(_bloque(), timeout=30.0)
    r2 = motor.mine(_bloque(), difficulty=4, timeout=30.0)
    stats = motor.get_mining_stats()
    assert stats["blocks_mined"] == 2
    assert stats["last_difficulty_bits"] == 4
    assert stats["min_time_s"] <= stats["avg_time_s"] <= stats["max_time_s"]
    assert stats["avg_hash_rate"] == pytest.approx(
        (r1.hash_rate + r2.hash_rate) / 2)
    assert motor.get_avg_hash_rate() == pytest.approx(stats["avg_hash_rate"])


# ── difficulty_to_expected_time() ────────────────────────────────────────────

def test_tiempo_esperado_ejemplo_del_docstring():
    assert difficulty_to_expected_time(16, 65_536) == pytest.approx(1.0)


def test_tiempo_esperado_se_duplica_por_cada_bit_adicional():
    t10 = difficulty_to_expected_time(10, 1_000)
    t11 = difficulty_to_expected_time(11, 1_000)
    assert t11 == pytest.approx(2 * t10)


@pytest.mark.parametrize("tasa", [0, -5.0])
def test_tiempo_esperado_infinito_si_la_tasa_no_es_positiva(tasa):
    assert difficulty_to_expected_time(16, tasa) == float("inf")


def test_tiempo_esperado_con_cero_bits_es_un_intento():
    assert difficulty_to_expected_time(0, 4.0) == pytest.approx(0.25)
