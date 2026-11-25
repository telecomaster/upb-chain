"""Cobertura de `security/attacks/eclipse.py`: modelo de probabilidad por tramos, mitigaciones,
tiempos y umbral de vulnerabilidad. Cálculos puros, sin red; el último test pasa por el
endpoint `POST /security/eclipse-simulation` de una app creada con `make_app`.
"""
import pytest
from httpx import ASGITransport, AsyncClient

from security.attacks.eclipse import EclipseAttack
from tests.helpers import make_app

pytestmark = pytest.mark.unit


def _prob(max_connections, effective_attacker, network_size):
    return EclipseAttack._compute_eclipse_probability(
        max_connections=max_connections,
        effective_attacker=effective_attacker,
        network_size=network_size,
    )


# ── Tramos del modelo (honest_fraction = 0 => dilución 1.0) ──────────────────

@pytest.mark.parametrize("eff, esperado", [
    (100, 0.90),    # ratio 1.00
    (75, 0.65),     # ratio 0.75 (frontera inclusiva)
    (50, 0.40),     # ratio 0.50 (frontera inclusiva)
    (25, 0.18),     # ratio 0.25 (frontera inclusiva)
    (24, 0.132),    # ratio < 0.25 => ratio * 0.55
    (10, 0.055),    # ratio 0.10 => 0.10 * 0.55
])
def test_tramos_de_probabilidad_con_red_totalmente_atacante(eff, esperado):
    assert _prob(max_connections=100, effective_attacker=eff, network_size=eff) == pytest.approx(esperado)


def test_dilucion_reduce_la_probabilidad_segun_la_fraccion_honesta():
    # base 0.40 (ratio 0.5); honesta = 0.5 => dilución = 1 - 0.5 * 0.30 = 0.85
    assert _prob(max_connections=100, effective_attacker=50, network_size=100) == 0.34


def test_atacante_mayor_que_la_red_no_da_fraccion_honesta_negativa():
    # eff 20 > net 10: honesta clamped a 0 => dilución 1.0 => 0.90
    assert _prob(max_connections=10, effective_attacker=20, network_size=10) == 0.90


@pytest.mark.parametrize("max_c, eff, net", [(32, 10, 0), (0, 10, 50), (32, 0, 50), (32, -5, 50)])
def test_probabilidad_cero_con_entradas_degeneradas(max_c, eff, net):
    assert _prob(max_c, eff, net) == 0.0


def test_probabilidad_acotada_entre_cero_y_uno():
    for eff in (0.5, 1, 7.3, 31, 32, 500):
        p = _prob(max_connections=32, effective_attacker=eff, network_size=50)
        assert 0.0 <= p <= 1.0


# ── simulate(): métricas base ────────────────────────────────────────────────

def test_simulacion_por_defecto_no_es_vulnerable():
    r = EclipseAttack().simulate()
    m = r.metrics
    assert r.attack_type == "Eclipse Attack"
    assert m["attacker_control_ratio"] == 0.3125           # 10 / 32
    assert m["eclipse_probability"] == 0.1368              # 0.18 * (1 - 0.8 * 0.30)
    assert m["vulnerable"] is False and r.success is False
    assert m["mitigations_active"] == []
    assert m["time_to_eclipse_s"] == 480.0                 # 32 * 3.0 * (50 / 10)
    assert (m["max_connections"], m["attacker_nodes"], m["network_size"]) == (32, 10, 50)
    assert r.duration_s >= 0


def test_atacante_con_todos_los_slots_es_vulnerable():
    r = EclipseAttack().simulate(max_connections=32, attacker_nodes=32, network_size=50)
    assert r.metrics["eclipse_probability"] == 0.8028      # 0.90 * (1 - 0.36 * 0.30)
    assert r.metrics["vulnerable"] is True and r.success is True


def test_umbral_de_vulnerabilidad_es_estricto(monkeypatch):
    """`vulnerable` exige probabilidad ESTRICTAMENTE mayor que 0.30."""
    for valor, esperado in [(0.30, False), (0.3001, True)]:
        monkeypatch.setattr(EclipseAttack, "_compute_eclipse_probability",
                            staticmethod(lambda **kw: valor))
        r = EclipseAttack().simulate()
        assert r.metrics["vulnerable"] is esperado, valor


def test_tiempo_hasta_eclipse_redondeado_a_una_cifra():
    r = EclipseAttack().simulate(max_connections=32, attacker_nodes=7, network_size=50)
    assert r.metrics["time_to_eclipse_s"] == 685.7        # 32 * 3 * 50 / 7 = 685.71...


def test_sin_atacantes_no_hay_probabilidad_y_el_tiempo_usa_un_nodo():
    r = EclipseAttack().simulate(attacker_nodes=0)
    assert r.metrics["attacker_control_ratio"] == 0.0
    assert r.metrics["eclipse_probability"] == 0.0
    assert r.metrics["vulnerable"] is False
    assert r.metrics["time_to_eclipse_s"] == 4800.0       # 32 * 3 * (50 / max(0, 1))


def test_sin_conexiones_maximas_el_ratio_usa_uno_y_la_probabilidad_es_cero():
    r = EclipseAttack().simulate(max_connections=0, attacker_nodes=10)
    assert r.metrics["attacker_control_ratio"] == 10.0    # 10 / max(0, 1)
    assert r.metrics["eclipse_probability"] == 0.0
    assert r.metrics["time_to_eclipse_s"] == 0.0


def test_descripcion_y_recomendaciones_del_resultado():
    r = EclipseAttack().simulate()
    assert "10/50" in r.description and "32 conexiones" in r.description
    assert "['ninguna']" in r.description                  # sin mitigaciones
    assert len(r.recommendations) == 6
    assert any("/24" in rec for rec in r.recommendations)


# ── Mitigaciones ─────────────────────────────────────────────────────────────

def test_limite_por_ip_recorta_la_capacidad_al_cincuenta_por_ciento():
    sin = EclipseAttack().simulate(attacker_nodes=30, max_connections=32, network_size=50)
    con = EclipseAttack().simulate(attacker_nodes=30, max_connections=32, network_size=50,
                                   has_connection_limit_per_ip=True)
    assert sin.metrics["eclipse_probability"] == 0.572     # ratio 0.94 => 0.65 * 0.88
    # capacidad efectiva min(30, 16) = 16 => ratio 0.5 => 0.40 * (1 - 0.68 * 0.3)
    assert con.metrics["eclipse_probability"] == pytest.approx(0.3184)
    assert con.metrics["mitigations_active"] == ["Límite de conexiones por IP/subred (/24)"]


def test_diversidad_de_subredes_reduce_la_capacidad_por_ceil_entre_tres():
    r = EclipseAttack().simulate(attacker_nodes=30, max_connections=32, network_size=50,
                                 has_peer_diversity=True)
    # subredes = ceil(30 / 3) = 10 => ratio diversidad 10/32 => capacidad 9.375
    assert r.metrics["eclipse_probability"] == pytest.approx(0.1361, abs=1e-4)
    assert r.metrics["mitigations_active"] == ["Diversidad de subredes requerida"]


def test_ambas_mitigaciones_se_acumulan_y_bajan_la_probabilidad():
    base = EclipseAttack().simulate(attacker_nodes=30, max_connections=32, network_size=50)
    limite = EclipseAttack().simulate(attacker_nodes=30, max_connections=32, network_size=50,
                                      has_connection_limit_per_ip=True)
    diversidad = EclipseAttack().simulate(attacker_nodes=30, max_connections=32, network_size=50,
                                          has_peer_diversity=True)
    ambas = EclipseAttack().simulate(attacker_nodes=30, max_connections=32, network_size=50,
                                     has_connection_limit_per_ip=True, has_peer_diversity=True)
    assert ambas.metrics["eclipse_probability"] == pytest.approx(0.0627, abs=1e-4)
    assert ambas.metrics["mitigations_active"] == [
        "Límite de conexiones por IP/subred (/24)", "Diversidad de subredes requerida"]
    assert (ambas.metrics["eclipse_probability"] < diversidad.metrics["eclipse_probability"]
            < limite.metrics["eclipse_probability"] < base.metrics["eclipse_probability"])


def test_mitigaciones_no_cambian_el_ratio_crudo_de_control():
    r = EclipseAttack().simulate(attacker_nodes=30, max_connections=32,
                                 has_connection_limit_per_ip=True, has_peer_diversity=True)
    assert r.metrics["attacker_control_ratio"] == round(30 / 32, 4)


# ── Endpoint (seam: app creada con make_app) ─────────────────────────────────

@pytest.mark.asyncio
async def test_endpoint_eclipse_usa_los_parametros_y_valida_limites(tmp_path):
    app = make_app(tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        ok = await ac.post("/security/eclipse-simulation",
                           params={"max_connections": 32, "attacker_nodes": 32, "network_size": 50})
        assert ok.status_code == 200
        cuerpo = ok.json()
        assert cuerpo["metrics"]["eclipse_probability"] == 0.8028
        assert cuerpo["metrics"]["vulnerable"] is True

        fuera_de_rango = await ac.post("/security/eclipse-simulation",
                                       params={"max_connections": 0})
        assert fuera_de_rango.status_code == 422
