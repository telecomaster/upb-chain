"""Freno térmico local del minero (idea 5): controlador, bucle de PoW, config, API y bench."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import bench_rpi  # noqa: E402
from blockchain.consensus.proof_of_work import LOTE_FRENO, ProofOfWork  # noqa: E402
from blockchain.consensus.termico import FrenoTermico, ciclo_para, leer_temperatura_soc  # noqa: E402
from blockchain.core.block import Block, BlockHeader, hash_meets_bits  # noqa: E402
from config import ConfigError, build_settings  # noqa: E402
from tests.helpers import make_app  # noqa: E402


def _bloque(i=1) -> Block:
    cab = BlockHeader(index=i, timestamp=1_700_000_000.0, previous_hash="0" * 64,
                      merkle_root="0" * 64, node_id="t")
    return Block(header=cab, transactions=[])


def test_ciclo_para_curva():
    assert ciclo_para(None, 70, 80, 0.2) == 1.0
    assert ciclo_para(50, 70, 80, 0.2) == 1.0
    assert ciclo_para(70, 70, 80, 0.2) == 1.0
    assert ciclo_para(75, 70, 80, 0.2) == pytest.approx(0.6)
    assert ciclo_para(80, 70, 80, 0.2) == 0.2
    assert ciclo_para(95, 70, 80, 0.2) == 0.2


def test_lectura_de_sensor_desde_archivo(tmp_path):
    f = tmp_path / "temp"
    f.write_text("61250\n", encoding="utf-8")
    assert leer_temperatura_soc(str(f), usar_vcgencmd=False) == 61.25
    assert leer_temperatura_soc(str(tmp_path / "no_existe"), usar_vcgencmd=False) is None


def test_freno_cachea_lecturas_y_calcula_pausa():
    t = [0.0]
    lecturas = []

    def fuente():
        lecturas.append(1)
        return 75.0

    fr = FrenoTermico(70, 80, 0.2, fuente=fuente, intervalo_s=1.0, reloj=lambda: t[0])
    assert fr.pausa_para(0.1) == pytest.approx(0.1 * (1 / 0.6 - 1))
    fr.pausa_para(0.1)
    assert len(lecturas) == 1          # dentro del intervalo no relee
    t[0] = 2.0
    fr.pausa_para(0.1)
    assert len(lecturas) == 2
    assert fr.estado()["temperature_c"] == 75.0
    with pytest.raises(ValueError):
        FrenoTermico(80, 70)


def test_freno_sin_sensor_no_pausa():
    fr = FrenoTermico(fuente=lambda: None)
    assert fr.pausa_para(1.0) == 0.0
    assert fr.estado()["temperature_c"] is None


def test_pow_respeta_el_ciclo_con_reloj_y_sleep_falsos():
    t = [0.0]
    dormidas = []

    def reloj():
        t[0] += 0.01   # cada lectura del reloj avanza 10 ms
        return t[0]

    fr = FrenoTermico(70, 80, 0.2, fuente=lambda: 90.0, reloj=lambda: 0.0)
    pow_ = ProofOfWork(difficulty=14, freno=fr, dormir=dormidas.append, reloj=reloj)
    res = pow_.mine(_bloque(), timeout=None)
    assert res is not None
    assert len(dormidas) == res.nonce // LOTE_FRENO
    assert len(dormidas) >= 1
    # ciclo 0.2: pausa = 4x el trabajo medido (10 ms entre lecturas del reloj falso)
    assert all(d == pytest.approx(0.01 * 4) for d in dormidas)


def test_bloque_minado_con_freno_es_valido_y_misma_dificultad():
    dormidas = []
    fr = FrenoTermico(fuente=lambda: 90.0)
    con = ProofOfWork(difficulty=12, freno=fr, dormir=dormidas.append)
    sin = ProofOfWork(difficulty=12)
    r1 = con.mine(_bloque(), timeout=None)
    r2 = sin.mine(_bloque(), timeout=None)
    assert r1.nonce == r2.nonce and r1.hash == r2.hash       # el freno no altera el resultado
    assert r1.block.header.difficulty == 12
    assert hash_meets_bits(r1.block.hash, 12)


def test_config_termica():
    s = build_settings(False)
    assert s.thermal_throttle == "off" and (s.thermal_soft_c, s.thermal_hard_c) == (70.0, 80.0)
    s = build_settings(False, thermal_throttle="ON", thermal_soft_c=60, thermal_hard_c=75,
                       thermal_min_duty=0.5)
    assert s.thermal_throttle == "on" and s.thermal_min_duty == 0.5
    for malo in (dict(thermal_throttle="si"), dict(thermal_soft_c=80, thermal_hard_c=70),
                 dict(thermal_min_duty=0)):
        with pytest.raises(ConfigError):
            build_settings(False, **malo)


def test_health_y_metricas_con_freno_activo(tmp_path):
    from fastapi.testclient import TestClient
    app = make_app(tmp_path, thermal_throttle="on", metrics_public=True)
    node = app.state.node
    node.pow_engine.freno._fuente = lambda: 75.0
    with TestClient(app, base_url="http://127.0.0.1") as c:
        th = c.get("/health").json()["thermal"]
        assert th["temperature_c"] is None or th["temperature_c"] == 75.0
        txt = c.get("/metrics").text
        assert "upb_soc_temperature_celsius 75.0" in txt
        assert "upb_miner_duty 0.6" in txt
    assert node.blockchain._calculate_difficulty() == make_app(tmp_path, "otro").state.node \
        .blockchain._calculate_difficulty()


def test_health_sin_freno(tmp_path):
    from fastapi.testclient import TestClient
    with TestClient(make_app(tmp_path), base_url="http://127.0.0.1") as c:
        assert c.get("/health").json()["thermal"] is None


def test_bench_termico_modo_rapido(tmp_path):
    t = bench_rpi.medir_termico(0.3, bits=8, muestreo_s=0.05, fuente=lambda: 90.0)
    assert t["sin_freno"]["hash_rate_medio"] > t["con_freno"]["hash_rate_medio"] > 0 \
        or t["sin_freno"]["bloques"] >= 1
    assert t["con_freno"]["muestras"] or t["con_freno"]["bloques"] >= 0
    md, cs = bench_rpi.guardar_termico(t, tmp_path)
    assert "hipótesis" in md.read_text(encoding="utf-8")
    assert cs.read_text(encoding="utf-8").startswith("seccion,clave,valor")
