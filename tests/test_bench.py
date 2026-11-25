"""Pruebas del benchmark y de la semilla de bloques (P1-10), en modo rápido."""
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import bench_rpi  # noqa: E402
import semilla_bloques  # noqa: E402
from blockchain.core.wallet import Wallet  # noqa: E402
from tests.helpers import make_app  # noqa: E402


def test_bench_rapido_estructura_y_archivos(tmp_path):
    r = bench_rpi.ejecutar("rapido")
    assert r["hash_rate"]["hashes_por_s"] > 0
    assert [c["bits"] for c in r["curva"]] == bench_rpi.PERFILES["rapido"]["bits"]
    assert all(c["bloques"] > 0 and c["intentos_esperados"] == 1 << c["bits"]
               for c in r["curva"])
    assert r["tps"]["txs"] == bench_rpi.PERFILES["rapido"]["txs"]
    assert r["tps"]["tps_total"] > 0
    for clave in ("anfitrion", "plataforma", "cpu", "python", "fecha_utc"):
        assert r["host"][clave]
    md, cs = bench_rpi.guardar(r, tmp_path)
    texto = md.read_text(encoding="utf-8")
    for titulo in ("## Equipo", "## Hash rate", "## Curva", "## TPS", "## Temperatura", "## RAM"):
        assert titulo in texto
    with open(cs, encoding="utf-8", newline="") as f:
        filas = list(csv.reader(f))
    assert filas[0] == ["seccion", "clave", "valor"]
    assert any(f[0] == "tps" and f[1] == "tps_total" for f in filas)


def test_temperatura_y_ram_no_fallan():
    t = bench_rpi.leer_temperatura()
    assert t is None or t > 0
    assert set(bench_rpi.leer_ram()) == {"total_mib", "disponible_mib", "proceso_mib",
                                         "proceso_pico_mib"}


def test_semilla_50_bloques_y_un_nodo_nuevo_la_acepta(tmp_path):
    autoridad = Wallet.generate()
    r = semilla_bloques.sembrar(tmp_path / "semilla", bloques=50, autoridad=autoridad, bits=2)
    assert r["bloques"] >= 50 and r["valida"]
    assert r["txs"]["CREDENTIAL_ISSUE"] > 0 and r["txs"]["TOKEN_TRANSFER"] > 0
    # Un nodo nuevo (create_app) sobre el mismo DATA_DIR revalida la cadena entera.
    app = make_app(tmp_path, "semilla", autoridad=autoridad, revalidate_on_start="full",
                   mining_difficulty=2)
    bc = app.state.node.blockchain
    assert bc.height >= 50
    assert bc.validate_chain()[0]


def test_bench_rapido_pbft_estructura_y_selector(tmp_path):
    r = bench_rpi.ejecutar("rapido", consenso="pbft")
    assert "tps" not in r and "hash_rate" not in r     # solo PBFT
    t = r["tps_pbft"]
    assert t["txs"] == bench_rpi.PERFILES["rapido"]["txs_pbft"]
    assert (t["replicas"], t["f"]) == (4, 1)
    assert t["bloques"] >= 2                            # bloques de hasta 50 TX
    assert t["tps"] > 0 and t["tps_consenso"] > 0
    assert 0 < t["latencia_commit_mediana_ms"] <= t["latencia_commit_p95_ms"]
    md, cs = bench_rpi.guardar(r, tmp_path)
    assert "## TPS con PBFT" in md.read_text(encoding="utf-8")
    with open(cs, encoding="utf-8", newline="") as f:
        assert any(fila[0] == "tps_pbft" and fila[1] == "tps" for fila in csv.reader(f))


def test_bench_consenso_invalido():
    import pytest
    with pytest.raises(ValueError):
        bench_rpi.ejecutar("rapido", consenso="raft")
