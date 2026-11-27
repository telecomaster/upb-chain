"""P1-1: el arnés de la carrera de consensos corre en ambos modos (carga mínima)."""
import importlib.util
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

_RUTA = Path(__file__).resolve().parent.parent / "scripts" / "experiments" / "carrera_consensos.py"


def _modulo():
    spec = importlib.util.spec_from_file_location("carrera_consensos", _RUTA)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("modo", ["pow", "pbft"])
def test_carrera_mide_latencia_en_ambos_modos(modo, tmp_path):
    carrera = _modulo()
    resumen, filas = carrera.correr(modo, n_tx=3, tasa=20.0, semilla=1, bits=4, limite=120,
                                     convergencia=10, conexion=90)
    assert resumen["tx_confirmadas"] == 3 and len(filas) == 3
    assert resumen["latencia_media_ms"] > 0 and resumen["tps"] > 0
    # Regresión: en PoW una bifurcación de igual trabajo al parar no converge sola; el
    # arnés mina un bloque de cierre y las 4 cadenas deben terminar iguales.
    assert resumen["cadenas_iguales"]
    if modo == "pbft":
        assert resumen["reorgs"] == 0 and not resumen["bifurcacion_al_parar"]
    carrera._escribir(tmp_path, [resumen], filas, type("A", (), {
        "tx": 3, "tasa": 20.0, "semilla": 1, "bits": 4})())
    texto = (tmp_path / "carrera_consensos.md").read_text(encoding="utf-8")
    assert "NO son mediciones en Raspberry Pi" in texto
