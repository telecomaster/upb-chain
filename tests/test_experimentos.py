"""Idea 9: el arnés reproducible de experimentos corre en modo rápido y escribe sus archivos."""
import importlib.util
import json
from pathlib import Path

import pytest

_RUTA = Path(__file__).resolve().parent.parent / "scripts" / "experiments" / "run_all.py"


def _modulo():
    spec = importlib.util.spec_from_file_location("run_all_exp", _RUTA)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_run_all_rapido_escribe_tablas_y_maquina(tmp_path):
    run_all = _modulo()
    assert run_all.main(["--rapido", "--salida", str(tmp_path)]) == 0
    datos = {p.name for p in (tmp_path / "datos").iterdir()}
    assert {"merkle_prueba.csv", "pow_curva.csv", "retarget_convergencia.csv",
            "anomalias_global.csv"} <= datos
    maq = json.loads((tmp_path / "maquina.json").read_text(encoding="utf-8"))
    assert maq["modo"] == "rapido" and maq["python"] and "carrera" not in maq["experimentos"]
    if run_all._plt() is not None:
        assert (tmp_path / "figuras" / "retarget_convergencia.png").stat().st_size > 0


def test_retarget_es_determinista_y_converge(tmp_path):
    run_all = _modulo()
    for sub in ("a", "b"):
        assert run_all.main(["--rapido", "--solo", "retarget", "--salida", str(tmp_path / sub)]) == 0
    leer = lambda s: (tmp_path / s / "datos" / "retarget_detalle.csv").read_text(encoding="utf-8")
    assert leer("a") == leer("b")
    filas = (tmp_path / "a" / "datos" / "retarget_convergencia.csv").read_text(encoding="utf-8").splitlines()
    assert len(filas) > 5


def test_solo_carrera_rapido(tmp_path):
    run_all = _modulo()
    assert run_all.main(["--rapido", "--solo", "carrera", "--salida", str(tmp_path)]) == 0
    resumen = (tmp_path / "datos" / "carrera_resumen.csv").read_text(encoding="utf-8")
    assert "pow" in resumen and "pbft" in resumen
