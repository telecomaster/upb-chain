"""Pruebas de humo de los scripts de línea de comandos, tal como los usa un estudiante."""
import os
import subprocess
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent


def _correr(*args, cwd=RAIZ, **kw):
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONIOENCODING", "PYTHONUTF8")}
    return subprocess.run([sys.executable, *map(str, args)], cwd=cwd, env=env,
                          capture_output=True, timeout=60, **kw)


def test_demo_redirigido_no_falla_por_codificacion():
    r = _correr("scripts/demo.py")
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")[-500:]
    assert "Demo completado".encode("utf-8") in r.stdout


def test_crear_llave_autoridad_help_no_crea_archivo(tmp_path):
    r = _correr(RAIZ / "scripts" / "crear_llave_autoridad.py", "--help", cwd=tmp_path)
    assert r.returncode == 0
    assert not (tmp_path / "--help").exists()
    assert b"usage" in r.stdout


def test_crear_llave_autoridad_ruta(tmp_path):
    destino = tmp_path / "k" / "auth.json"
    r = _correr("scripts/crear_llave_autoridad.py", destino)
    assert r.returncode == 0 and destino.exists()


def test_upbasm_help_con_salida_redirigida():
    r = _correr("scripts/upbasm.py", "--help")
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")[-300:]


def test_upbasm_ejemplos_de_estudiantes_corren():
    for nombre in ("contador", "colecta", "acertijo"):
        r = _correr("scripts/upbasm.py", "ensamblar", f"contratos_estudiantes/{nombre}.upbasm")
        assert r.returncode == 0, nombre
    r = _correr("scripts/upbasm.py", "ejecutar", "contratos_estudiantes/contador.upbasm",
                "--args", "5")
    assert r.returncode == 0 and b"retorno: 5" in r.stdout
