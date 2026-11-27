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


def test_laboratorio_ataques_sybil_pbft_con_salida_redirigida():
    # la narración lleva flechas y puntos suspensivos: antes caía con cp1252
    r = _correr("scripts/laboratorio_ataques.py", "--escenario", "sybil", "--consenso", "pbft")
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")[-300:]
    assert "Veredicto".encode("utf-8") in r.stdout


def test_setup_rpi_da_el_directorio_al_usuario_del_servicio():
    texto = (RAIZ / "scripts" / "setup_rpi.sh").read_text(encoding="utf-8")
    usuario = [l.split("=", 1)[1] for l in texto.splitlines() if l.startswith("User=")][0]
    assert f"chown -R {usuario}:{usuario}" in texto
    assert texto.index("chown -R") < texto.index("systemctl restart")


def test_scripts_sin_secuencias_de_escape_invalidas():
    import warnings
    for f in sorted((RAIZ / "scripts").rglob("*.py")):
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            compile(f.read_text(encoding="utf-8"), str(f), "exec")


def _setup_rpi() -> str:
    return (RAIZ / "scripts" / "setup_rpi.sh").read_text(encoding="utf-8")


def test_setup_rpi_no_copia_venv_ni_datos_ni_env():
    t = _setup_rpi()
    assert "cp -r ." not in t
    for excluido in ("./venv", "./.git", "./data", "./.env", "./nodes", "./.claude", "__pycache__"):
        assert f"--exclude={excluido}" in t


def test_setup_rpi_no_pisa_un_env_existente():
    t = _setup_rpi()
    assert 'if [ -f "$ENV_FILE" ]' in t
    assert t.index('if [ -f "$ENV_FILE" ]') < t.index('cat > "$ENV_FILE"')


def test_setup_rpi_dos_replicas_en_la_misma_pi_no_se_pisan():
    """P0-7: 2 réplicas por Pi = 2 unidades systemd con env y DATA_DIR propios."""
    t = _setup_rpi()
    assert "/etc/systemd/system/$SERVICIO.service" in t and 'SERVICIO="upbchain-$NODE_ID"' in t
    assert "upbchain.service" not in t           # nombre fijo: la 2.ª réplica sobrescribiría la 1.ª
    assert 'ENV_FILE="$PROJECT_DIR/nodes/$NODE_ID.env"' in t
    assert "EnvironmentFile=$ENV_FILE" in t
    assert "DATA_DIR=$PROJECT_DIR/data/$NODE_ID" in t
    assert 'ufw allow "$API_PORT/tcp"' in t and 'ufw allow "$P2P_PORT/tcp"' in t
    assert "SKIP_APT" in t


def test_setup_rpi_no_asume_el_usuario_pi_ni_copia_sobre_si_mismo():
    t = _setup_rpi()
    assert "/home/pi" not in t and "pi:pi" not in t and "User=pi" not in t
    assert "SUDO_USER" in t and "User=$USUARIO" in t
    assert "pwd -P" in t                          # clon directo en el destino: no copiar
    assert "After=network-online.target" in t


def test_setup_rpi_sintaxis_bash_valida():
    import shutil
    import pytest
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("sin bash")
    ruta = RAIZ / "scripts" / "setup_rpi.sh"
    r = subprocess.run([bash, "-n", str(ruta)], capture_output=True, timeout=30)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")
    assert b"\r" not in ruta.read_bytes()        # CRLF rompe bash en la Pi


def test_setup_rpi_espera_salud_con_reintentos():
    t = _setup_rpi()
    assert "sleep 3" not in t
    assert "seq 1 30" in t and "60 s" in t
