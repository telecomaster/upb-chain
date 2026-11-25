"""Tests de P0-7: configuración de despliegue (.env, DATA_DIR, dificultad)."""
import os
import subprocess
import sys
from pathlib import Path

from blockchain.core.chain import Blockchain
from config import load_settings
from tests.helpers import mine_and_add

RAIZ = Path(__file__).resolve().parent.parent

CODIGO = (
    "import api.app as a;"
    "n = a.app.state.node;"
    "print(n.blockchain.data_dir.resolve());"
    "print(n.blockchain._calculate_difficulty());"
    "print(n.settings.node_id)"
)


def _importar_app(env_extra, cwd):
    """Importa api.app en un proceso aparte con el entorno dado."""
    env = {k: v for k, v in os.environ.items()
           if k not in ("NODE_ID", "DATA_DIR", "MINING_DIFFICULTY", "LOG_LEVEL", "PEERS")}
    env["PYTHONPATH"] = str(RAIZ)
    env["NODE_PORT"] = "0"
    env["PYTHONIOENCODING"] = "utf-8"
    env.update(env_extra)
    r = subprocess.run([sys.executable, "-c", CODIGO], cwd=cwd, env=env,
                       capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert r.returncode == 0, r.stderr
    return r.stdout.split()


def test_dos_nodos_usan_directorios_separados(tmp_path):
    a, b = tmp_path / "A", tmp_path / "B"
    _importar_app({"DATA_DIR": str(a), "NODE_ID": "node_a"}, cwd=tmp_path)
    _importar_app({"DATA_DIR": str(b), "NODE_ID": "node_b"}, cwd=tmp_path)
    assert (a / "chain.db").exists()
    assert (b / "chain.db").exists()
    assert not (tmp_path / "data").exists()  # nada cae en el directorio por defecto


def test_env_se_carga_sin_pisar_el_entorno(tmp_path):
    (tmp_path / ".env").write_text(
        f"DATA_DIR={(tmp_path / 'desde_env').as_posix()}\nMINING_DIFFICULTY=2\nNODE_ID=node_env\n",
        encoding="utf-8")
    ruta, dif, nid = _importar_app({"NODE_ID": "node_real"}, cwd=tmp_path)
    assert Path(ruta) == (tmp_path / "desde_env").resolve()
    assert dif == "2"
    assert nid == "node_real"  # el entorno ya definido gana al .env


def test_reinicio_conserva_la_cadena(tmp_path):
    d = str(tmp_path / "nodo")
    c1 = Blockchain(node_id="n", data_dir=d, initial_difficulty=1)
    ok, motivo = mine_and_add(c1)
    assert ok, motivo
    altura = c1.height
    assert altura >= 1
    assert Blockchain(node_id="n", data_dir=d, initial_difficulty=1).height == altura


def test_load_settings_valores(monkeypatch):
    monkeypatch.setenv("PEERS", "10.0.0.1:8001, 10.0.0.2:8001")
    monkeypatch.setenv("NODE_ADVERTISE_HOST", "192.168.1.5")
    monkeypatch.setenv("MINING_DIFFICULTY", "3")
    s = load_settings(load_env_file=False)
    assert s.peers == ["10.0.0.1:8001", "10.0.0.2:8001"]
    assert s.node_advertise_host == "192.168.1.5"
    assert s.mining_difficulty == 3


def test_revalidate_on_start_y_snapshot_interval_llegan_a_la_cadena(tmp_path, monkeypatch):
    """P2-4: REVALIDATE_ON_START / SNAPSHOT_INTERVAL desde el entorno hasta la Blockchain."""
    import pytest
    from config import ConfigError
    from tests.helpers import make_app

    monkeypatch.setenv("REVALIDATE_ON_START", "FULL")
    monkeypatch.setenv("SNAPSHOT_INTERVAL", "7")
    s = load_settings(load_env_file=False)
    assert (s.revalidate_on_start, s.snapshot_interval) == ("full", 7)
    bc = make_app(tmp_path, revalidate_on_start="full", snapshot_interval=7).state.node.blockchain
    assert (bc.revalidate_on_start, bc.snapshot_interval) == ("full", 7)
    monkeypatch.setenv("REVALIDATE_ON_START", "a-veces")
    with pytest.raises(ConfigError, match="REVALIDATE_ON_START"):
        load_settings(load_env_file=False)
