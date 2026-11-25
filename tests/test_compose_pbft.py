"""P1-1: perfil de Docker Compose para PBFT (override). Compose no se ejecuta aquí."""
import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

from blockchain.consensus.pbft import ReplicaSet
from blockchain.core.wallet import Wallet

RAIZ = Path(__file__).resolve().parent.parent
HELPER = str(RAIZ / "scripts" / "preparar_pbft_compose.py")
NODOS = ["node_1", "node_2", "node_3", "node_4"]


def _cargar(nombre):
    with open(RAIZ / nombre, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _correr(salida):
    return subprocess.run([sys.executable, HELPER, "--salida", str(salida)],
                          capture_output=True, text=True, encoding="utf-8", cwd=RAIZ,
                          env={**os.environ, "PYTHONIOENCODING": "utf-8"})


def test_helper_genera_llaves_y_lista(tmp_path):
    r = _correr(tmp_path)
    assert r.returncode == 0, r.stderr
    with open(tmp_path / "pbft_replicas.json", encoding="utf-8") as f:
        items = json.load(f)["replicas"]
    assert [i["id"] for i in items] == NODOS
    assert len({i["public_key"] for i in items}) == 4
    assert [i["address"] for i in items] == [f"{n}:8001" for n in NODOS]
    rs = ReplicaSet.from_list(items)
    assert (rs.n, rs.f) == (4, 1)
    for i in items:
        w = Wallet.load(str(tmp_path / f"pbft_{i['id']}.json"))
        assert w.public_key_hex == i["public_key"]
    # no sobrescribe llaves existentes
    assert _correr(tmp_path).returncode != 0


def test_override_referencia_las_rutas_generadas():
    base = _cargar("docker-compose.yml")
    ov = _cargar("docker-compose.pbft.yml")
    assert set(ov["services"]) == set(NODOS) <= set(base["services"])
    for n in NODOS:
        s = ov["services"][n]
        assert s["environment"]["CONSENSUS"] == "pbft"
        assert s["environment"]["PBFT_REPLICAS_FILE"] == "/pbft/replicas.json"
        assert s["environment"]["PBFT_KEY_FILE"] == "/pbft/replica.json"
        assert f"./data/pbft/pbft_{n}.json:/pbft/replica.json:ro" in s["volumes"]
        assert "./data/pbft/pbft_replicas.json:/pbft/replicas.json:ro" in s["volumes"]
