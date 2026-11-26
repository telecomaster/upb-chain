"""Coherencia de la configuración de despliegue (sin Docker): .env.example, Compose,
Prometheus/Grafana, Dockerfile y CI frente a ``Settings``."""
import re
from pathlib import Path

import yaml

from config import Settings, build_settings

RAIZ = Path(__file__).resolve().parent.parent
NODOS = ["node_1", "node_2", "node_3", "node_4"]


def _yaml(ruta):
    with open(RAIZ / ruta, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _env_example():
    """Variables asignadas (no comentadas) en .env.example."""
    vars_ = {}
    with open(RAIZ / ".env.example", encoding="utf-8") as f:
        for linea in f:
            m = re.match(r"^([A-Z][A-Z0-9_]*)=(.*)$", linea.rstrip("\n"))
            if m:
                vars_[m.group(1)] = m.group(2)
    return vars_


def _compose(*archivos):
    """Servicios con ``environment`` ya fusionado (base + override)."""
    envs = {}
    for a in archivos:
        for nombre, s in _yaml(a)["services"].items():
            envs.setdefault(nombre, {}).update(s.get("environment") or {})
    return envs


def test_env_example_cubre_todas_las_variables_de_settings():
    esperadas = {n.upper() for n in Settings.model_fields}
    assert set(_env_example()) == esperadas


def test_env_example_pasa_la_validacion():
    valores = {k.lower(): v for k, v in _env_example().items()}
    s = build_settings(load_env_file=False, **valores)
    assert s.mining_difficulty == 16 and s.consensus == "pow"


def test_compose_solo_usa_variables_de_settings_y_son_validas():
    validas = {n.upper() for n in Settings.model_fields}
    for archivos in (["docker-compose.yml"], ["docker-compose.yml", "docker-compose.pbft.yml"]):
        for nombre, env in _compose(*archivos).items():
            if not nombre.startswith("node_"):
                continue
            assert set(env) <= validas, (nombre, set(env) - validas)
            valores = {k.lower(): str(v).replace("${ADMIN_API_KEY:?definir ADMIN_API_KEY}", "k")
                       for k, v in env.items()}
            s = build_settings(load_env_file=False, **valores)
            assert s.node_id == nombre and s.api_port == 8000


def test_peers_de_compose_apuntan_al_puerto_p2p_de_los_demas():
    for nombre, env in _compose("docker-compose.yml").items():
        if not nombre.startswith("node_"):
            continue
        peers = build_settings(load_env_file=False, peers=env["PEERS"]).peers
        assert sorted(p.split(":")[0] for p in peers) == sorted(set(NODOS) - {nombre})
        assert {p.split(":")[1] for p in peers} == {env["NODE_PORT"]}


def test_prometheus_raspa_los_nodos_de_compose_en_el_puerto_de_la_api():
    job = _yaml("monitoring/prometheus.yml")["scrape_configs"][0]
    assert job["metrics_path"] == "/metrics"
    envs = _compose("docker-compose.yml")
    esperados = {f"{n}:{envs[n]['API_PORT']}" for n in NODOS}
    assert set(job["static_configs"][0]["targets"]) == esperados
    assert envs["node_1"]["METRICS_PUBLIC"] == "true"  # sin llave para Prometheus


def test_grafana_monta_lo_que_aprovisiona():
    g = _yaml("docker-compose.yml")["services"]["grafana"]
    montajes = {v.split(":")[1]: v.split(":")[0] for v in g["volumes"] if v.startswith("./")}
    assert (RAIZ / montajes["/etc/grafana/provisioning"]).is_dir()
    prov = _yaml("monitoring/grafana/provisioning/dashboards/upb.yml")
    ruta = prov["providers"][0]["options"]["path"]
    assert montajes[ruta] == "./monitoring/grafana/dashboards"
    ds = _yaml("monitoring/grafana/provisioning/datasources/prometheus.yml")["datasources"][0]
    assert ds["url"] == "http://prometheus:9090"
    dash = (RAIZ / "monitoring/grafana/dashboards/upb-chain.json").read_text(encoding="utf-8")
    assert ds["uid"] in dash


def test_dockerfile_dockerignore_y_ci():
    df = (RAIZ / "Dockerfile").read_text(encoding="utf-8")
    assert "uvicorn api.app:app" in df and "--workers 1" in df and "--port ${API_PORT}" in df
    assert "USER upb" in df and "/data" in df
    ignorados = (RAIZ / ".dockerignore").read_text(encoding="utf-8").split()
    assert {"venv/", ".env", "data/", ".git/"} <= set(ignorados)
    ci = (RAIZ / ".github/workflows/tests.yml").read_text(encoding="utf-8")
    assert '"3.12"' in ci and "pip install -r requirements.txt" in ci
    assert "python -m pytest tests -q" in ci
