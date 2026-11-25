"""P2-9: ``create_app`` construye apps independientes (sin globales) y valida la configuración."""
import time

import pytest
from fastapi.testclient import TestClient

from api.app import NodeState, app as app_global
from config import ConfigError, build_settings
from tests.helpers import make_app, make_settings

pytestmark = pytest.mark.integration


def test_create_app_guarda_un_nodestate_en_app_state(tmp_path):
    app = make_app(tmp_path, "a")
    assert isinstance(app.state.node, NodeState)
    assert app.state.node.settings.node_id == "a"
    # el módulo conserva ``app`` para ``uvicorn api.app:app``
    assert app_global.state.node is not app.state.node


def test_dos_apps_en_el_mismo_proceso_son_independientes(tmp_path):
    a, b = make_app(tmp_path, "nodo_a"), make_app(tmp_path, "nodo_b")
    na, nb = a.state.node, b.state.node
    for campo in ("blockchain", "p2p", "security_monitor", "tx_rate_limiter", "mining_lock",
                  "mining_stop", "tx_anomaly_detector", "block_anomaly_detector", "pbft_node"):
        assert getattr(na, campo) is not getattr(nb, campo), campo
    with TestClient(a) as ca, TestClient(b) as cb:
        assert ca.post("/blocks/mine", json={"miner_address": "M"}).status_code == 200
        assert ca.get("/health").json()["height"] == 1
        assert ca.get("/health").json()["node_id"] == "nodo_a"
        assert cb.get("/health").json()["height"] == 0
        assert cb.get("/health").json()["node_id"] == "nodo_b"
        assert len(na.blockchain.chain) == 2 and len(nb.blockchain.chain) == 1
        assert na.p2p.port != nb.p2p.port and na.p2p.port != 0
    # los datos viven en directorios distintos
    assert (tmp_path / "nodo_a" / "chain.json").exists()
    assert (tmp_path / "nodo_b" / "chain.json").exists()


def test_dos_apps_se_conectan_y_sincronizan_en_proceso(tmp_path):
    a, b = make_app(tmp_path, "nodo_a"), make_app(tmp_path, "nodo_b")
    with TestClient(a) as ca, TestClient(b) as cb:
        for _ in range(2):
            assert ca.post("/blocks/mine", json={"miner_address": "M"}).status_code == 200
        assert cb.get("/health").json()["height"] == 0
        puerto = a.state.node.p2p.port
        r = cb.post("/network/peers", params={"host": "127.0.0.1", "port": puerto})
        assert r.status_code == 200 and r.json()["connected"] is True
        limite = time.time() + 15
        while time.time() < limite and cb.get("/health").json()["height"] < 2:
            cb.post("/network/sync")
            time.sleep(0.1)
        assert cb.get("/health").json()["height"] == 2
        assert (b.state.node.blockchain.last_block.hash
                == a.state.node.blockchain.last_block.hash)


def test_settings_por_argumento_ganan_al_entorno(tmp_path, monkeypatch):
    monkeypatch.setenv("NODE_ID", "desde_entorno")
    assert make_settings(tmp_path, "explicito").node_id == "explicito"
    assert build_settings(False).node_id == "desde_entorno"


@pytest.mark.parametrize("campo,valor", [
    ("node_port", 70000), ("api_port", -1), ("mining_difficulty", 0),
    ("tx_rate_limit", 0), ("log_level", "RUIDOSO"), ("node_id", "  "),
])
def test_settings_invalidos_dan_error_claro_en_espanol(campo, valor):
    with pytest.raises(ConfigError) as e:
        build_settings(False, **{campo: valor})
    assert campo.upper() in str(e.value) and "Configuración inválida" in str(e.value)


def test_variable_de_entorno_no_numerica_da_error_en_espanol(monkeypatch):
    monkeypatch.setenv("NODE_PORT", "abc")
    with pytest.raises(ConfigError, match="NODE_PORT: debe ser un número entero"):
        build_settings(False)


def test_settings_son_inmutables_y_peers_se_separan_por_comas(monkeypatch):
    monkeypatch.setenv("PEERS", "10.0.0.1:8001, 10.0.0.2:8001")
    s = build_settings(False)
    assert s.peers == ["10.0.0.1:8001", "10.0.0.2:8001"]
    with pytest.raises(Exception):
        s.node_port = 1
