"""Pruebas de scripts/preparar_despliegue_rpi.py (P1-10): los paquetes 2 Pi x 2 réplicas cargan."""
import json
import sys
from pathlib import Path

import pytest
from dotenv import dotenv_values

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import preparar_despliegue_rpi as pd  # noqa: E402
from config import build_settings  # noqa: E402


def _settings(env: Path):
    valores = {k.lower(): v for k, v in dotenv_values(env).items()}
    return build_settings(False, **valores)


@pytest.fixture
def paquetes(tmp_path):
    destino = tmp_path / "proyecto_pi"
    r = pd.preparar(tmp_path / "salida", "10.0.0.1", "10.0.0.2", destino.as_posix(),
                    admin_key="clave-de-prueba")
    return tmp_path / "salida", destino, r


def test_cada_pi_recibe_solo_lo_suyo(paquetes):
    salida, _, r = paquetes
    assert r["urls"] == ["http://10.0.0.1:8000", "http://10.0.0.1:8010",
                         "http://10.0.0.2:8000", "http://10.0.0.2:8010"]
    nombres = {p.relative_to(salida).as_posix() for p in salida.rglob("*") if p.is_file()}
    assert "ca/ca.key" in nombres                       # solo en la máquina del administrador
    for pi, nodos in (("pi1", ("node_1", "node_2")), ("pi2", ("node_3", "node_4"))):
        propios = {n for n in nombres if n.startswith(pi + "/")}
        assert not any(n.endswith("ca.key") for n in propios)
        for nodo in nodos:
            assert {f"{pi}/nodes/{nodo}.env", f"{pi}/keys/pbft_{nodo}.json",
                    f"{pi}/tls/{nodo}.crt", f"{pi}/tls/{nodo}.key"} <= propios
        ajenos = {"node_1", "node_2", "node_3", "node_4"} - set(nodos)
        assert not any(a in n for n in propios for a in ajenos if "pbft_replicas" not in n)
    assert (salida / "pi1/pbft_replicas.json").read_bytes() == \
        (salida / "pi2/pbft_replicas.json").read_bytes()


def test_las_llaves_privadas_no_van_en_la_lista_publica(paquetes):
    salida, _, _ = paquetes
    lista = json.loads((salida / "pi1/pbft_replicas.json").read_text(encoding="utf-8"))
    assert [r["id"] for r in lista["replicas"]] == ["node_1", "node_2", "node_3", "node_4"]
    assert [r["address"] for r in lista["replicas"]] == [
        "10.0.0.1:8001", "10.0.0.1:8011", "10.0.0.2:8001", "10.0.0.2:8011"]
    assert "private" not in json.dumps(lista)


def test_env_sin_crlf_y_valido_para_config(paquetes):
    salida, destino, _ = paquetes
    for pi, nodo, api, p2p in (("pi1", "node_2", 8010, 8011), ("pi2", "node_3", 8000, 8001)):
        ruta = salida / pi / "nodes" / f"{nodo}.env"
        assert b"\r" not in ruta.read_bytes()
        s = _settings(ruta)
        assert (s.node_id, s.api_port, s.node_port) == (nodo, api, p2p)
        assert s.consensus == "pbft" and s.p2p_tls == "on" and s.admin_api_key == "clave-de-prueba"
        assert s.data_dir == f"{destino.as_posix()}/data/{nodo}"
        assert s.pbft_key_file == f"{destino.as_posix()}/keys/pbft_{nodo}.json"
        assert s.node_advertise_host == ("10.0.0.1" if pi == "pi1" else "10.0.0.2")


def test_las_cuatro_replicas_comparten_el_dominio_did_web(paquetes, tmp_path):
    """Regresión (P2-3): cada réplica tenía su PUBLIC_BASE_URL y ningún DID_WEB_DOMAIN, así que
    cada una exportaba VCs con su propio did:web y un VC de node_1 fallaba en verificar_vc.py
    contra node_3 (la otra Pi). Las 4 deben usar el MISMO dominio."""
    from blockchain.contracts import vc_export
    salida, _, _ = paquetes
    dominios = set()
    for pi, nodo, _hueco in pd.REPLICAS:
        s = _settings(salida / pi / "nodes" / f"{nodo}.env")
        dominios.add(vc_export.did_domain(s.did_web_domain, s.public_base_url))
    assert dominios == {"10.0.0.1%3A8000"}
    otro = pd.preparar(tmp_path / "otra", "10.0.0.1", "10.0.0.2", "/srv/upb",
                       admin_key="k", did_dominio="upb.edu.bo")
    s = _settings(otro["salida"] / "pi2" / "nodes" / "node_4.env")
    assert s.did_web_domain == "upb.edu.bo"


def test_una_replica_arranca_con_su_paquete(paquetes):
    """El paquete copiado a la raíz del proyecto basta para construir el nodo (PBFT + mTLS)."""
    from api.app import create_app
    salida, destino, _ = paquetes
    destino.mkdir()
    for origen in (salida / "pi1").rglob("*"):
        if origen.is_file():
            objetivo = destino / origen.relative_to(salida / "pi1")
            objetivo.parent.mkdir(parents=True, exist_ok=True)
            objetivo.write_bytes(origen.read_bytes())
    app = create_app(_settings(destino / "nodes" / "node_1.env"))
    node = app.state.node
    assert node.settings.consensus == "pbft" and node.replica_set.n == 4


def test_no_sobrescribe_una_salida_existente(paquetes, tmp_path):
    salida, destino, _ = paquetes
    with pytest.raises(SystemExit):
        pd.preparar(salida, "10.0.0.1", "10.0.0.2", destino.as_posix())


def test_desfase_de_la_segunda_pi_para_simular_en_una_maquina(tmp_path):
    r = pd.preparar(tmp_path / "s", "127.0.0.1", "127.0.0.1", "/x", api_base=9300, p2p_base=9301,
                    desfase_pi2=40)
    assert r["urls"] == ["http://127.0.0.1:9300", "http://127.0.0.1:9310",
                         "http://127.0.0.1:9340", "http://127.0.0.1:9350"]


def test_llave_de_autoridad_distinta_del_genesis_aborta(tmp_path):
    from blockchain.core.wallet import Wallet
    clave = tmp_path / "otra.json"
    Wallet.generate().export(str(clave))
    with pytest.raises(SystemExit) as e:
        pd.preparar(tmp_path / "s", "10.0.0.1", "10.0.0.2", "/x", autoridad_llave=clave)
    assert "NO es la autoridad" in str(e.value)
    assert not (tmp_path / "s").exists()


def test_llave_de_autoridad_solo_en_node_1(tmp_path, monkeypatch):
    from blockchain.core.wallet import Wallet
    clave = tmp_path / "authority.json"
    w = Wallet.generate()
    w.export(str(clave))
    monkeypatch.setattr("blockchain.core.block.GENESIS_AUTHORITY_ADDRESS", w.address)
    pd.preparar(tmp_path / "s", "10.0.0.1", "10.0.0.2", "/x", autoridad_llave=clave)
    assert (tmp_path / "s/pi1/keys/authority.json").exists()
    assert not (tmp_path / "s/pi2/keys/authority.json").exists()
    assert "AUTHORITY_KEY_FILE=/x/keys/authority.json" in \
        (tmp_path / "s/pi1/nodes/node_1.env").read_text(encoding="utf-8")
    assert "AUTHORITY_KEY_FILE" not in (tmp_path / "s/pi1/nodes/node_2.env").read_text(encoding="utf-8")


def test_la_guia_usa_solo_opciones_que_existen_en_los_scripts():
    """docs/despliegue_rpi.md: cada ``--opcion`` de una línea con ``scripts/X.py`` está en su --help."""
    import re
    import subprocess
    raiz = Path(__file__).resolve().parents[1]
    texto = (raiz / "docs" / "despliegue_rpi.md").read_text(encoding="utf-8")
    ayudas, vistos = {}, 0
    for linea in texto.splitlines():
        m = re.search(r"scripts[\\/]([a-z_]+)\.py", linea)
        if not m or "--" not in linea:
            continue
        nombre = m.group(1)
        if nombre not in ayudas:
            ayudas[nombre] = subprocess.run(
                [sys.executable, str(raiz / "scripts" / f"{nombre}.py"), "--help"],
                capture_output=True, timeout=60).stdout.decode("utf-8", "replace")
        for opcion in re.findall(r"(?<![\w-])--[a-z0-9][a-z0-9-]*", linea):
            vistos += 1
            assert opcion in ayudas[nombre], f"{nombre}.py no tiene {opcion}: {linea.strip()}"
    assert vistos >= 8 and {"preparar_despliegue_rpi", "verificar_red", "bench_rpi"} <= set(ayudas)
