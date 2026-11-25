"""
P0-8: integración multinodo a través de la API HTTP.

Levanta nodos reales (subprocesos uvicorn con P2P propio) y los maneja solo por
HTTP. Cubre: sincronización al unirse, propagación de bloques, partición y
reunión, y credenciales emitidas en A verificadas en B.
"""
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from blockchain.core.wallet import Wallet

pytestmark = pytest.mark.integration

RAIZ = Path(__file__).resolve().parent.parent
LANZADOR = RAIZ / "tests" / "_nodo_prueba.py"
TIMEOUT = 20.0


def _puerto_libre() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _esperar(cond, descripcion, timeout=TIMEOUT):
    limite = time.time() + timeout
    ultimo = None
    while time.time() < limite:
        try:
            ultimo = cond()
            if ultimo:
                return ultimo
        except httpx.HTTPError:
            pass
        time.sleep(0.15)
    raise AssertionError(f"Timeout esperando: {descripcion} (último: {ultimo})")


class Nodo:
    def __init__(self, nombre, tmp, autoridad, peers=()):
        self.nombre = nombre
        self.api_port = _puerto_libre()
        self.p2p_port = _puerto_libre()
        self.data_dir = tmp / f"data_{nombre}"
        self.log = tmp / f"{nombre}.log"
        self.peers = list(peers)
        self.autoridad = autoridad
        self.proc = None
        self._log_f = None
        self.http = httpx.Client(base_url=f"http://127.0.0.1:{self.api_port}", timeout=30.0)

    @property
    def p2p_addr(self):
        return f"127.0.0.1:{self.p2p_port}"

    def start(self):
        env = {**os.environ,
               "NODE_ID": self.nombre, "DATA_DIR": str(self.data_dir),
               "API_PORT": str(self.api_port), "NODE_PORT": str(self.p2p_port),
               "NODE_HOST": "127.0.0.1", "NODE_ADVERTISE_HOST": "127.0.0.1",
               "PEERS": ",".join(self.peers), "MINING_DIFFICULTY": "1",
               "AUTHORITY_KEY_FILE": str(self.autoridad["archivo"]),
               "TEST_AUTHORITY_ADDRESS": self.autoridad["direccion"],
               "LOG_LEVEL": "INFO", "PYTHONUTF8": "1"}
        self._log_f = open(self.log, "ab")
        self.proc = subprocess.Popen([sys.executable, str(LANZADOR)], cwd=RAIZ, env=env,
                                     stdout=self._log_f, stderr=subprocess.STDOUT)
        _esperar(lambda: self.http.get("/health").status_code == 200, f"{self.nombre} arriba")

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(10)
        if self._log_f:
            self._log_f.close()
            self._log_f = None
        self.proc = None

    def height(self):
        return self.http.get("/health").json()["height"]

    def estado(self):
        """(altura, hash de la punta)."""
        h = self.height()
        b = self.http.get(f"/blocks/{h}").json()
        return h, b.get("hash") or b["header"].get("hash")

    def mine(self, n=1):
        for _ in range(n):
            r = self.http.post("/blocks/mine", json={"miner_address": "UPBMINER"})
            assert r.status_code == 200, r.text


@pytest.fixture
def red(tmp_path):
    autoridad_w = Wallet.generate()
    archivo = tmp_path / "authority.json"
    autoridad_w.export(str(archivo))
    autoridad = {"archivo": archivo, "direccion": autoridad_w.address}
    nodos = []

    def crear(nombre, peers=()):
        n = Nodo(nombre, tmp_path, autoridad, peers)
        nodos.append(n)
        return n

    yield crear
    for n in nodos:
        n.stop()
        n.http.close()
        if n.log.exists():  # pytest solo muestra esto si el test falla
            print(f"\n--- log {n.nombre} ---\n"
                  + n.log.read_text(encoding="utf-8", errors="replace")[-3000:])


def test_union_propagacion_particion_y_credenciales(red):
    # 1. A mina 2 bloques; B arranca con PEERS=A y converge a la misma punta.
    a = red("node_a")
    a.start()
    a.mine(2)
    assert a.height() == 2
    b = red("node_b", peers=[a.p2p_addr])
    b.start()
    _esperar(lambda: b.estado() == a.estado(), "B alcanza la punta de A")

    # 2. Minar en B aparece en A.
    b.mine(1)
    _esperar(lambda: a.height() == 3 and a.estado() == b.estado(), "bloque de B visible en A")

    # 3. Partición: B cae, A mina 2, B vuelve con el mismo DATA_DIR.
    b.stop()
    a.mine(2)
    b.start()
    assert b.height() >= 3, "B debe conservar su cadena persistida al reiniciar"
    _esperar(lambda: b.height() == 5 and b.estado() == a.estado(),
             "B se pone al día tras la partición")

    # 4. Credenciales: registrar emisor, emitir en A, minar en A, verificar en B.
    emisor, estudiante = Wallet.generate(), Wallet.generate()
    r = a.http.post("/credentials/issuers",
                    json={"issuer_address": emisor.address, "institution_code": "UPB"})
    assert r.status_code == 200, r.text
    r = a.http.post("/credentials/issue", json={
        "issuer_address": emisor.address, "student_address": estudiante.address,
        "private_key_hex": emisor.private_key_hex,
        "credential_data": {"student_name": "Ana", "program": "IA", "degree": "Lic. IA",
                            "issue_date": "2026-01-01", "credential_type": "DEGREE"}})
    assert r.status_code == 200, r.text
    cid = r.json()["credential_id"]
    a.mine(1)
    _esperar(lambda: b.height() == a.height(), "B recibe el bloque con la credencial")
    v = _esperar(lambda: (lambda d: d if d["status"] == "CONFIRMED" else None)(
        b.http.get(f"/credentials/verify/{cid}").json()), "credencial CONFIRMED en B")
    assert v["valid"] is True and v["confirmations"] >= 1

    r = a.http.post("/credentials/revoke", json={
        "credential_id": cid, "revoker_address": emisor.address,
        "private_key_hex": emisor.private_key_hex, "reason": "prueba"})
    assert r.status_code == 200, r.text
    a.mine(1)
    _esperar(lambda: b.http.get(f"/credentials/verify/{cid}").json()["status"] == "REVOKED",
             "credencial REVOKED en B")
