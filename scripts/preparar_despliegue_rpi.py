"""
Prepara en UNA máquina todo lo que necesitan 2 Raspberry Pi con 2 réplicas PBFT cada una (P1-10).

Genera, en ``--salida`` (por defecto ``data/despliegue``, que git ignora), con las funciones de
``crear_llave_replica``, ``crear_ca`` y ``emitir_cert_nodo`` (sin duplicar cripto):

    ca/ca.crt, ca/ca.key         CA privada: ca.key NO sale de esta máquina
    pi1/                         réplicas node_1 y node_2 (estructura = raíz del proyecto en la Pi)
        nodes/node_1.env  nodes/node_2.env
        keys/pbft_node_1.json  keys/pbft_node_2.json   (+ keys/authority.json si --autoridad-llave)
        pbft_replicas.json
        tls/ca.crt  tls/node_1.crt/.key  tls/node_2.crt/.key
    pi2/                         réplicas node_3 y node_4 (igual)

Cada Pi recibe SOLO sus llaves y certificados: se copia ``piN/`` a la raíz del proyecto de esa Pi
(``scp -r pi1/. usuario@IP:~/upb-chain/``). La lista de réplicas es la misma en las 4 (el orden
define el primario). Los ``.env`` usan la misma ``ADMIN_API_KEY`` (aleatoria si no se da).

Puertos: réplica 1 de cada Pi = ``--api-base``/``--p2p-base`` (8000/8001), réplica 2 = +10
(8010/8011). ``--desfase-pi2`` se suma a los puertos de la 2.ª Pi: solo para simular las dos Pi en
una sola máquina (loopback).

Uso (desde la raíz del repo)::

    venv/bin/python scripts/preparar_despliegue_rpi.py --ip-pi1 192.168.1.10 --ip-pi2 192.168.1.11 \\
        [--usuario pi] [--dir-proyecto /home/pi/upb-chain] [--autoridad-llave data/keys/authority.json]
"""
import argparse
import contextlib
import io
import secrets
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from crear_llave_replica import crear_llave_replica  # noqa: E402
from security.pki import crear_ca, emitir_cert_nodo  # noqa: E402

# (pi, nodo, hueco): la réplica "hueco" 0/1 de cada Pi; el orden define el primario (node_1).
REPLICAS = [("pi1", "node_1", 0), ("pi1", "node_2", 1), ("pi2", "node_3", 0), ("pi2", "node_4", 1)]


def _env(nodo: str, ip: str, api: int, p2p: int, d: str, admin_key: str,
         con_autoridad: bool) -> str:
    lineas = [
        f"NODE_ID={nodo}",
        "NODE_HOST=0.0.0.0",
        f"NODE_ADVERTISE_HOST={ip}",
        f"NODE_PORT={p2p}",
        f"API_PORT={api}",
        f"DATA_DIR={d}/data/{nodo}",
        "LOG_LEVEL=INFO",
        "CONSENSUS=pbft",
        f"PBFT_REPLICAS_FILE={d}/pbft_replicas.json",
        f"PBFT_KEY_FILE={d}/keys/pbft_{nodo}.json",
        "P2P_TLS=on",
        f"P2P_TLS_DIR={d}/tls",
        f"ADMIN_API_KEY={admin_key}",
        f"PUBLIC_BASE_URL=http://{ip}:{api}",
    ]
    if con_autoridad:
        lineas.append(f"AUTHORITY_KEY_FILE={d}/keys/authority.json")
    return "\n".join(lineas) + "\n"


def _verificar_autoridad(ruta: Path) -> None:
    """Sale con error si la llave no es la autoridad del génesis (si no, mint/emisores dan 503)."""
    from blockchain.core.block import GENESIS_AUTHORITY_ADDRESS
    from blockchain.core.wallet import Wallet, derive_address, public_key_from_private
    try:
        w = Wallet.load(str(ruta))
        direccion = derive_address(public_key_from_private(w.private_key_hex))
    except Exception as e:
        sys.exit(f"La llave de autoridad {ruta} es ilegible ({e}).")
    if direccion != GENESIS_AUTHORITY_ADDRESS:
        sys.exit(f"La llave {ruta} tiene la dirección {direccion}, que NO es la autoridad del "
                 f"génesis ({GENESIS_AUTHORITY_ADDRESS}). Usar la llave original de la autoridad; "
                 "con otra, los endpoints de emisión/mint devolverían 503.")


def preparar(salida: Path, ip_pi1: str, ip_pi2: str, dir_proyecto: str, api_base: int = 8000,
             p2p_base: int = 8001, desfase_pi2: int = 0, admin_key: Optional[str] = None,
             autoridad_llave: Optional[Path] = None) -> Dict[str, object]:
    """Crea los paquetes ``pi1``/``pi2`` y devuelve ``{"admin_key", "urls", "salida"}``."""
    if salida.exists() and any(salida.iterdir()):
        sys.exit(f"{salida} ya existe y no está vacío: borrarlo antes (no se sobrescriben llaves).")
    if autoridad_llave is not None and not autoridad_llave.is_file():
        sys.exit(f"No existe la llave de autoridad {autoridad_llave}")
    if autoridad_llave is not None:
        _verificar_autoridad(autoridad_llave)
    admin_key = admin_key or secrets.token_hex(24)
    d = dir_proyecto.rstrip("/")
    ips = {"pi1": ip_pi1, "pi2": ip_pi2}
    desfase = {"pi1": 0, "pi2": desfase_pi2}

    ca = salida / "ca"
    crear_ca(ca)
    lista = salida / "pbft_replicas.json"
    llaves = salida / "_llaves"
    urls: List[str] = []
    datos = []
    for pi, nodo, hueco in REPLICAS:
        api = api_base + 10 * hueco + desfase[pi]
        p2p = p2p_base + 10 * hueco + desfase[pi]
        with contextlib.redirect_stdout(io.StringIO()):   # sus avisos de "f = 0" confunden aquí
            crear_llave_replica(nodo, f"{ips[pi]}:{p2p}", llaves / f"pbft_{nodo}.json", lista)
        datos.append((pi, nodo, api, p2p))
        urls.append(f"http://{ips[pi]}:{api}")

    for pi, nodo, api, p2p in datos:
        paquete = salida / pi
        for sub in ("nodes", "keys", "tls"):
            (paquete / sub).mkdir(parents=True, exist_ok=True)
        # newline="\n": systemd conserva un \r de más como parte del valor.
        with open(paquete / "nodes" / f"{nodo}.env", "w", encoding="utf-8", newline="\n") as f:
            f.write(_env(nodo, ips[pi], api, p2p, d, admin_key,
                         autoridad_llave is not None and nodo == "node_1"))
        shutil.copy2(llaves / f"pbft_{nodo}.json", paquete / "keys" / f"pbft_{nodo}.json")
        shutil.copy2(lista, paquete / "pbft_replicas.json")
        shutil.copy2(ca / "ca.crt", paquete / "tls" / "ca.crt")
    # Certificados: se emiten junto a la CA y se reparten solo los de cada Pi.
    for pi, nodo, api, p2p in datos:
        emitir_cert_nodo(ca, nodo, [ips[pi]])
        for ext in ("crt", "key"):
            shutil.copy2(ca / f"{nodo}.{ext}", salida / pi / "tls" / f"{nodo}.{ext}")
            (ca / f"{nodo}.{ext}").unlink()
    if autoridad_llave is not None:
        shutil.copy2(autoridad_llave, salida / "pi1" / "keys" / "authority.json")
    shutil.rmtree(llaves)
    lista.unlink()
    return {"admin_key": admin_key, "urls": urls, "salida": salida}


def main() -> None:
    ap = argparse.ArgumentParser(description="Paquetes de despliegue para 2 Pi x 2 réplicas PBFT")
    ap.add_argument("--ip-pi1", required=True)
    ap.add_argument("--ip-pi2", required=True)
    ap.add_argument("--usuario", default="pi", help="usuario Linux de las Pi (para las rutas)")
    ap.add_argument("--dir-proyecto", help="raíz del proyecto en la Pi (por defecto /home/<usuario>/upb-chain)")
    ap.add_argument("--salida", default="data/despliegue")
    ap.add_argument("--api-base", type=int, default=8000)
    ap.add_argument("--p2p-base", type=int, default=8001)
    ap.add_argument("--desfase-pi2", type=int, default=0,
                    help="se suma a los puertos de la 2.ª Pi (solo para simular ambas en una máquina)")
    ap.add_argument("--admin-key", help="ADMIN_API_KEY común (por defecto una aleatoria)")
    ap.add_argument("--autoridad-llave",
                    help="llave de la autoridad del génesis: se copia SOLO al paquete de node_1")
    args = ap.parse_args()
    r = preparar(Path(args.salida), args.ip_pi1, args.ip_pi2,
                 args.dir_proyecto or f"/home/{args.usuario}/upb-chain", args.api_base,
                 args.p2p_base, args.desfase_pi2, args.admin_key,
                 Path(args.autoridad_llave) if args.autoridad_llave else None)
    print(f"\nPaquetes listos en {r['salida']}/pi1 y {r['salida']}/pi2 (NO versionar).")
    print(f"ca.key queda en {r['salida']}/ca/ca.key: no copiarla a ninguna Pi.")
    print(f"ADMIN_API_KEY: {r['admin_key']}")
    print("URLs de la API: " + " ".join(r["urls"]))


if __name__ == "__main__":
    main()
