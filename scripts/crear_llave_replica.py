"""
Genera la llave de firma de una réplica PBFT (P1-1) y la registra en la lista de réplicas.

Cada réplica firma sus mensajes PBFT (PRE-PREPARE, PREPARE, COMMIT, VIEW-CHANGE,
NEW-VIEW) con su propia llave ECDSA secp256k1 (mismo formato que una wallet). La
llave PRIVADA queda solo en la máquina de la réplica (``data/keys/``, ignorado por
git); la PÚBLICA va en ``pbft_replicas.json``, que es igual en todos los nodos.

Uso (desde la raíz del repo, una vez por réplica):
    venv\\Scripts\\python.exe scripts\\crear_llave_replica.py --id node_1 --address 192.168.1.100:8001
        [--llave data/keys/pbft_node_1.json] [--lista pbft_replicas.json]

Luego, en el .env de esa réplica: CONSENSUS=pbft, NODE_ID=node_1,
PBFT_KEY_FILE=<ruta de --llave> y PBFT_REPLICAS_FILE=<ruta de --lista>. El ORDEN de
la lista define el primario de cada vista (replicas[v mod n]): copiar el archivo
final, sin reordenarlo, a todos los nodos. Con 4 réplicas se tolera 1 falla.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blockchain.consensus.pbft import PBFTConfigError, ReplicaSet  # noqa: E402
from blockchain.core.wallet import Wallet  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Llave de firma de una réplica PBFT")
    parser.add_argument("--id", required=True, help="NODE_ID de la réplica, p. ej. node_1")
    parser.add_argument("--address", required=True,
                        help="host:puerto P2P alcanzable por las demás réplicas")
    parser.add_argument("--llave", help="archivo de la llave privada "
                                        "(por defecto data/keys/pbft_<id>.json)")
    parser.add_argument("--lista", default="pbft_replicas.json",
                        help="lista de réplicas a actualizar (se crea si no existe)")
    args = parser.parse_args()

    llave = Path(args.llave or f"data/keys/pbft_{args.id}.json")
    if llave.exists():
        sys.exit(f"{llave} ya existe; no se sobrescribe una llave de réplica.")
    lista = Path(args.lista)
    replicas = []
    if lista.exists():
        with open(lista, encoding="utf-8") as f:
            replicas = json.load(f).get("replicas", [])
        if any(r.get("id") == args.id for r in replicas):
            sys.exit(f"{args.id} ya figura en {lista}; quitarla a mano antes de regenerar su llave.")

    wallet = Wallet.generate()
    replicas.append({"id": args.id, "address": args.address, "public_key": wallet.public_key_hex})
    try:
        rs = ReplicaSet.from_list(replicas)       # valida antes de escribir nada
    except PBFTConfigError as e:
        sys.exit(f"Lista de réplicas inválida: {e}")

    llave.parent.mkdir(parents=True, exist_ok=True)
    wallet.export(str(llave))
    with open(lista, "w", encoding="utf-8") as f:
        json.dump({"replicas": rs.to_list()}, f, indent=2)
        f.write("\n")
    print(f"Llave privada de {args.id} guardada en {llave} (NO versionar).")
    print(f"{lista}: {rs.n} réplica(s), f = {rs.f}"
          + ("" if rs.f else " (hacen falta 4 réplicas para tolerar 1 falla)"))


if __name__ == "__main__":
    main()
