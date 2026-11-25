"""
Crea la CA privada de la red UPB-Chain (P2-6): ``ca.key`` + ``ca.crt``.

Uso (desde la raíz del repo, UNA vez, en la máquina del administrador):
    venv\Scripts\python.exe scripts\crear_ca.py [--dir data/tls]

``ca.key`` firma los certificados de los nodos: no debe copiarse a los nodos. A cada nodo
solo van ``ca.crt`` y su propio ``<node_id>.crt/.key`` (ver ``emitir_cert_nodo.py``).
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security.pki import crear_ca  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="CA privada para el TLS mutuo del P2P")
    parser.add_argument("--dir", default="data/tls")
    args = parser.parse_args()
    try:
        crt = crear_ca(args.dir)
    except FileExistsError as e:
        sys.exit(str(e))
    print(f"CA creada: {crt} (la llave ca.key queda junto a ella; guárdala fuera de los nodos)")


if __name__ == "__main__":
    main()
