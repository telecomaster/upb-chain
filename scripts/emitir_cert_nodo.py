"""
Emite el certificado de un nodo firmado por la CA de la red (P2-6). CN = node_id.

Uso:
    venv\Scripts\python.exe scripts\emitir_cert_nodo.py node_1 --host 192.168.1.100 [--host nodo1.local]
        [--dir data/tls] [--dias 365]

Escribe ``<dir>/<node_id>.crt`` y ``<dir>/<node_id>.key``. Volver a ejecutarlo para el mismo
node_id rota el certificado (reiniciar el nodo para que lo cargue).
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security.pki import DIAS_NODO, emitir_cert_nodo  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Certificado de nodo para el TLS mutuo del P2P")
    parser.add_argument("node_id")
    parser.add_argument("--host", action="append", default=[], help="IP o nombre (SAN); repetible")
    parser.add_argument("--dir", default="data/tls")
    parser.add_argument("--dias", type=int, default=DIAS_NODO)
    args = parser.parse_args()
    try:
        crt = emitir_cert_nodo(args.dir, args.node_id, args.host, args.dias)
    except (FileNotFoundError, ValueError) as e:
        sys.exit(str(e))
    print(f"Certificado emitido: {crt} (llave: {crt.with_suffix('.key')})")


if __name__ == "__main__":
    main()
