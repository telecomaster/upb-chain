"""Mejora los anclajes OpenTimestamps pendientes pidiendo la prueba de Bitcoin a los calendarios.

Uso: venv/Scripts/python.exe scripts/actualizar_anclajes.py [--data-dir data/chain]
Hace llamadas HTTPS salientes; los calendarios tardan unas horas en tenerla. Idempotente.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blockchain.anchoring import actualizar_pendientes, fetch_http  # noqa: E402
from blockchain.core.storage import ChainStore  # noqa: E402


def main(argv=None, fetch=fetch_http) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data-dir", default="data/chain")
    args = ap.parse_args(argv)
    store = ChainStore(Path(args.data_dir) / "chain.db")
    try:
        n = actualizar_pendientes(store, fetch)
    finally:
        store.close()
    print(f"Anclajes mejorados a confirmados: {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
