"""
Exporta la cadena de ``chain.db`` a un JSON legible (P2-4).

Desde P2-4 el nodo guarda la cadena en SQLite (``<DATA_DIR>/chain.db``). Este
script deja la cadena como la lista de bloques de antes (``Block.to_dict()``),
útil para inspeccionarla en clase, compararla entre nodos o abrirla en un editor.
Abre la base en modo solo lectura: se puede usar con el nodo encendido.

Uso (desde la raíz del repo):
    venv\\Scripts\\python.exe scripts\\exportar_cadena.py [DATA_DIR] [-o salida.json]

Sin DATA_DIR se usa el de la configuración (.env / variables de entorno). Sin
``-o`` se escribe ``<DATA_DIR>/chain_export.json``. Con ``-o -`` se imprime.

Nota: renombrar la exportación a ``chain.json`` en un DATA_DIR SIN chain.db hace
que el nodo la importe (con validación completa) al arrancar.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blockchain.core.storage import ChainStore, StorageError  # noqa: E402


def exportar(data_dir: Path) -> list:
    """Bloques de ``<data_dir>/chain.db`` en orden de altura (lista de dicts)."""
    store = ChainStore(Path(data_dir) / "chain.db", readonly=True)
    try:
        return store.load_blocks()
    finally:
        store.close()


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="Exporta chain.db a JSON (P2-4).")
    parser.add_argument("data_dir", nargs="?", help="directorio de datos del nodo")
    parser.add_argument("-o", "--salida", help="archivo de salida ('-' = pantalla)")
    args = parser.parse_args(argv)
    if args.data_dir:
        data_dir = Path(args.data_dir)
    else:
        from config import load_settings
        data_dir = Path(load_settings().data_dir)
    try:
        bloques = exportar(data_dir)
    except StorageError as e:
        sys.exit(str(e))
    texto = json.dumps(bloques, indent=2, ensure_ascii=False)
    if args.salida == "-":
        print(texto)
        return
    salida = Path(args.salida) if args.salida else data_dir / "chain_export.json"
    with open(salida, "w", encoding="utf-8") as f:
        f.write(texto)
    print(f"{len(bloques)} bloques exportados a {salida}")


if __name__ == "__main__":
    main()
