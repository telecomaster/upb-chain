"""
Prepara las llaves PBFT para ``docker-compose.pbft.yml`` (P1-1).

Genera, con ``crear_llave_replica`` (sin duplicar cripto), las llaves de las 4 réplicas
``node_1``..``node_4`` y la lista de réplicas compartida:

    <salida>/pbft_node_1.json ... pbft_node_4.json   (llaves PRIVADAS; no versionar)
    <salida>/pbft_replicas.json                      (lista pública, igual en todos los nodos)

Las direcciones son los nombres de servicio de la red de Compose (``node_1:8001``...).
Uso (desde la raíz del repo):
    venv\\Scripts\\python.exe scripts\\preparar_pbft_compose.py [--salida data/pbft]
No sobrescribe llaves existentes: para regenerarlas, borrar la carpeta de salida.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from crear_llave_replica import crear_llave_replica  # noqa: E402

NODOS = ["node_1", "node_2", "node_3", "node_4"]
PUERTO_P2P = 8001


def preparar(salida: Path) -> Path:
    """Crea llaves y lista en ``salida``; devuelve la ruta de la lista de réplicas."""
    lista = salida / "pbft_replicas.json"
    for nodo in NODOS:
        crear_llave_replica(nodo, f"{nodo}:{PUERTO_P2P}", salida / f"pbft_{nodo}.json", lista)
    return lista


def main() -> None:
    parser = argparse.ArgumentParser(description="Llaves PBFT para docker-compose.pbft.yml")
    parser.add_argument("--salida", default="data/pbft", help="carpeta de salida (data/ no se versiona)")
    args = parser.parse_args()
    lista = preparar(Path(args.salida))
    print(f"Listo: {lista} y 4 llaves en {args.salida}/. Siguiente paso: "
          "docker compose -f docker-compose.yml -f docker-compose.pbft.yml up --build -d")


if __name__ == "__main__":
    main()
