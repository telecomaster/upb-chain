"""
Genera el par de llaves de la autoridad UPB (P0-6).

La autoridad firma las TXs ISSUER_REGISTER (alta de emisores de credenciales).
Su *dirección* va en el génesis (``GENESIS_AUTHORITY_ADDRESS`` en
``blockchain/core/block.py``); su llave *privada* se guarda solo en un archivo
local ignorado por git (``data/keys/authority.json`` por defecto).

Uso (desde la raíz del repo):
    venv\\Scripts\\python.exe scripts\\crear_llave_autoridad.py [ruta]

Cambiar la dirección de la autoridad cambia el hash del génesis: es una red
nueva y las cadenas existentes dejan de ser compatibles. Para una red ya
desplegada NO generar otra llave: usar la original (la que corresponde a
``GENESIS_AUTHORITY_ADDRESS``).
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blockchain.core.wallet import Wallet  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description="Genera la llave de la autoridad UPB")
    ap.add_argument("ruta", nargs="?", default="data/keys/authority.json",
                    help="archivo de salida (por defecto data/keys/authority.json)")
    ruta = Path(ap.parse_args().ruta)
    if ruta.exists():
        sys.exit(f"{ruta} ya existe; no se sobrescribe una llave de autoridad.")
    ruta.parent.mkdir(parents=True, exist_ok=True)
    wallet = Wallet.generate()
    wallet.export(str(ruta))
    print(f"Llave privada guardada en {ruta} (NO versionar).")
    print(f"Dirección de la autoridad: {wallet.address}")
    print("OJO: solo para una red NUEVA. Poner esta dirección en GENESIS_AUTHORITY_ADDRESS "
          "(blockchain/core/block.py) cambia el génesis y obliga a que todos los nodos borren "
          "su DATA_DIR y resincronicen. En una red existente usar la llave original.")


if __name__ == "__main__":
    main()
