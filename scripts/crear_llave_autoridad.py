"""
Genera el par de llaves de la autoridad UPB (P0-6).

La autoridad firma las TXs ISSUER_REGISTER (alta de emisores de credenciales).
Su *dirección* va en el génesis (``GENESIS_AUTHORITY_ADDRESS`` en
``blockchain/core/block.py``); su llave *privada* se guarda solo en un archivo
local ignorado por git (``data/keys/authority.json`` por defecto).

Uso (desde la raíz del repo):
    venv\\Scripts\\python.exe scripts\\crear_llave_autoridad.py [ruta]

Cambiar la dirección de la autoridad cambia el hash del génesis: es una red
nueva y las cadenas existentes dejan de ser compatibles.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blockchain.core.wallet import Wallet  # noqa: E402


def main() -> None:
    ruta = Path(sys.argv[1] if len(sys.argv) > 1 else "data/keys/authority.json")
    if ruta.exists():
        sys.exit(f"{ruta} ya existe; no se sobrescribe una llave de autoridad.")
    ruta.parent.mkdir(parents=True, exist_ok=True)
    wallet = Wallet.generate()
    wallet.export(str(ruta))
    print(f"Llave privada guardada en {ruta} (NO versionar).")
    print(f"Dirección de la autoridad: {wallet.address}")
    print("Copiarla en GENESIS_AUTHORITY_ADDRESS y actualizar GENESIS_HASH.")


if __name__ == "__main__":
    main()
