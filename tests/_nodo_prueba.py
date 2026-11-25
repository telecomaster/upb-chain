"""
Arranque de un nodo real para tests multinodo (P0-8). Uso: python tests/_nodo_prueba.py

El génesis fija la dirección de la autoridad UPB y su llave privada nunca se
versiona; por eso los tests no pueden firmar ISSUER_REGISTER con la real. Este
lanzador, SOLO para tests, sustituye la dirección de autoridad por la de una
llave temporal (env TEST_AUTHORITY_ADDRESS) y recalcula GENESIS_HASH ANTES de
importar la app. Todos los nodos del test comparten esa red de prueba.
El código de producción no se modifica.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import blockchain.core.block as _block  # noqa: E402

_block.GENESIS_AUTHORITY_ADDRESS = os.environ["TEST_AUTHORITY_ADDRESS"]
_block.GENESIS_HASH = _block.Block.create_genesis().compute_hash()

import uvicorn  # noqa: E402
from api.app import app  # noqa: E402

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ["API_PORT"]), log_level="warning")
