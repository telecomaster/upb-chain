"""
Límites de tamaño de consenso (P0-3): TX y bloque.

Son reglas de CONSENSO (no política local): un bloque que las viola es inválido
para todos los nodos, igual que uno con mala firma. Por eso viven en un único
lugar y se miden de forma determinista: bytes UTF-8 del JSON canónico
(``sort_keys``, separadores compactos, ``ensure_ascii``), que no depende del
orden de las claves ni de los espacios con que llegó el mensaje.

Por qué estos valores (ver docs/arquitectura.md, "Límites de tamaño"):

- ``MAX_TX_BYTES = 64 KiB``. La TX legítima más grande del sistema es un
  ``CONTRACT_DEPLOY`` al máximo de la VM: 4096 B de bytecode (8192 caracteres
  hex) + 256 casillas iniciales con claves y valores de 256 bits. Medida con
  este mismo criterio ocupa ~49,8 KB; 64 KiB deja ~30 % de margen. Una
  credencial (campos públicos + ``fields_root``), un voto o una fila del CSV
  de premios ocupan menos de 2 KB.
- ``MAX_BLOCK_BYTES = 1 MiB``: el bloque completo (encabezado + TXs + hash).
  Caben al menos 16 TX máximas; el minero arma bloques de hasta 50 TX y corta
  antes si se pasaría del tope (``Blockchain.create_candidate_block``). Con
  bloques de 1 MiB un lote de sincronización (``GET_BLOCKS``) de pocos MB
  siempre lleva al menos un bloque entero.
- ``MAX_BLOCK_TXS = 1000``: acota también el trabajo de CPU por bloque
  (una verificación ECDSA por TX en la RPi), aunque las TX sean pequeñas.

Cambiar cualquiera de estos números es un cambio de consenso: todos los nodos
deben actualizarse a la vez (una cadena válida con un tope podría no serlo con
otro).
"""
import json

MAX_TX_BYTES = 64 * 1024          # 65 536 bytes por TX serializada
MAX_BLOCK_BYTES = 1024 * 1024     # 1 048 576 bytes por bloque serializado
MAX_BLOCK_TXS = 1000              # TXs por bloque


def serialized_size(obj) -> int:
    """Bytes del JSON canónico de ``obj``. -1 si no es serializable (se trata como inválido)."""
    try:
        return len(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    except (TypeError, ValueError, RecursionError):
        return -1


def check_tx_size(tx_dict: dict):
    """``(ok, motivo)``: la TX serializada no supera ``MAX_TX_BYTES``."""
    size = serialized_size(tx_dict)
    if size < 0:
        return False, "Transacción no serializable"
    if size > MAX_TX_BYTES:
        return False, f"Transacción demasiado grande: {size} bytes (máximo {MAX_TX_BYTES})"
    return True, "OK"


def check_block_size(block_dict: dict):
    """``(ok, motivo)``: el bloque no supera ``MAX_BLOCK_BYTES`` ni ``MAX_BLOCK_TXS``."""
    txs = block_dict.get("transactions") or []
    if len(txs) > MAX_BLOCK_TXS:
        return False, f"Bloque con demasiadas TXs: {len(txs)} (máximo {MAX_BLOCK_TXS})"
    size = serialized_size(block_dict)
    if size < 0:
        return False, "Bloque no serializable"
    if size > MAX_BLOCK_BYTES:
        return False, f"Bloque demasiado grande: {size} bytes (máximo {MAX_BLOCK_BYTES})"
    return True, "OK"
