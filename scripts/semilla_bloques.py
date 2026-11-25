"""Semilla de 50+ bloques con TXs realistas en un DATA_DIR (P1-10).

Crea una cadena de demostración: registra un emisor UPB, acuña tokens, emite
credenciales y hace transferencias, un bloque tras otro, con las reglas reales
(firmas ECDSA, nonce = confirmado + 1, contratos). Sirve para demos y para
medir (arranque, consulta) sobre una cadena que no esté vacía.

Llave de autoridad: ``--llave-autoridad`` (por defecto ``data/keys/authority.json``).
Si esa llave es la del génesis se usa tal cual y los nodos normales aceptan la
cadena. Si no existe, se genera una autoridad LOCAL en ``<data-dir>/keys/`` y la
cadena solo valida en nodos construidos con ESA dirección de autoridad
(``create_app(settings, authority_address=...)``): útil para pruebas y bancos de
medición, no para unirse a la red real. Nunca se versionan llaves.

La dificultad inicial (``--bits``, por defecto 2) es regla de consenso: el nodo que
lea la cadena debe arrancar con ``MINING_DIFFICULTY`` igual a ese valor.
``--data-dir`` es obligatorio: el script nunca escribe en ``data/`` por sí solo.

Uso (desde la raíz del repo)::

    venv\\Scripts\\python.exe scripts\\semilla_bloques.py --data-dir data/semilla --bloques 60
"""
import argparse
import random
import sys
from pathlib import Path
from typing import Optional

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))

from blockchain.consensus.proof_of_work import ProofOfWork  # noqa: E402
from blockchain.core.block import GENESIS_AUTHORITY_ADDRESS  # noqa: E402
from blockchain.core.chain import Blockchain  # noqa: E402
from blockchain.core.transaction import (  # noqa: E402
    create_credential_transaction, create_issuer_register_transaction,
    create_mint_transaction, create_transfer_transaction,
)
from blockchain.core.wallet import Wallet  # noqa: E402

PROGRAMAS = ["Ingeniería en IA", "Ingeniería de Sistemas", "Ingeniería Industrial",
             "Ingeniería Civil"]
N_ESTUDIANTES = 12


def cargar_autoridad(llave: str, data_dir: Path) -> Wallet:
    """Autoridad del génesis si ``llave`` es esa; si no, una local nueva (ver docstring)."""
    if Path(llave).exists():
        w = Wallet.load(llave)
        if w.address == GENESIS_AUTHORITY_ADDRESS:
            return w
    destino = Path(data_dir) / "keys" / "authority_local.json"
    if destino.exists():
        return Wallet.load(str(destino))
    destino.parent.mkdir(parents=True, exist_ok=True)
    w = Wallet.generate()
    w.export(str(destino))
    return w


def minar_siguiente(bc: Blockchain) -> None:
    """Mina y añade el siguiente bloque con las TXs válidas del mempool."""
    cand = bc.create_candidate_block()
    res = ProofOfWork(difficulty=cand.header.difficulty).mine(
        cand, timeout=120.0, difficulty=cand.header.difficulty)
    ok, motivo = bc.add_block(res.block) if res else (False, "minado sin solución")
    if not ok:
        raise RuntimeError(f"bloque rechazado en la semilla: {motivo}")


def enviar(bc: Blockchain, tx) -> None:
    ok, motivo = bc.add_transaction(tx)
    if not ok:
        raise RuntimeError(f"TX rechazada en la semilla: {motivo}")


def sembrar(data_dir, bloques: int = 55, autoridad: Optional[Wallet] = None,
            bits: int = 2, semilla: int = 7) -> dict:
    """Añade bloques hasta que la cadena tenga al menos ``bloques`` (sin contar el
    génesis) y devuelve un resumen. ``autoridad`` es quien firma ISSUER_REGISTER y
    TOKEN_MINT; el nodo que lea la cadena debe usar esa misma dirección."""
    data_dir = Path(data_dir)
    autoridad = autoridad or cargar_autoridad("data/keys/authority.json", data_dir)
    rng = random.Random(semilla)
    bc = Blockchain("semilla", str(data_dir), initial_difficulty=bits, authority_address=autoridad.address)
    try:
        emisor = Wallet.generate()
        alumnos = [Wallet.generate() for _ in range(N_ESTUDIANTES)]
        nonce = bc.next_nonce
        contadores = {"CREDENTIAL_ISSUE": 0, "TOKEN_MINT": 0, "TOKEN_TRANSFER": 0,
                      "ISSUER_REGISTER": 0}

        # Bloque de arranque: alta del emisor y saldo inicial de cada estudiante.
        enviar(bc, create_issuer_register_transaction(
            autoridad.address, emisor.address, "UPB", autoridad.private_key_hex,
            nonce(autoridad.address)))
        contadores["ISSUER_REGISTER"] += 1
        for a in alumnos:
            enviar(bc, create_mint_transaction(
                autoridad.address, a.address, 1000, autoridad.private_key_hex,
                nonce(autoridad.address)))
            contadores["TOKEN_MINT"] += 1
        minar_siguiente(bc)

        while bc.height < bloques:
            n = bc.height
            for _ in range(rng.randint(1, 2)):
                alumno = rng.choice(alumnos)
                enviar(bc, create_credential_transaction(
                    emisor.address, alumno.address, {
                        "student_name": f"Estudiante {rng.randint(1000, 9999)}",
                        "program": rng.choice(PROGRAMAS),
                        "degree": f"Licenciatura {n}-{rng.randint(0, 999)}",
                        "issue_date": "2026-06-10", "credential_type": "DEGREE",
                        "grade": rng.randint(61, 100),
                    }, emisor.private_key_hex, nonce(emisor.address)))
                contadores["CREDENTIAL_ISSUE"] += 1
            if n % 3 == 0:
                enviar(bc, create_mint_transaction(
                    autoridad.address, rng.choice(alumnos).address, rng.randint(5, 50),
                    autoridad.private_key_hex, nonce(autoridad.address)))
                contadores["TOKEN_MINT"] += 1
            for _ in range(rng.randint(1, 3)):
                a, b = rng.sample(alumnos, 2)
                enviar(bc, create_transfer_transaction(
                    a.address, b.address, rng.randint(1, 20), a.private_key_hex,
                    nonce(a.address)))
                contadores["TOKEN_TRANSFER"] += 1
            minar_siguiente(bc)

        ok, motivo = bc.validate_chain()
        return {"bloques": bc.height, "autoridad": autoridad.address, "valida": ok,
                "motivo": motivo, "txs": contadores,
                "total_txs": sum(len(b.transactions) for b in bc.chain)}
    finally:
        bc.close()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--data-dir", required=True, help="DATA_DIR donde se escribe chain.db")
    ap.add_argument("--bloques", type=int, default=55, help="altura objetivo (>= 50)")
    ap.add_argument("--bits", type=int, default=2, help="dificultad de minado en bits")
    ap.add_argument("--semilla", type=int, default=7)
    ap.add_argument("--llave-autoridad", default="data/keys/authority.json")
    args = ap.parse_args()
    d = Path(args.data_dir)
    r = sembrar(d, args.bloques, cargar_autoridad(args.llave_autoridad, d),
                args.bits, args.semilla)
    print(f"Cadena sembrada en {d}: {r['bloques']} bloques, {r['total_txs']} TXs, "
          f"válida={r['valida']}")
    print(f"TXs por tipo: {r['txs']}")
    print(f"Autoridad: {r['autoridad']}")


if __name__ == "__main__":
    main()
