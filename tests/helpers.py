"""Utilidades de prueba: minar bloques válidos con dificultad baja (P0-3)."""
from blockchain.consensus.proof_of_work import ProofOfWork


def mine_candidate(bc, transactions=None):
    """Crea un candidato, lo mina con la dificultad esperada y lo devuelve (sin añadirlo)."""
    candidate = bc.create_candidate_block(transactions)
    result = ProofOfWork(difficulty=candidate.header.difficulty).mine(
        candidate, timeout=60.0, difficulty=candidate.header.difficulty
    )
    assert result is not None, "el minado de prueba falló"
    return result.block


def mine_and_add(bc, transactions=None):
    """Mina y añade el siguiente bloque; devuelve (ok, motivo)."""
    return bc.add_block(mine_candidate(bc, transactions))
