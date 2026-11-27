"""Auditoría de seguridad: contrato de votación (``blockchain/contracts/voting.py``).

Ocupación de elecciones ("squatting"): ``VotingContract.validate`` acepta un VOTE en
una elección SIN configurar (regla heredada de P1-13) y ``_check_create`` rechaza un
``ELECTION_CREATE`` si ``election_id in state.elections``. Cualquier dirección (sin
saldo, fee 0) puede votar primero en el id que la autoridad va a usar (los ids son
predecibles y el mempool es público en ``GET /transactions/pending``) y la autoridad
ya no puede crear esa elección.

Arreglo mínimo: que un VOTE en una elección sin configurar no bloquee su creación
(p. ej. ``_check_create`` solo mira ``state.configs``, y al crearla se descartan los
votos previos sin configuración), o bien exigir que la elección exista para votar.
"""
import pytest

from blockchain.core.transaction import create_election_transaction, create_vote_transaction
from blockchain.core.wallet import Wallet
from tests.test_canjes import _cadena, _ok


@pytest.mark.xfail(strict=True, reason="un VOTE previo ocupa el election_id y bloquea ELECTION_CREATE")
def test_voto_previo_no_bloquea_la_creacion_de_la_eleccion(tmp_path):
    autoridad, intruso = Wallet.generate(), Wallet.generate()
    bc = _cadena(tmp_path / "a", autoridad)
    # El intruso (sin saldo, sin registro) vota primero en el id que usará la autoridad.
    _ok(bc, [create_vote_transaction(intruso.address, "rector-2026", "x",
                                     intruso.private_key_hex, nonce=1)])
    h = bc.contracts.height
    crear = create_election_transaction(autoridad.address, "rector-2026", ["x", "y"],
                                        "one_per_address", h, h + 20,
                                        autoridad.private_key_hex, nonce=1)
    ok, motivo = bc.add_transaction(crear)
    assert ok, motivo
