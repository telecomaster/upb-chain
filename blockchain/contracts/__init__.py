"""
Contratos de UPB-Chain (P1-13): reglas deterministas reproducidas en cada nodo.

Para agregar un contrato: escribirlo en este paquete siguiendo ``base.py``
(``voting.py`` es la plantilla) y sumarlo a ``default_contracts``. El
conjunto de contratos es parte del consenso: todos los nodos de la red deben
correr la misma lista, en el mismo orden (ver ``docs/contratos.md``).
"""
from typing import List, Optional


def default_contracts(authority_address: Optional[str] = None) -> List:
    """Contratos de aplicación de la red. El de cuentas lo agrega la cadena, primero."""
    from blockchain.contracts.badges import BadgeContract
    from blockchain.contracts.credential import CredentialContract
    from blockchain.contracts.programs import ProgramContract
    from blockchain.contracts.tokens import TokenContract
    from blockchain.contracts.voting import VotingContract
    return [
        CredentialContract(authority_address),
        VotingContract(authority_address),  # P2-12: elecciones ponderadas (lee badges/accounts)
        TokenContract(authority_address),   # P1-12: lee emisores de "credentials"
        BadgeContract(),                    # P1-12: ídem
        ProgramContract(),                  # P2-11: VM de pila ("vm"); va al final
    ]
