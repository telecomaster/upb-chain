"""
Tests unitarios del contrato de credenciales académicas (CredentialContract).

Cubre: emisión, verificación, revocación, búsqueda de estudiante,
registro de emisores y estadísticas. Desde P1-13 el contrato son reglas
puras (``validate``/``apply``) sobre un ``CredentialState``; aquí se ejercitan
con ``execute`` sobre TXs en dict (la firma la verifica la cadena, no el contrato).
"""
import pytest

from blockchain.contracts.credential import (
    CredentialContract,
    CredentialStatus,
    credential_id_of_tx,
)
from blockchain.core.wallet import Wallet


# ---------------------------------------------------------------------------
# Helpers de construcción de datos
# ---------------------------------------------------------------------------

def _make_data(**overrides) -> dict:
    """Datos mínimos válidos para una emisión, con sobreescrituras opcionales."""
    base = {
        "program": "Ingeniería en Sistemas",
        "degree": "Licenciatura en Ingeniería de Sistemas",
        "issue_date": "2025-06-10",
        "credential_type": "DEGREE",
        "fields_root": "ab" * 32,
    }
    base.update(overrides)
    return base


def _registro(contract, issuer_address, code="UPB") -> dict:
    return {"type": "ISSUER_REGISTER", "sender": contract.authority_address,
            "recipient": issuer_address, "tx_id": f"reg-{issuer_address}-{code}",
            "payload": {"issuer_address": issuer_address, "institution_code": code}}


def _emision(issuer, student, data) -> dict:
    return {"type": "CREDENTIAL_ISSUE", "sender": issuer, "recipient": student,
            "tx_id": f"emi-{student}-{data.get('degree')}", "payload": data}


def _revocacion(revoker, credential_id, reason) -> dict:
    return {"type": "CREDENTIAL_REVOKE", "sender": revoker, "recipient": "",
            "tx_id": f"rev-{credential_id}",
            "payload": {"credential_id": credential_id, "reason": reason}}


def _emitir(contract, state, issuer, student, data):
    """Emite y devuelve (ok, motivo, estado, credencial o None)."""
    tx = _emision(issuer, student, data)
    ok, reason, state = contract.execute(state, tx)
    return ok, reason, state, (state.get(credential_id_of_tx(tx)) if ok else None)


# ---------------------------------------------------------------------------
# Registro de emisores
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestIssuerRegistry:
    def test_register_valid_issuer(self):
        contract = CredentialContract()
        issuer = Wallet.generate()
        ok, reason, state = contract.execute(contract.initial_state(),
                                             _registro(contract, issuer.address))
        assert ok, reason
        assert state.get_stats()["registered_issuers"] == 1

    def test_register_issuer_invalid_code_returns_error(self):
        """Un código de institución no autorizado debe ser rechazado con mensaje descriptivo."""
        contract = CredentialContract()
        ok, reason, _ = contract.execute(contract.initial_state(),
                                         _registro(contract, "UPBsomeaddress", "INVALID_INST"))
        assert not ok
        assert "INVALID_INST" in reason or "no autorizada" in reason.lower()

    def test_register_issuer_all_authorized_codes(self):
        """Todos los códigos autorizados (UPB, UMSS, UMSA) deben aceptarse."""
        contract = CredentialContract()
        state = contract.initial_state()
        for code in ("UPB", "UMSS", "UMSA"):
            ok, reason, state = contract.execute(state, _registro(contract, f"addr_{code}", code))
            assert ok, f"Código {code} rechazado: {reason}"

    def test_register_issuer_by_non_authority_rejected(self):
        contract = CredentialContract()
        tx = _registro(contract, "UPBx")
        tx["sender"] = "UPBintruso"
        ok, reason, _ = contract.execute(contract.initial_state(), tx)
        assert not ok and "autoridad" in reason


# ---------------------------------------------------------------------------
# Emisión de credenciales
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestCredentialIssuance:
    def test_issue_credential_all_fields_ok(
        self, credential_contract, credential_state, issuer_wallet, student_wallet
    ):
        """Emisión con todos los campos requeridos debe retornar credencial válida."""
        ok, reason, _, cred = _emitir(credential_contract, credential_state,
                                      issuer_wallet.address, student_wallet.address, _make_data())
        assert ok, reason
        assert cred is not None
        assert cred.student_address == student_wallet.address
        assert cred.status == CredentialStatus.ACTIVE

    def test_issue_credential_missing_fields_returns_error(
        self, credential_contract, credential_state, issuer_wallet, student_wallet
    ):
        """Omitir campos requeridos debe producir un mensaje de error descriptivo."""
        incomplete_data = {
            "program": "Ingeniería",
            # Faltan: program, degree, issue_date, credential_type
        }
        ok, reason, _, cred = _emitir(credential_contract, credential_state,
                                      issuer_wallet.address, student_wallet.address,
                                      incomplete_data)
        assert not ok
        assert cred is None
        assert "faltante" in reason.lower()

    def test_issue_credential_duplicate_returns_error(
        self, credential_contract, credential_state, issuer_wallet, student_wallet
    ):
        """Emitir la misma credencial dos veces debe retornar error en la segunda llamada."""
        data = _make_data()
        ok1, _, state, _ = _emitir(credential_contract, credential_state,
                                   issuer_wallet.address, student_wallet.address, data)
        assert ok1
        ok2, reason2, _, cred2 = _emitir(credential_contract, state,
                                         issuer_wallet.address, student_wallet.address, data)
        assert not ok2
        assert cred2 is None
        assert "exist" in reason2.lower()

    def test_issue_credential_unregistered_issuer_rejected(self, student_wallet):
        """Un emisor no registrado no puede emitir credenciales."""
        contract = CredentialContract()
        unregistered = Wallet.generate()
        ok, reason, _, cred = _emitir(contract, contract.initial_state(),
                                      unregistered.address, student_wallet.address, _make_data())
        assert not ok
        assert cred is None

    def test_invalid_tx_leaves_state_unchanged(
        self, credential_contract, credential_state, issuer_wallet
    ):
        """Una TX inválida no modifica el estado recibido (validate es pura)."""
        antes = credential_state.get_stats()
        ok, _, state = credential_contract.execute(
            credential_state, _emision(issuer_wallet.address, "", _make_data()))
        assert not ok and state is credential_state
        assert state.get_stats() == antes


# ---------------------------------------------------------------------------
# Verificación
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestCredentialVerification:
    def test_verify_active_credential_is_valid(
        self, credential_contract, credential_state, issuer_wallet, student_wallet
    ):
        """Una credencial activa debe verificarse como válida."""
        _, _, state, cred = _emitir(credential_contract, credential_state,
                                    issuer_wallet.address, student_wallet.address, _make_data())
        ok, reason, data = state.verify_credential(cred.credential_id)
        assert ok, reason
        assert data is not None
        assert data["status"] == CredentialStatus.ACTIVE

    def test_verify_nonexistent_id_returns_not_found(self, credential_state):
        """Verificar un ID inexistente debe retornar False y sin datos."""
        ok, reason, data = credential_state.verify_credential("nonexistent_id_abc123")
        assert not ok
        assert data is None
        assert "no encontrada" in reason.lower()


# ---------------------------------------------------------------------------
# Revocación
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestCredentialRevocation:
    def test_revoke_credential_makes_it_invalid(
        self, credential_contract, credential_state, issuer_wallet, student_wallet
    ):
        """Revocar una credencial activa debe hacer que la verificación retorne False."""
        _, _, state, cred = _emitir(credential_contract, credential_state,
                                    issuer_wallet.address, student_wallet.address, _make_data())
        revoke_ok, revoke_reason, state = credential_contract.execute(
            state, _revocacion(issuer_wallet.address, cred.credential_id,
                               "Error administrativo en emisión"))
        assert revoke_ok, revoke_reason

        verify_ok, _, _ = state.verify_credential(cred.credential_id)
        assert not verify_ok

    def test_revoke_then_verify_returns_revoked_status(
        self, credential_contract, credential_state, issuer_wallet, student_wallet
    ):
        """Tras revocar, la credencial existe con estado REVOKED."""
        _, _, state, cred = _emitir(credential_contract, credential_state,
                                    issuer_wallet.address, student_wallet.address, _make_data())
        _, _, state = credential_contract.execute(
            state, _revocacion(issuer_wallet.address, cred.credential_id, "Test revocación"))
        raw = state.get(cred.credential_id)
        assert raw is not None
        assert raw.status == CredentialStatus.REVOKED

    def test_revoke_by_third_party_rejected(
        self, credential_contract, credential_state, issuer_wallet, student_wallet
    ):
        _, _, state, cred = _emitir(credential_contract, credential_state,
                                    issuer_wallet.address, student_wallet.address, _make_data())
        ok, reason, _ = credential_contract.execute(
            state, _revocacion(student_wallet.address, cred.credential_id, "x"))
        assert not ok and "emisor original" in reason


# ---------------------------------------------------------------------------
# Búsqueda por estudiante
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestStudentCredentials:
    def test_get_student_credentials_empty_when_no_records(self, credential_state):
        """Estudiante sin credenciales retorna lista vacía."""
        unknown = Wallet.generate()
        assert credential_state.get_student_credentials(unknown.address) == []

    def test_get_student_credentials_returns_all_issued(
        self, credential_contract, credential_state, issuer_wallet, student_wallet
    ):
        """Después de emitir dos credenciales distintas, get_student_credentials las retorna."""
        data1 = _make_data(degree="Licenciatura Primero", credential_type="DEGREE")
        data2 = _make_data(
            degree="Certificación Cloud",
            credential_type="CERTIFICATION",
            issue_date="2025-07-01",
        )
        _, _, state, _ = _emitir(credential_contract, credential_state,
                                 issuer_wallet.address, student_wallet.address, data1)
        _, _, state, _ = _emitir(credential_contract, state,
                                 issuer_wallet.address, student_wallet.address, data2)
        assert len(state.get_student_credentials(student_wallet.address)) == 2


# ---------------------------------------------------------------------------
# Estadísticas del contrato
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestContractStats:
    def test_stats_reflect_issued_and_revoked_counts(
        self, credential_contract, credential_state, issuer_wallet, student_wallet
    ):
        """get_stats() debe reflejar contadores coherentes con las operaciones."""
        before = credential_state.get_stats()

        _, _, state, c1 = _emitir(credential_contract, credential_state,
                                  issuer_wallet.address, student_wallet.address,
                                  _make_data(degree="Grado A", issue_date="2025-01-01"))
        s2 = Wallet.generate()
        _, _, state, _ = _emitir(credential_contract, state, issuer_wallet.address, s2.address,
                                 _make_data(degree="Grado B", issue_date="2025-02-01"))

        after_issue = state.get_stats()
        assert after_issue["total_credentials"] == before["total_credentials"] + 2
        assert after_issue["active"] == before["active"] + 2

        _, _, state = credential_contract.execute(
            state, _revocacion(issuer_wallet.address, c1.credential_id, "Motivo prueba"))

        after_revoke = state.get_stats()
        assert after_revoke["revoked"] == before.get("revoked", 0) + 1
        assert after_revoke["active"] == after_issue["active"] - 1
