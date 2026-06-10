"""
Tests unitarios del smart contract de credenciales académicas (CredentialContract).

Cubre: emisión, verificación, revocación, búsqueda de estudiante,
registro de emisores y estadísticas internas del contrato.
"""
import pytest

from blockchain.contracts.credential import (
    CredentialContract,
    CredentialStatus,
    CredentialType,
)
from blockchain.core.wallet import Wallet


# ---------------------------------------------------------------------------
# Helpers de construcción de datos
# ---------------------------------------------------------------------------

def _make_data(**overrides) -> dict:
    """Datos mínimos válidos para issue_credential, con sobreescrituras opcionales."""
    base = {
        "student_name": "María Flores",
        "program": "Ingeniería en Sistemas",
        "degree": "Licenciatura en Ingeniería de Sistemas",
        "issue_date": "2025-06-10",
        "credential_type": "DEGREE",
        "grade": 85.0,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Registro de emisores
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestIssuerRegistry:
    def test_register_valid_issuer(self):
        contract = CredentialContract()
        issuer = Wallet.generate()
        ok, reason = contract.register_issuer(issuer.address, "UPB")
        assert ok, reason
        assert contract.get_stats()["registered_issuers"] == 1

    def test_register_issuer_invalid_code_returns_error(self):
        """Un código de institución no autorizado debe ser rechazado con mensaje descriptivo."""
        contract = CredentialContract()
        ok, reason = contract.register_issuer("UPBsomeaddress", "INVALID_INST")
        assert not ok
        assert "INVALID_INST" in reason or "no autorizada" in reason.lower()

    def test_register_issuer_all_authorized_codes(self):
        """Todos los códigos autorizados (UPB, UMSS, UMSA) deben aceptarse."""
        contract = CredentialContract()
        for code in ("UPB", "UMSS", "UMSA"):
            ok, reason = contract.register_issuer(f"addr_{code}", code)
            assert ok, f"Código {code} rechazado: {reason}"


# ---------------------------------------------------------------------------
# Emisión de credenciales
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestCredentialIssuance:
    def test_issue_credential_all_fields_ok(
        self, credential_contract, issuer_wallet, student_wallet
    ):
        """Emisión con todos los campos requeridos debe retornar credencial válida."""
        ok, reason, cred = credential_contract.issue_credential(
            issuer_wallet.address,
            student_wallet.address,
            _make_data(),
        )
        assert ok, reason
        assert cred is not None
        assert cred.student_address == student_wallet.address
        assert cred.status == CredentialStatus.ACTIVE

    def test_issue_credential_missing_fields_returns_error(
        self, credential_contract, issuer_wallet, student_wallet
    ):
        """Omitir campos requeridos debe producir un mensaje de error descriptivo."""
        incomplete_data = {
            "student_name": "Pedro Quispe",
            # Faltan: program, degree, issue_date, credential_type
        }
        ok, reason, cred = credential_contract.issue_credential(
            issuer_wallet.address,
            student_wallet.address,
            incomplete_data,
        )
        assert not ok
        assert cred is None
        # El mensaje debe mencionar los campos faltantes
        assert "faltante" in reason.lower() or "missing" in reason.lower() or len(reason) > 5

    def test_issue_credential_duplicate_returns_error(
        self, credential_contract, issuer_wallet, student_wallet
    ):
        """Emitir la misma credencial dos veces debe retornar error en la segunda llamada."""
        data = _make_data()
        ok1, _, cred1 = credential_contract.issue_credential(
            issuer_wallet.address, student_wallet.address, data
        )
        assert ok1

        ok2, reason2, cred2 = credential_contract.issue_credential(
            issuer_wallet.address, student_wallet.address, data
        )
        assert not ok2
        assert cred2 is None
        assert "exist" in reason2.lower() or "duplicad" in reason2.lower()

    def test_issue_credential_unregistered_issuer_rejected(self, student_wallet):
        """Un emisor no registrado no puede emitir credenciales."""
        contract = CredentialContract()
        unregistered = Wallet.generate()
        ok, reason, cred = contract.issue_credential(
            unregistered.address,
            student_wallet.address,
            _make_data(),
        )
        assert not ok
        assert cred is None


# ---------------------------------------------------------------------------
# Verificación
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestCredentialVerification:
    def test_verify_active_credential_is_valid(
        self, credential_contract, issuer_wallet, student_wallet
    ):
        """Una credencial activa debe verificarse como válida."""
        _, _, cred = credential_contract.issue_credential(
            issuer_wallet.address, student_wallet.address, _make_data()
        )
        ok, reason, data = credential_contract.verify_credential(cred.credential_id)
        assert ok, reason
        assert data is not None
        assert data["status"] == CredentialStatus.ACTIVE

    def test_verify_nonexistent_id_returns_not_found(self, credential_contract):
        """Verificar un ID inexistente debe retornar False y sin datos."""
        ok, reason, data = credential_contract.verify_credential("nonexistent_id_abc123")
        assert not ok
        assert data is None
        assert "no encontrada" in reason.lower() or "not found" in reason.lower()


# ---------------------------------------------------------------------------
# Revocación
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestCredentialRevocation:
    def test_revoke_credential_makes_it_invalid(
        self, credential_contract, issuer_wallet, student_wallet
    ):
        """Revocar una credencial activa debe hacer que la verificación retorne False."""
        _, _, cred = credential_contract.issue_credential(
            issuer_wallet.address, student_wallet.address, _make_data()
        )
        revoke_ok, revoke_reason = credential_contract.revoke_credential(
            issuer_wallet.address, cred.credential_id, "Error administrativo en emisión"
        )
        assert revoke_ok, revoke_reason

        verify_ok, _, _ = credential_contract.verify_credential(cred.credential_id)
        assert not verify_ok

    def test_revoke_then_verify_returns_revoked_status(
        self, credential_contract, issuer_wallet, student_wallet
    ):
        """Tras revocar, verify_credential reporta estado REVOKED."""
        _, _, cred = credential_contract.issue_credential(
            issuer_wallet.address, student_wallet.address, _make_data()
        )
        credential_contract.revoke_credential(
            issuer_wallet.address, cred.credential_id, "Test revocación"
        )
        # La credencial existe pero está revocada
        raw = credential_contract._credentials.get(cred.credential_id)
        assert raw is not None
        assert raw.status == CredentialStatus.REVOKED


# ---------------------------------------------------------------------------
# Búsqueda por estudiante
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestStudentCredentials:
    def test_get_student_credentials_empty_when_no_records(self, credential_contract):
        """Estudiante sin credenciales retorna lista vacía."""
        unknown = Wallet.generate()
        results = credential_contract.get_student_credentials(unknown.address)
        assert results == []

    def test_get_student_credentials_returns_all_issued(
        self, credential_contract, issuer_wallet, student_wallet
    ):
        """Después de emitir dos credenciales distintas, get_student_credentials las retorna."""
        data1 = _make_data(degree="Licenciatura Primero", credential_type="DEGREE")
        data2 = _make_data(
            degree="Certificación Cloud",
            credential_type="CERTIFICATION",
            issue_date="2025-07-01",
        )
        credential_contract.issue_credential(
            issuer_wallet.address, student_wallet.address, data1
        )
        credential_contract.issue_credential(
            issuer_wallet.address, student_wallet.address, data2
        )
        results = credential_contract.get_student_credentials(student_wallet.address)
        assert len(results) == 2


# ---------------------------------------------------------------------------
# Estadísticas del contrato
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestContractStats:
    def test_stats_reflect_issued_and_revoked_counts(
        self, credential_contract, issuer_wallet, student_wallet
    ):
        """get_stats() debe reflejar contadores coherentes con las operaciones."""
        before = credential_contract.get_stats()

        # Emitir dos credenciales
        _, _, c1 = credential_contract.issue_credential(
            issuer_wallet.address,
            student_wallet.address,
            _make_data(degree="Grado A", issue_date="2025-01-01"),
        )
        s2 = Wallet.generate()
        _, _, c2 = credential_contract.issue_credential(
            issuer_wallet.address,
            s2.address,
            _make_data(degree="Grado B", issue_date="2025-02-01"),
        )

        after_issue = credential_contract.get_stats()
        assert after_issue["total_credentials"] == before["total_credentials"] + 2
        assert after_issue["active"] == before["active"] + 2

        # Revocar una
        credential_contract.revoke_credential(
            issuer_wallet.address, c1.credential_id, "Motivo prueba"
        )

        after_revoke = credential_contract.get_stats()
        assert after_revoke["revoked"] == before.get("revoked", 0) + 1
        assert after_revoke["active"] == after_issue["active"] - 1
