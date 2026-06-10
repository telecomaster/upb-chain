"""Tests de módulos de seguridad: criptografía, ataques y monitoreo."""
import os
import pytest

from security.crypto_utils import (
    generate_keypair, sign_data, verify_signature,
    sha256, sha3_256, blake2b, hash_password, verify_password,
    encrypt_aes_gcm, decrypt_aes_gcm, benchmark_crypto,
)
from security.attacks.simulator import (
    FiftyOnePercentAttack, SybilAttack, DoubleSpendAttack, full_security_analysis
)
from security.monitor import SecurityMonitor, AlertLevel


class TestCrypto:
    def test_generate_keypair(self):
        priv, pub = generate_keypair()
        assert len(priv) > 0
        assert len(pub) > 0
        assert priv != pub

    def test_sign_and_verify(self):
        priv, pub = generate_keypair()
        msg = "Hola UPB-Chain"
        sig = sign_data(msg, priv)
        assert verify_signature(msg, sig, pub)

    def test_wrong_message_fails(self):
        priv, pub = generate_keypair()
        sig = sign_data("mensaje original", priv)
        assert not verify_signature("mensaje diferente", sig, pub)

    def test_wrong_key_fails(self):
        priv1, pub1 = generate_keypair()
        _, pub2 = generate_keypair()
        sig = sign_data("test", priv1)
        assert not verify_signature("test", sig, pub2)

    def test_hash_functions_deterministic(self):
        data = "blockchain upb"
        assert sha256(data) == sha256(data)
        assert sha3_256(data) == sha3_256(data)
        assert blake2b(data) == blake2b(data)

    def test_hash_functions_different_results(self):
        data = "test"
        hashes = {sha256(data), sha3_256(data), blake2b(data)}
        assert len(hashes) == 3

    def test_password_hashing(self):
        salt, hashed = hash_password("mi_password_seguro")
        assert verify_password("mi_password_seguro", salt, hashed)
        assert not verify_password("password_incorrecto", salt, hashed)

    def test_aes_gcm_encrypt_decrypt(self):
        import os
        key = os.urandom(32).hex()
        plaintext = "Credencial académica UPB 2025"
        encrypted = encrypt_aes_gcm(plaintext, key)
        assert "nonce" in encrypted
        assert "ciphertext" in encrypted
        decrypted = decrypt_aes_gcm(encrypted, key)
        assert decrypted == plaintext

    def test_benchmark_runs(self):
        result = benchmark_crypto(iterations=100)
        assert "sha256" in result
        assert "ecdsa_sign_verify" in result

    def test_encrypt_decrypt_roundtrip_large_payload(self):
        """Cifrado y descifrado AES-GCM de un payload de 10 KB deben ser exactos."""
        key = os.urandom(32).hex()
        large_text = "X" * (10 * 1024)  # 10 KB de datos
        encrypted = encrypt_aes_gcm(large_text, key)

        assert "nonce" in encrypted
        assert "ciphertext" in encrypted
        # El ciphertext cifrado no debe coincidir con el plaintext en hex
        assert encrypted["ciphertext"] != large_text.encode().hex()

        decrypted = decrypt_aes_gcm(encrypted, key)
        assert decrypted == large_text, (
            "El texto descifrado no coincide con el original (10 KB)"
        )


class TestAttackSimulator:
    def test_51_attack_below_50_percent(self):
        attack = FiftyOnePercentAttack()
        result = attack.simulate(honest_hash_rate=70, attacker_hash_rate=30)
        assert result.attack_type == "51% Attack"
        assert not result.success
        assert len(result.recommendations) > 0

    def test_51_attack_above_50_percent(self):
        attack = FiftyOnePercentAttack()
        result = attack.simulate(honest_hash_rate=40, attacker_hash_rate=60)
        assert result.success

    def test_sybil_no_mitigation(self):
        attack = SybilAttack()
        result = attack.simulate(total_nodes=5, sybil_nodes=3)
        assert result.attack_type == "Sybil Attack"
        assert result.metrics["sybil_nodes"] == 3

    def test_sybil_with_stake_reduces_impact(self):
        attack = SybilAttack()
        r_no_mitigation = attack.simulate(total_nodes=10, sybil_nodes=5)
        r_with_stake = attack.simulate(total_nodes=10, sybil_nodes=5, require_stake=True)
        assert r_with_stake.metrics["effective_sybil_ratio"] < r_no_mitigation.metrics["effective_sybil_ratio"]

    def test_double_spend_more_confirmations_safer(self):
        attack = DoubleSpendAttack()
        r6 = attack.simulate(confirmations_required=6, attacker_hash_rate_percent=30)
        r12 = attack.simulate(confirmations_required=12, attacker_hash_rate_percent=30)
        assert r12.metrics["success_probability"] < r6.metrics["success_probability"]

    def test_double_spend_probability_decreases_with_confirmations(self):
        """La probabilidad de éxito del doble gasto decrece estrictamente con las confirmaciones.

        Según Nakamoto (2008), para cualquier tasa de hash del atacante < 50 %,
        la probabilidad de éxito converge a 0 al aumentar las confirmaciones.
        """
        attack = DoubleSpendAttack()
        attacker_rate = 30  # 30 % del hash rate

        confirmations = [1, 3, 6, 12, 24]
        probs = [
            attack.simulate(
                confirmations_required=c,
                attacker_hash_rate_percent=attacker_rate,
            ).metrics["success_probability"]
            for c in confirmations
        ]

        # La tendencia debe ser estrictamente decreciente
        for i in range(len(probs) - 1):
            assert probs[i] > probs[i + 1], (
                f"Probabilidad con {confirmations[i]} conf ({probs[i]:.6f}) "
                f"no es mayor que con {confirmations[i+1]} conf ({probs[i+1]:.6f})"
            )

    def test_full_security_analysis(self):
        result = full_security_analysis(node_count=2)
        assert "51_percent" in result
        assert "sybil_no_mitigation" in result
        assert "double_spend_6conf" in result


class TestSecurityMonitor:
    def test_detects_tx_rate_limit(self):
        monitor = SecurityMonitor()
        alerts_received = []
        monitor._alert_callback = alerts_received.append

        sender = "UPB_TEST_ADDRESS"
        tx = {"sender": sender, "type": "DATA_RECORD", "payload": {}}
        for _ in range(monitor.TX_RATE_LIMIT + 5):
            monitor.on_transaction(tx)

        warning_alerts = [
            a for a in alerts_received
            if a.event_type == "TX_RATE_LIMIT"
        ]
        assert len(warning_alerts) > 0

    def test_detects_chain_reorg(self):
        monitor = SecurityMonitor()
        monitor.on_chain_reorg(depth=5)
        alerts = monitor.get_alerts(level=AlertLevel.CRITICAL)
        assert len(alerts) > 0
        assert alerts[-1]["event_type"] == "CHAIN_REORG"

    def test_threat_summary_structure(self):
        monitor = SecurityMonitor()
        summary = monitor.get_threat_summary()
        assert "threat_level" in summary
        assert "total_alerts" in summary
        assert "chain_reorgs" in summary
