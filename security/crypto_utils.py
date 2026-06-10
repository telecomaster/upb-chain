"""
UPB-Chain — Primitivas Criptográficas
Universidad Privada Boliviana · Carrera de IA · Área de Ciberseguridad

Implementa las primitivas criptográficas que sustentan la seguridad del sistema:

─── Firma digital (ECDSA secp256k1) ───────────────────────────────────────
    Curva elíptica: y² = x³ + 7 (mod p) sobre F_p donde
    p = 2²⁵⁶ − 2³² − 977  (primo de 256 bits)
    n = orden del grupo de puntos (número de llaves privadas posibles ≈ 10⁷⁷)

    Seguridad: equivalente a RSA-3072, pero llave 4× más pequeña (32 bytes).
    Razón de elección: mismo estándar que Bitcoin/Ethereum; validado masivamente.
    Ref: Johnson et al. (2001) — ECDSA. IJIS.

─── Funciones de hash ─────────────────────────────────────────────────────
    SHA-256:   salida 256 bits, resistente a colisiones (2¹²⁸ operaciones).
    SHA3-256:  Keccak-256, diferente construcción (sponge) → diversidad.
    BLAKE2b:   más rápido que SHA-256 en software, salida 512 bits.

    Propiedad avalancha: cambiar 1 bit de entrada cambia ~50 % de la salida.

─── Cifrado simétrico (AES-256-GCM) ───────────────────────────────────────
    Cifrado autenticado: proporciona confidencialidad + integridad + autenticidad.
    Nonce de 12 bytes aleatorio por operación → evita reutilización de nonce.
    Precondición: nunca reutilizar (key, nonce). Genera nonce nuevo con os.urandom().

─── Derivación de contraseñas (PBKDF2-HMAC-SHA256) ────────────────────────
    Iteraciones: 100,000 → ~100 ms en RPi5 por verificación → costoso para atacante.
    Salt: 32 bytes aleatorios por contraseña → previene rainbow tables.

─── Comparación de hashes (hmac.compare_digest) ───────────────────────────
    Tiempo constante → previene timing attacks en verificación de contraseñas.

Rendimiento esperado en RPi5 (Cortex-A76 @ 2.4 GHz):
    SHA-256:              ~500,000 ops/s
    ECDSA sign+verify:    ~300–500 ops/s
    AES-256-GCM encrypt:  ~1,000,000 ops/s (aceleración AES-NI disponible)

Referencias:
    NIST FIPS 186-5 (2023) — Digital Signature Standard (ECDSA).
    NIST SP 800-57 (2020) — Key Management Recommendation.
    Johnson, D., et al. (2001). The Elliptic Curve Digital Signature Algorithm. IJIS.
"""
import hashlib
import hmac
import json
import os
import secrets
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import base64


# ── Firma y verificación ECDSA ────────────────────────────────────────────────

def generate_keypair() -> Tuple[str, str]:
    """Retorna (private_key_hex, public_key_hex) para secp256k1."""
    private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_bytes.hex(), pub_bytes.hex()


def sign_data(message: str, private_key_hex: str) -> str:
    priv_bytes = bytes.fromhex(private_key_hex)
    private_key = serialization.load_der_private_key(priv_bytes, password=None, backend=default_backend())
    signature = private_key.sign(message.encode(), ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode()


def verify_signature(message: str, signature_b64: str, public_key_hex: str) -> bool:
    try:
        pub_bytes = bytes.fromhex(public_key_hex)
        public_key = serialization.load_der_public_key(pub_bytes, backend=default_backend())
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, message.encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, Exception):
        return False


# ── Funciones de hash ─────────────────────────────────────────────────────────

def sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def sha3_256(data: str) -> str:
    return hashlib.sha3_256(data.encode()).hexdigest()


def blake2b(data: str) -> str:
    return hashlib.blake2b(data.encode()).hexdigest()


def double_sha256(data: str) -> str:
    first = hashlib.sha256(data.encode()).digest()
    return hashlib.sha256(first).hexdigest()


def hash_object(obj: dict) -> str:
    serialized = json.dumps(obj, sort_keys=True, ensure_ascii=False)
    return sha256(serialized)


# ── Generación de tokens seguros ──────────────────────────────────────────────

def generate_nonce(length: int = 32) -> str:
    return secrets.token_hex(length)


def generate_challenge() -> str:
    """Challenge de autenticación de un solo uso."""
    return secrets.token_urlsafe(32)


# ── Derivación de llave (KDF) ─────────────────────────────────────────────────

def derive_key(password: str, salt: bytes, iterations: int = 100_000) -> bytes:
    """PBKDF2-HMAC-SHA256 para derivación de llaves desde contraseña."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)


def hash_password(password: str) -> Tuple[str, str]:
    """Retorna (salt_hex, hash_hex) para almacenamiento seguro."""
    salt = os.urandom(32)
    key = derive_key(password, salt)
    return salt.hex(), key.hex()


def verify_password(password: str, salt_hex: str, stored_hash_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    key = derive_key(password, salt)
    return hmac.compare_digest(key.hex(), stored_hash_hex)


# ── Cifrado simétrico AES-GCM ──────────────────────────────────────────────────

def encrypt_aes_gcm(plaintext: str, key_hex: str) -> dict:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = bytes.fromhex(key_hex)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return {
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
    }


def decrypt_aes_gcm(encrypted: dict, key_hex: str) -> str:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = bytes.fromhex(key_hex)
    nonce = bytes.fromhex(encrypted["nonce"])
    ciphertext = bytes.fromhex(encrypted["ciphertext"])
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()


# ── Benchmark criptográfico ───────────────────────────────────────────────────

def benchmark_crypto(iterations: int = 10_000) -> dict:
    import time
    results = {}
    msg = "UPB-Chain benchmark test message " * 5

    for name, fn in [("sha256", sha256), ("sha3_256", sha3_256), ("blake2b", blake2b)]:
        t0 = time.perf_counter()
        for _ in range(iterations):
            fn(msg)
        elapsed = time.perf_counter() - t0
        results[name] = {
            "ops_per_sec": round(iterations / elapsed),
            "avg_us": round(elapsed / iterations * 1_000_000, 2),
        }

    priv, pub = generate_keypair()
    t0 = time.perf_counter()
    for i in range(100):
        sig = sign_data(f"msg_{i}", priv)
        verify_signature(f"msg_{i}", sig, pub)
    elapsed = time.perf_counter() - t0
    results["ecdsa_sign_verify"] = {
        "ops_per_sec": round(100 / elapsed),
        "avg_ms": round(elapsed / 100 * 1000, 2),
    }

    return results
