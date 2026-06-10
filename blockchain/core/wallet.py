"""
Wallet criptográfica para UPB-Chain.
Genera pares de llaves ECDSA (secp256k1), deriva direcciones y firma transacciones.
"""
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


@dataclass
class Wallet:
    private_key_hex: str
    public_key_hex: str
    address: str

    @classmethod
    def generate(cls) -> "Wallet":
        private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_key = private_key.public_key()
        pub_bytes = pub_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        priv_hex = priv_bytes.hex()
        pub_hex = pub_bytes.hex()
        address = cls._derive_address(pub_hex)
        return cls(private_key_hex=priv_hex, public_key_hex=pub_hex, address=address)

    @staticmethod
    def _derive_address(public_key_hex: str) -> str:
        pub_bytes = bytes.fromhex(public_key_hex)
        sha256_hash = hashlib.sha256(pub_bytes).digest()
        ripemd160 = hashlib.new("ripemd160")
        ripemd160.update(sha256_hash)
        raw = ripemd160.digest()
        checksum = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
        return "UPB" + (raw + checksum).hex().upper()[:32]

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "public_key": self.public_key_hex,
        }

    def export(self, path: str, passphrase: Optional[str] = None) -> None:
        data = {
            "address": self.address,
            "public_key": self.public_key_hex,
            "private_key": self.private_key_hex,
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load(cls, path: str) -> "Wallet":
        with open(path) as f:
            data = json.load(f)
        return cls(
            private_key_hex=data["private_key"],
            public_key_hex=data["public_key"],
            address=data["address"],
        )

    def __repr__(self) -> str:
        return f"Wallet(address={self.address})"
