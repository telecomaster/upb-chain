"""
Mini autoridad certificadora (CA) privada de la red UPB para el TLS mutuo del P2P (P2-6).

Una CA = un par llave/certificado autofirmado. Cada nodo recibe un certificado firmado
por esa CA con ``CN = node_id``; el CN es la identidad del nodo (la lista blanca se compara
contra él). Todo con ``cryptography``; los archivos van a ``data/tls/`` (ignorado por git).

Alcance: sin CRL ni OCSP. Revocar un nodo = quitarlo de ``P2P_ALLOWLIST`` en los demás
nodos; renovar = emitir otro certificado y reiniciar el nodo (ver README).
"""
import datetime
import ipaddress
import os
from pathlib import Path
from typing import Iterable, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_CRT, CA_KEY = "ca.crt", "ca.key"
DIAS_CA = 3650
DIAS_NODO = 365


def _nuevo_par():
    return ec.generate_private_key(ec.SECP256R1())


def _escribir_llave(path: Path, key) -> None:
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    # 0o600: la llave privada no debe ser legible por otros usuarios (en Windows se ignora).
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)


def _escribir_cert(path: Path, cert) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _ahora() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def crear_ca(directorio, nombre: str = "UPB-Chain CA", dias: int = DIAS_CA) -> Path:
    """Crea ``ca.key`` y ``ca.crt`` en ``directorio``. No sobrescribe una CA existente."""
    d = Path(directorio)
    d.mkdir(parents=True, exist_ok=True)
    if (d / CA_KEY).exists() or (d / CA_CRT).exists():
        raise FileExistsError(f"Ya existe una CA en {d}; no se sobrescribe")
    key = _nuevo_par()
    sujeto = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nombre)])
    cert = (x509.CertificateBuilder()
            .subject_name(sujeto).issuer_name(sujeto).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_ahora() - datetime.timedelta(days=1))
            .not_valid_after(_ahora() + datetime.timedelta(days=dias))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    _escribir_llave(d / CA_KEY, key)
    _escribir_cert(d / CA_CRT, cert)
    return d / CA_CRT


def emitir_cert_nodo(directorio, node_id: str, hosts: Optional[Iterable[str]] = None,
                     dias: int = DIAS_NODO) -> Path:
    """Emite ``<node_id>.key`` y ``<node_id>.crt`` firmado por la CA de ``directorio``.

    ``CN = node_id``. ``hosts`` (IP o nombres) van como SAN; ``127.0.0.1`` y ``localhost``
    se incluyen siempre. Si el certificado ya existe se reemplaza (rotación).
    """
    d = Path(directorio)
    if not node_id or not node_id.replace("_", "").replace("-", "").replace(".", "").isalnum():
        raise ValueError("node_id inválido (use letras, números, '_', '-' o '.')")
    try:
        ca_key = serialization.load_pem_private_key((d / CA_KEY).read_bytes(), password=None)
        ca_cert = x509.load_pem_x509_certificate((d / CA_CRT).read_bytes())
    except FileNotFoundError:
        raise FileNotFoundError(f"No hay CA en {d}: ejecutar scripts/crear_ca.py primero") from None
    sans = [x509.DNSName(node_id), x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    for h in hosts or []:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(h)))
        except ValueError:
            sans.append(x509.DNSName(h))
    key = _nuevo_par()
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id)]))
            .issuer_name(ca_cert.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_ahora() - datetime.timedelta(days=1))
            .not_valid_after(_ahora() + datetime.timedelta(days=dias))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            # El mismo certificado sirve como servidor y como cliente (TLS mutuo).
            .add_extension(x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    _escribir_llave(d / f"{node_id}.key", key)
    _escribir_cert(d / f"{node_id}.crt", cert)
    return d / f"{node_id}.crt"
