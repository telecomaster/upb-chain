"""
Contextos TLS para el P2P (P2-6), solo con ``ssl`` de la biblioteca estándar.

- TLS 1.3 como mínimo y ``CERT_REQUIRED`` en AMBOS lados (TLS mutuo): cada extremo presenta un
  certificado firmado por la CA de la red y verifica el del otro contra ``ca.crt``.
- NO se verifica el nombre de host (``check_hostname = False``): los nodos se direccionan por
  IP en una LAN (o por nombres de compose) y la identidad útil es el ``node_id``. En su lugar,
  tras el apretón de manos se compara el CN del certificado del par con la lista blanca
  (``cn_del_par`` + ``P2PNode._autorizado``).
"""
import ssl
from typing import Optional, Tuple


def crear_contextos(ca: str, cert: str, key: str) -> Tuple[ssl.SSLContext, ssl.SSLContext]:
    """(contexto de servidor, contexto de cliente) con el certificado de este nodo."""
    servidor = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cliente = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    for ctx in (servidor, cliente):
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_cert_chain(cert, key)
        ctx.load_verify_locations(cafile=ca)
    cliente.check_hostname = False     # ver el docstring del módulo
    # Sin tickets de sesión TLS 1.3: el servidor los envía DESPUÉS del apretón de manos y, en
    # los canales donde el cliente nunca lee (PBFT, difusiones sin respuesta), dejaban el socket
    # "legible"; ``_Link.viva()`` lo daba por cerrado y se reabría la conexión. Cerrar un socket
    # con datos sin leer manda RST y el par descartaba los mensajes que aún no había leído
    # (pérdida silenciosa de PREPARE/COMMIT). No se usa reanudación de sesión: no hacen falta.
    servidor.num_tickets = 0
    return servidor, cliente


def cn_del_par(sock) -> Optional[str]:
    """CN del certificado (ya verificado por la CA) del par de un ``SSLSocket``; None si no hay."""
    try:
        cert = sock.getpeercert()
    except (ValueError, OSError):
        return None
    for rdn in (cert or {}).get("subject", ()):
        for clave, valor in rdn:
            if clave == "commonName":
                return valor
    return None
