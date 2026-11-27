"""Auditoría de seguridad: superficie P2P sin autenticar (``P2P_TLS=off`` por defecto).

1. ``_recv_framed`` (``blockchain/network/node.py``): si el primer byte es ``{`` usa el
   protocolo legado y acumula hasta encontrar ``\\n`` SIN tope; ``_MAX_PAYLOAD`` solo
   se aplica al protocolo con prefijo de longitud. Cualquiera en la LAN puede mandar
   cientos de MB sin salto de línea y agotar la RAM de la RPi (además ``rest += chunk``
   es cuadrático). Arreglo: cortar con ValueError cuando ``len(rest) > _MAX_PAYLOAD``
   (o eliminar el protocolo legado).

2. ``_handle_handshake`` → ``_learn_peers``: un HANDSHAKE sin autenticar trae una lista
   ``peers`` de tamaño arbitrario y todas se agregan a ``self.peers``; el par además se
   registra con el host/puerto que anuncia (no se comprueba). Es envenenamiento
   de la tabla de pares (base de un eclipse) y crecimiento sin límite de memoria.
   Arreglo: tope de pares conocidos (p. ej. 64) y de direcciones aprendidas por mensaje.
"""
import json
import socket
import threading

import pytest

from blockchain.core.block import GENESIS_HASH
from blockchain.network.node import MSG_HANDSHAKE, P2PNode

HOST = "127.0.0.1"


def _par_de_sockets():
    a, b = socket.socketpair()
    a.settimeout(5)
    b.settimeout(5)
    return a, b


@pytest.mark.xfail(strict=True, reason="el protocolo legado (JSON + newline) ignora _MAX_PAYLOAD")
def test_protocolo_legado_respeta_el_limite_de_tamano():
    nodo = P2PNode("a", HOST, 0)          # sin start(): solo el framing
    nodo._MAX_PAYLOAD = 1_000             # límite pequeño para que el test sea rápido
    lector, escritor = _par_de_sockets()
    mensaje = (json.dumps({"type": "PING", "relleno": "x" * 20_000}) + "\n").encode("utf-8")

    def enviar():
        try:
            escritor.sendall(mensaje)
        except OSError:
            pass                          # tras el arreglo el lector puede cortar antes

    hilo = threading.Thread(target=enviar, daemon=True)
    hilo.start()
    try:
        with pytest.raises(ValueError):
            nodo._recv_framed(lector)     # hoy devuelve el dict de 20 KB (> 1 KB)
    finally:
        lector.close()
        escritor.close()
        hilo.join(timeout=5)


@pytest.mark.xfail(strict=True, reason="un HANDSHAKE sin autenticar agrega pares sin límite")
def test_handshake_no_autenticado_no_inunda_la_tabla_de_pares():
    nodo = P2PNode("a", HOST, 0)
    conn, otro = _par_de_sockets()
    falsos = [f"10.66.{i // 250}.{i % 250}:8001" for i in range(2_000)]
    mensaje = {
        "type": MSG_HANDSHAKE, "id": "auditoria-1", "node_id": "intruso",
        "host": "10.66.255.1", "port": 8001, "genesis_hash": GENESIS_HASH,
        "consensus": "pow", "height": 0, "work": 0, "peers": falsos,
    }
    try:
        nodo._dispatch(mensaje, conn)
    finally:
        conn.close()
        otro.close()
    # Hoy: 2001 pares (las 2000 direcciones inventadas + el host que anunció el intruso).
    assert len(nodo.peers) <= 64, f"{len(nodo.peers)} pares tras un solo HANDSHAKE"
