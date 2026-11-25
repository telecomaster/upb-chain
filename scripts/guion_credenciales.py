"""Guion de TAREAS 3.1 contra un nodo en ejecución, por HTTP (P1-4).

Registra un emisor UPB, emite 5 credenciales de estudiantes ficticios, mina,
revoca una, mina de nuevo e imprime la tabla de estados.

Requisitos: nodo LOCAL con la llave de autoridad (``data/keys/authority.json``),
porque ``POST /credentials/issuers`` es de administración. Si el nodo define
``ADMIN_API_KEY``, páselo con ``--admin-key``.

Uso (desde la raíz del repo, con el nodo ya levantado en el puerto 8000)::

    venv\\Scripts\\python.exe scripts\\guion_credenciales.py --base-url http://127.0.0.1:8000
"""
import argparse
import sys
import time

import httpx

ESTUDIANTES = ["Ana Quispe", "Bruno Mamani", "Carla Rojas", "Diego Flores", "Elena Vargas"]


def _ok(r: httpx.Response, que: str) -> dict:
    if r.status_code != 200:
        sys.exit(f"Error en {que}: HTTP {r.status_code} {r.text}")
    return r.json()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base-url", default="http://127.0.0.1:8000")
    ap.add_argument("--admin-key", default="", help="X-API-Key si el nodo define ADMIN_API_KEY")
    args = ap.parse_args()
    headers = {"X-API-Key": args.admin_key} if args.admin_key else {}

    with httpx.Client(base_url=args.base_url.rstrip("/"), timeout=120) as c:
        emisor = _ok(c.post("/wallet/generate"), "wallet emisor")
        _ok(c.post("/credentials/issuers", headers=headers, json={
            "issuer_address": emisor["address"], "institution_code": "UPB"}), "registro de emisor")
        _ok(c.post("/blocks/mine", json={}), "minado del registro")
        print(f"Emisor UPB registrado: {emisor['address']}")

        sello = time.time_ns()
        ids = []
        for nombre in ESTUDIANTES:
            alumno = _ok(c.post("/wallet/generate"), "wallet estudiante")
            r = _ok(c.post("/credentials/issue", json={
                "issuer_address": emisor["address"],
                "student_address": alumno["address"],
                "private_key_hex": emisor["private_key"],
                "credential_data": {
                    "student_name": nombre, "program": "Ingeniería en IA",
                    "degree": f"Licenciatura en IA {sello}", "issue_date": "2026-06-10",
                    "credential_type": "DEGREE", "grade": 90,
                }}), f"emisión para {nombre}")
            ids.append((nombre, r["credential_id"]))
        _ok(c.post("/blocks/mine", json={}), "minado de emisiones")

        revocada = ids[2][1]
        _ok(c.post("/credentials/revoke", json={
            "credential_id": revocada, "revoker_address": emisor["address"],
            "private_key_hex": emisor["private_key"], "reason": "Revocación de prueba"}),
            "revocación")
        _ok(c.post("/blocks/mine", json={}), "minado de la revocación")

        print(f"\n{'Estudiante':<16}{'ID':<34}{'Estado':<10}{'Bloque':<8}Conf.")
        for nombre, cid in ids:
            h = _ok(c.get(f"/credentials/{cid}/history"), "historial")
            print(f"{nombre:<16}{cid:<34}{h['verdict']:<10}{h['block_index']!s:<8}{h['confirmations']}")
        h = _ok(c.get(f"/credentials/{revocada}/history"), "historial")
        print(f"\nRevocada en el bloque {h['revocation_block']}: {h['revocation_reason']}")


if __name__ == "__main__":
    main()
