"""
Laboratorio de ataques en vivo (Idea 1 del ROADMAP): un nodo malicioso real contra nodos honestos.

Levanta los nodos EN ESTE PROCESO (sockets reales en 127.0.0.1, datos en un directorio
temporal que se borra), corre el escenario y muestra una narración en español seguida del
resultado en JSON. Ver docs/laboratorio_ataques.md.

Uso (desde la raíz del repo):
    venv\\Scripts\\python.exe scripts\\laboratorio_ataques.py --escenario doble_gasto --consenso pow
    venv\\Scripts\\python.exe scripts\\laboratorio_ataques.py --escenario doble_gasto --consenso pbft
    venv\\Scripts\\python.exe scripts\\laboratorio_ataques.py --escenario reorg --intentos 4
    venv\\Scripts\\python.exe scripts\\laboratorio_ataques.py --escenario sybil --consenso pbft
    venv\\Scripts\\python.exe scripts\\laboratorio_ataques.py --escenario equivocacion --consenso pbft

Solo para el laboratorio: nunca escucha fuera del loopback ni contacta nodos ajenos.
"""
import argparse
import atexit
import json
import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))


def _aislar_entorno() -> None:
    """``api.app`` crea un nodo con la configuración del entorno al importarse: se le da un
    directorio temporal para no abrir la cadena ni la llave de autoridad del desarrollador."""
    if "api.app" in sys.modules:
        return
    tmp = tempfile.mkdtemp(prefix="lab-ataques-")
    os.environ["DATA_DIR"] = tmp
    os.environ["AUTHORITY_KEY_FILE"] = os.path.join(tmp, "sin_llave.json")
    atexit.register(shutil.rmtree, tmp, ignore_errors=True)


def construir_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Laboratorio de ataques en vivo (solo loopback).")
    p.add_argument("--escenario", required=True,
                   choices=["doble_gasto", "reorg", "sybil", "equivocacion"])
    p.add_argument("--consenso", default="pow", choices=["pow", "pbft"])
    p.add_argument("--semilla", type=int, default=1)
    p.add_argument("--cuota", type=int, default=90,
                   help="doble_gasto pow: %% de los intentos de hash del atacante (0-100)")
    p.add_argument("--confirmaciones", type=int, default=1,
                   help="doble_gasto/reorg pow: confirmaciones que exige el comercio")
    p.add_argument("--cuotas", default="10,30,45,60,75,90",
                   help="reorg: cuotas a barrer, separadas por comas")
    p.add_argument("--intentos", type=int, default=4, help="reorg: corridas por cuota")
    p.add_argument("--identidades", type=int, default=5, help="sybil: identidades falsas")
    p.add_argument("--bits", type=int, default=10, help="pow: dificultad en bits")
    p.add_argument("--direccion", help="dirección UPB del estudiante: si completa un escenario "
                   "premiable (P1-12), se imprime un recibo para que el docente lo reclame")
    p.add_argument("--json", action="store_true", help="imprimir solo el JSON")
    p.add_argument("--verboso", action="store_true", help="mostrar los logs de los nodos")
    return p


def opciones_de(args) -> dict:
    if args.escenario == "doble_gasto":
        return ({"cuota": args.cuota, "confirmaciones": args.confirmaciones, "bits": args.bits}
                if args.consenso == "pow" else {})
    if args.escenario == "reorg":
        return {"cuotas": tuple(int(c) for c in args.cuotas.split(",") if c.strip()),
                "intentos": args.intentos, "confirmaciones": args.confirmaciones, "bits": args.bits}
    if args.escenario == "sybil":
        return {"identidades": args.identidades}
    return {"bits": args.bits} if args.consenso == "pow" else {}


def main(argv=None) -> dict:
    args = construir_parser().parse_args(argv)
    _aislar_entorno()
    from security.attacks.laboratorio import ejecutar
    if not args.verboso:
        logging.getLogger("upb_chain").setLevel(logging.CRITICAL + 1)
    resultado = ejecutar(args.escenario, args.consenso, args.semilla, **opciones_de(args))
    if args.direccion:
        from security.attacks.recompensas import construir_recibo
        resultado["recibo"] = construir_recibo(resultado, args.direccion)
    if not args.json:
        print(f"== Laboratorio de ataques: {args.escenario} ({args.consenso}) ==")
        for linea in resultado["narrativa"]:
            print(f"- {linea}")
        veredicto = "TUVO ÉXITO" if resultado["exito_ataque"] else "FALLÓ"
        print(f"Veredicto: el ataque {veredicto}.")
        if args.direccion:
            print("Recibo para el docente (campo 'recibo', POST /laboratorio/recompensas)."
                  if resultado["recibo"] else
                  "Sin recibo: el escenario/consenso no da recompensa o el logro no se cumplió.")
        print()
    print(json.dumps(resultado, ensure_ascii=False, indent=2))
    return resultado


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):  # con salida redirigida en Windows sería cp1252
        sys.stdout.reconfigure(encoding="utf-8")
    main()
