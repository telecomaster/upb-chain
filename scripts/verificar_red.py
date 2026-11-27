"""
Verificación previa de una red UPB-Chain ya desplegada (P1-10, docs/despliegue_rpi.md).

Recibe las URL base de las APIs de todos los nodos (réplicas) y comprueba, solo leyendo
(``GET``), que forman una red coherente:

  1. ``/health`` responde en cada nodo.
  2. Mismo hash del bloque génesis en todos (y, si se corre desde el repo, igual al del código).
  3. Mismo ``CONSENSUS`` (pow/pbft) en todos.
  4. Mismo ``P2P_TLS`` (on/off) en todos.
  5. Alturas convergentes (diferencia máxima ``--tolerancia-altura``, con reintentos).
  6. Conectividad P2P: cada nodo con al menos ``--pares`` pares activos (por defecto N-1).
  7. PBFT: mismo conjunto de réplicas (ids, direcciones y llaves públicas), mismo n/f/quorum,
     cada nodo es la réplica que dice ser, misma vista y primario, y al menos 2f+1 réplicas
     activas vistas desde cada nodo.
  8. Desfase de reloj entre nodos (``timestamp`` de ``/health`` corregido por la mitad del RTT)
     menor que ``--tolerancia-reloj`` segundos: un reloj desviado rompe los certificados TLS y
     los plazos de cambio de vista de PBFT.
  9. Llave de la autoridad: al menos un nodo informa ``authority_key_loaded`` en ``/health``
     (si ninguno la tiene, mint y alta de emisores devuelven 503): FAIL; WARN si no informan.

Imprime una tabla OK / FAIL / WARN y termina con código 0 solo si no hay ningún FAIL.

Uso (desde la raíz del repo; las URL son las de la API de cada réplica)::

    venv/bin/python scripts/verificar_red.py http://192.168.1.10:8000 http://192.168.1.10:8010 \\
        http://192.168.1.11:8000 http://192.168.1.11:8010 [--api-key CLAVE] [--espera 120]

``--espera SEGUNDOS`` repite la verificación hasta que todo pase (útil justo tras arrancar los
servicios). La llave ``--api-key`` (o la variable ``ADMIN_API_KEY``) se envía como ``X-API-Key``;
los endpoints que lee este script son públicos, así que normalmente no hace falta.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

OK, FAIL, WARN = "OK", "FAIL", "WARN"


@dataclass
class Chequeo:
    nombre: str
    estado: str
    detalle: str


@dataclass
class Muestra:
    """Lo leído de un nodo: respuestas JSON (o None) y desfase de reloj estimado."""
    url: str
    health: Optional[dict] = None
    consenso: Optional[dict] = None
    red: Optional[dict] = None
    genesis: Optional[str] = None
    error: str = ""
    reloj_s: Optional[float] = None     # reloj del nodo menos el local, en segundos


# fetch(url_base, ruta, cabeceras, timeout) -> (código HTTP, JSON); lanza OSError si no hay red.
Fetch = Callable[[str, str, dict, float], Tuple[int, object]]


def fetch_http(base: str, ruta: str, cabeceras: dict, timeout: float) -> Tuple[int, object]:
    """GET con ``urllib`` (solo biblioteca estándar: corre igual en la Pi)."""
    req = urllib.request.Request(base.rstrip("/") + ruta, headers=cabeceras)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, None
    except (urllib.error.URLError, ValueError) as e:
        raise OSError(str(getattr(e, "reason", e))) from None


def _get(fetch: Fetch, url: str, ruta: str, cab: dict, timeout: float) -> Optional[dict]:
    codigo, cuerpo = fetch(url, ruta, cab, timeout)
    return cuerpo if codigo == 200 and isinstance(cuerpo, dict) else None


def leer_nodo(url: str, fetch: Fetch, api_key: str = "", timeout: float = 5.0,
              reloj: Callable[[], float] = time.time) -> Muestra:
    """Lee /health, /consensus, /network y el génesis de un nodo (sin lanzar excepciones)."""
    cab = {"X-API-Key": api_key} if api_key else {}
    m = Muestra(url)
    try:
        t0 = reloj()
        m.health = _get(fetch, url, "/health", cab, timeout)
        t1 = reloj()
        if m.health is None:
            m.error = "/health no respondió 200"
            return m
        ts = m.health.get("timestamp")
        if isinstance(ts, (int, float)):
            m.reloj_s = float(ts) - (t0 + t1) / 2        # compensa la mitad del RTT
        m.consenso = _get(fetch, url, "/consensus", cab, timeout)
        m.red = _get(fetch, url, "/network", cab, timeout)
        m.genesis = m.health.get("genesis_hash")
        if not m.genesis:                                # nodo anterior a /health con génesis
            bl = _get(fetch, url, "/blocks?page=0&size=1", cab, timeout)
            if bl and bl.get("blocks"):
                m.genesis = bl["blocks"][0].get("hash")
    except OSError as e:
        m.error = f"sin conexión: {e}"
    return m


def _uno(valores: Dict[str, object]) -> Tuple[bool, str]:
    """(todos iguales, descripción compacta ``valor: nodos``)."""
    grupos: Dict[str, List[str]] = {}
    for url, v in valores.items():
        grupos.setdefault(json.dumps(v, sort_keys=True), []).append(url)
    if len(grupos) == 1:
        return True, str(next(iter(valores.values())))
    return False, " | ".join(f"{k} -> {', '.join(u)}" for k, u in grupos.items())


def _conjunto_replicas(cons: dict) -> list:
    return sorted((r.get("id"), r.get("address"), r.get("public_key"))
                  for r in cons.get("replicas", []))


def evaluar(muestras: List[Muestra], pares_min: Optional[int] = None, tol_altura: int = 1,
            tol_reloj: float = 2.0, genesis_codigo: Optional[str] = None) -> List[Chequeo]:
    """Convierte las muestras en la lista de chequeos (función pura, fácil de probar)."""
    out: List[Chequeo] = []
    caidos = [m for m in muestras if m.health is None]
    for m in caidos:
        out.append(Chequeo(f"salud {m.url}", FAIL, m.error or "sin respuesta"))
    vivos = [m for m in muestras if m.health is not None]
    if vivos:
        out.append(Chequeo("salud (/health)", OK if not caidos else FAIL,
                           f"{len(vivos)}/{len(muestras)} nodos responden"))
    else:
        return out + [Chequeo("salud (/health)", FAIL, "ningún nodo responde")]

    # génesis
    gen = {m.url: m.genesis for m in vivos}
    if any(v is None for v in gen.values()):
        out.append(Chequeo("génesis", FAIL, "algún nodo no devolvió el hash del génesis"))
    else:
        igual, det = _uno(gen)
        if igual and genesis_codigo and next(iter(gen.values())) != genesis_codigo:
            out.append(Chequeo("génesis", WARN, f"iguales entre sí pero distintos del código "
                               f"local ({genesis_codigo[:12]}...): ¿versiones distintas?"))
        else:
            out.append(Chequeo("génesis", OK if igual else FAIL,
                               (det[:16] + "...") if igual else det))

    # consenso
    modos = {m.url: (m.consenso or {}).get("mode") or m.health.get("consensus") for m in vivos}
    igual, det = _uno(modos)
    out.append(Chequeo("consenso", OK if igual and None not in modos.values() else FAIL, det))
    pbft = all(v == "pbft" for v in modos.values())

    # TLS
    tls = {m.url: m.health.get("p2p_tls") for m in vivos}
    if all(v is None for v in tls.values()):
        out.append(Chequeo("P2P TLS", WARN, "los nodos no informan P2P_TLS (versión antigua)"))
    else:
        igual, det = _uno(tls)
        out.append(Chequeo("P2P TLS", OK if igual and None not in tls.values() else FAIL, det))

    # alturas
    alturas = {m.url: m.health.get("height") for m in vivos}
    h = [a for a in alturas.values() if isinstance(a, int)]
    if len(h) == len(alturas) and max(h) - min(h) <= tol_altura:
        out.append(Chequeo("alturas", OK, f"altura {min(h)}..{max(h)} (tolerancia {tol_altura})"))
    else:
        out.append(Chequeo("alturas", FAIL, f"divergen: {alturas}"))

    # pares P2P
    minimo = len(muestras) - 1 if pares_min is None else pares_min
    mal = []
    for m in vivos:
        act = (m.red or {}).get("active_peers")
        if not isinstance(act, int) or act < minimo:
            mal.append(f"{m.url} ({act} activos)")
    out.append(Chequeo("pares P2P", FAIL if mal else OK,
                       f"sin los {minimo} pares activos: {', '.join(mal)}" if mal
                       else f"todos con >= {minimo} pares activos"))

    # PBFT
    if pbft:
        out += _evaluar_pbft(vivos)
    else:
        out.append(Chequeo("PBFT", OK, "no aplica (modo pow)"))

    # llave de la autoridad (mint/emisores): al menos un nodo debe tenerla cargada
    aut = {m.url: m.health.get("authority_key_loaded") for m in vivos}
    if all(v is None for v in aut.values()):
        out.append(Chequeo("llave de autoridad", WARN,
                           "los nodos no informan authority_key_loaded (versión antigua)"))
    elif any(v is True for v in aut.values()):
        out.append(Chequeo("llave de autoridad", OK,
                           "cargada en " + ", ".join(u for u, v in aut.items() if v is True)))
    else:
        out.append(Chequeo("llave de autoridad", FAIL,
                           "ningún nodo tiene la llave de la autoridad del génesis: mint y alta de "
                           "emisores devolverán 503 (revisar AUTHORITY_KEY_FILE y que la llave "
                           "sea la original)"))

    # reloj
    rel = {m.url: m.reloj_s for m in vivos if m.reloj_s is not None}
    if len(rel) < len(vivos):
        out.append(Chequeo("reloj", WARN, "algún nodo no informa timestamp"))
    else:
        dif = max(rel.values()) - min(rel.values())
        out.append(Chequeo("reloj", OK if dif <= tol_reloj else FAIL,
                           f"desfase máx. entre nodos {dif:.2f} s (tolerancia {tol_reloj} s); "
                           f"respecto a esta máquina {min(rel.values()):+.2f}..{max(rel.values()):+.2f} s"))
    return out


def _evaluar_pbft(vivos: List[Muestra]) -> List[Chequeo]:
    out: List[Chequeo] = []
    cons = {m.url: m.consenso or {} for m in vivos}
    igual, det = _uno({u: _conjunto_replicas(c) for u, c in cons.items()})
    out.append(Chequeo("PBFT: conjunto de réplicas", OK if igual else FAIL,
                       f"{len(next(iter(cons.values())).get('replicas', []))} réplicas idénticas "
                       "(id, dirección, llave pública)" if igual else det))
    igual, det = _uno({u: (c.get("n"), c.get("f"), c.get("quorum")) for u, c in cons.items()})
    out.append(Chequeo("PBFT: n / f / quórum", OK if igual else FAIL, det))
    quien = [u for u, c in cons.items() if not c.get("is_replica")]
    ids = [c.get("replica_id") for c in cons.values()]
    if quien:
        out.append(Chequeo("PBFT: réplica propia", FAIL, f"no son réplica (PBFT_KEY_FILE/NODE_ID): {quien}"))
    elif len(set(ids)) != len(ids):
        out.append(Chequeo("PBFT: réplica propia", FAIL, f"ids repetidos entre URL: {ids}"))
    else:
        out.append(Chequeo("PBFT: réplica propia", OK, f"ids {sorted(ids)}"))
    igual, det = _uno({u: (c.get("view"), c.get("primary")) for u, c in cons.items()})
    out.append(Chequeo("PBFT: vista y primario", OK if igual else WARN,
                       det if igual else f"vistas distintas (¿cambio de vista en curso?): {det}"))
    flojos = []
    for u, c in cons.items():
        activas = sum(1 for r in c.get("replicas", []) if r.get("active"))
        if activas < c.get("quorum", 0):
            flojos.append(f"{u} ve {activas} activas")
    # "activa" = mensaje PBFT reciente: en una red sin TXs no hay tráfico y es normal que sea 1.
    out.append(Chequeo("PBFT: quórum alcanzable", WARN if flojos else OK,
                       f"menos de 2f+1 réplicas con tráfico PBFT reciente: {', '.join(flojos)} "
                       "(normal si la red está ociosa: enviar una TX y repetir)" if flojos
                       else "cada nodo ve al menos 2f+1 réplicas activas"))
    return out


def verificar(urls: List[str], fetch: Fetch = fetch_http, api_key: str = "",
              timeout: float = 5.0, pares_min: Optional[int] = None, tol_altura: int = 1,
              tol_reloj: float = 2.0, reintentos_altura: int = 5, pausa: float = 1.0,
              dormir: Callable[[float], None] = time.sleep,
              genesis_codigo: Optional[str] = None) -> List[Chequeo]:
    """Lee todos los nodos y evalúa. Las alturas se re-muestrean unos segundos hasta converger
    (un bloque en tránsito no es un fallo)."""
    for i in range(max(1, reintentos_altura)):
        muestras = [leer_nodo(u, fetch, api_key, timeout) for u in urls]
        res = evaluar(muestras, pares_min, tol_altura, tol_reloj, genesis_codigo)
        if all(c.estado != FAIL or c.nombre != "alturas" for c in res):
            break
        dormir(pausa)
    return res


def tabla(chequeos: List[Chequeo]) -> str:
    ancho = max(len(c.nombre) for c in chequeos)
    lineas = [f"{'CHEQUEO'.ljust(ancho)}  ESTADO  DETALLE", "-" * (ancho + 40)]
    lineas += [f"{c.nombre.ljust(ancho)}  {c.estado.ljust(6)}  {c.detalle}" for c in chequeos]
    return "\n".join(lineas)


def _genesis_del_codigo() -> Optional[str]:
    try:
        from blockchain.core.block import GENESIS_HASH
        return GENESIS_HASH
    except ImportError:
        return None


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Verifica que una red UPB-Chain desplegada es coherente")
    ap.add_argument("urls", nargs="+", help="URL base de la API de cada nodo, p. ej. http://10.0.0.5:8000")
    ap.add_argument("--api-key", default=os.environ.get("ADMIN_API_KEY", ""),
                    help="X-API-Key (por defecto ADMIN_API_KEY del entorno)")
    ap.add_argument("--pares", type=int, default=None,
                    help="pares activos mínimos por nodo (por defecto N-1)")
    ap.add_argument("--tolerancia-altura", type=int, default=1)
    ap.add_argument("--tolerancia-reloj", type=float, default=2.0, help="segundos")
    ap.add_argument("--timeout", type=float, default=5.0, help="segundos por petición")
    ap.add_argument("--espera", type=float, default=0.0,
                    help="reintentar hasta SEGUNDOS esperando que todo pase (tras arrancar)")
    args = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    limite = time.monotonic() + args.espera
    while True:
        res = verificar(args.urls, api_key=args.api_key, timeout=args.timeout,
                        pares_min=args.pares, tol_altura=args.tolerancia_altura,
                        tol_reloj=args.tolerancia_reloj, genesis_codigo=_genesis_del_codigo())
        if all(c.estado != FAIL for c in res) or time.monotonic() >= limite:
            break
        time.sleep(3.0)
    print(tabla(res))
    fallos = [c for c in res if c.estado == FAIL]
    print(f"\n{'RED LISTA' if not fallos else 'RED CON FALLOS'}: "
          f"{len(res) - len(fallos)} OK/WARN, {len(fallos)} FAIL")
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
