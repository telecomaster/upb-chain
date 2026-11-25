"""
Arnés reproducible del paper (idea 9): regenera tablas (CSV) y figuras de todos los
experimentos que se pueden correr en una laptop, con semillas fijas.

Uso (desde la raíz del repo):
    venv\\Scripts\\python.exe scripts\\experiments\\run_all.py            # corrida completa
    venv\\Scripts\\python.exe scripts\\experiments\\run_all.py --rapido    # tamaños mínimos (CI/tests)
    venv\\Scripts\\python.exe scripts\\experiments\\run_all.py --solo retarget
    opciones: --salida <dir> (por defecto docs/experimentos), --semillas N

Experimentos: merkle, pow_curva, retarget, anomalias, carrera (ver ``EXPERIMENTOS``).

Qué es y qué NO es esto:
- Todo se mide en la máquina donde corre (se registra en ``maquina.json``). NO son
  números de las Raspberry Pi: esos los produce únicamente ``scripts/bench_rpi.py``,
  ejecutado por el dueño de las RPi (``docs/benchmark_hardware.md``).
- Donde hay varianza (minado PoW, carrera de consensos, Isolation Forest) se repite con
  varias semillas y se reporta media ± desviación estándar muestral. ``retarget`` y
  ``merkle`` (salvo los tiempos) son deterministas dada la semilla.
"""
import argparse
import csv
import importlib.util
import json
import logging
import os
import platform
import random
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(RAIZ))

from blockchain.consensus.proof_of_work import ProofOfWork  # noqa: E402
from blockchain.core.block import Block, BlockHeader  # noqa: E402
from blockchain.core.chain import retarget_step  # noqa: E402
from blockchain.core.merkle import build_proof, merkle_root_from_leaves, verify_proof  # noqa: E402

SEMILLA_BASE = 7


def _cargar(ruta: str, nombre: str):
    spec = importlib.util.spec_from_file_location(nombre, RAIZ / ruta)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[nombre] = mod
    spec.loader.exec_module(mod)
    return mod


def media_std(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return None, None
    return statistics.mean(xs), (statistics.stdev(xs) if len(xs) > 1 else 0.0)


def escribir_csv(ruta: Path, filas: list) -> None:
    ruta.parent.mkdir(parents=True, exist_ok=True)
    with open(ruta, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(filas[0]))
        w.writeheader()
        w.writerows(filas)


def _r(x, n=4):
    return None if x is None else round(x, n)


def info_maquina() -> dict:
    cpu = platform.processor() or "n/d"
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as f:
            for linea in f:
                if linea.lower().startswith("model name"):
                    cpu = linea.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    return {"plataforma": platform.platform(), "arquitectura": platform.machine(), "cpu": cpu,
            "nucleos": os.cpu_count() or 0, "python": platform.python_version(),
            "fecha_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")}


# ── Figuras (matplotlib opcional) ────────────────────────────────────────────

def _plt():
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        return plt
    except ImportError:
        return None


def _guardar_fig(plt, fig, ruta: Path) -> str:
    ruta.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(ruta, dpi=110)
    plt.close(fig)
    return ruta.name


# ── Experimentos ─────────────────────────────────────────────────────────────

def exp_merkle(ctx) -> dict:
    """Tamaño de la prueba de inclusión y tiempo de verificación según TXs por bloque."""
    import hashlib
    tamanos = [1, 2, 4, 16, 64] if ctx.rapido else [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024]
    reps = 20 if ctx.rapido else 200
    filas = []
    for n in tamanos:
        hojas = [hashlib.sha256(f"tx-{n}-{i}".encode()).hexdigest() for i in range(n)]
        raiz = merkle_root_from_leaves(hojas)
        idx = random.Random(SEMILLA_BASE + n).randrange(n)
        prueba = build_proof(hojas, idx)
        assert verify_proof(hojas[idx], prueba, raiz)
        t0 = time.perf_counter()
        for _ in range(reps):
            verify_proof(hojas[idx], prueba, raiz)
        t_ver = (time.perf_counter() - t0) / reps
        filas.append({"txs_por_bloque": n, "pasos_prueba": len(prueba),
                      "bytes_prueba_hex": 64 * len(prueba), "verificacion_us": round(t_ver * 1e6, 1)})
    escribir_csv(ctx.datos / "merkle_prueba.csv", filas)
    figs = []
    plt = ctx.plt
    if plt:
        fig, ax = plt.subplots(figsize=(5, 3.2))
        ax.plot([f["txs_por_bloque"] for f in filas], [f["pasos_prueba"] for f in filas], "o-")
        ax.set_xscale("log", base=2)
        ax.set_xlabel("TXs por bloque")
        ax.set_ylabel("pasos de la prueba (hashes)")
        ax.set_title("Prueba Merkle: crecimiento logarítmico")
        figs.append(_guardar_fig(plt, fig, ctx.figuras / "merkle_prueba.png"))
    return {"csv": ["merkle_prueba.csv"], "figuras": figs}


def _bloque(indice: int) -> Block:
    cab = BlockHeader(index=indice, timestamp=1_700_000_000.0 + indice, previous_hash="0" * 64,
                      merkle_root="0" * 64, node_id="exp")
    return Block(header=cab, transactions=[])


def exp_pow_curva(ctx) -> dict:
    """Minado PoW real: intentos y tiempo por dificultad, varias repeticiones (media ± std)."""
    bits_lista = [4, 8, 10] if ctx.rapido else [8, 10, 12, 14, 16, 18]
    reps = 3 if ctx.rapido else 10 * ctx.semillas // 5
    crudo, resumen = [], []
    for bits in bits_lista:
        ints, tiempos = [], []
        for r in range(reps):
            res = ProofOfWork(difficulty=bits).mine(_bloque(10_000 * bits + r), timeout=600.0)
            ints.append(res.attempts)
            tiempos.append(res.time_elapsed)
            crudo.append({"bits": bits, "repeticion": r, "intentos": res.attempts,
                          "tiempo_s": round(res.time_elapsed, 5)})
        mi, si = media_std(ints)
        mt, st = media_std(tiempos)
        resumen.append({"bits": bits, "repeticiones": reps, "intentos_media": round(mi),
                        "intentos_std": round(si), "intentos_esperados": 1 << bits,
                        "tiempo_media_s": _r(mt, 5), "tiempo_std_s": _r(st, 5),
                        "hash_rate_hs": round(mi / mt) if mt else None})
    escribir_csv(ctx.datos / "pow_curva_crudo.csv", crudo)
    escribir_csv(ctx.datos / "pow_curva.csv", resumen)
    figs = []
    plt = ctx.plt
    if plt:
        fig, ax = plt.subplots(figsize=(5, 3.2))
        ax.errorbar([r["bits"] for r in resumen], [r["intentos_media"] for r in resumen],
                    yerr=[r["intentos_std"] for r in resumen], fmt="o-", capsize=3, label="medido (media ± std)")
        ax.plot([r["bits"] for r in resumen], [r["intentos_esperados"] for r in resumen], "--",
                label="esperado 2^bits")
        ax.set_yscale("log")
        ax.set_xlabel("dificultad (bits)")
        ax.set_ylabel("intentos por bloque")
        ax.set_title("Minado PoW (esta máquina)")
        ax.legend()
        figs.append(_guardar_fig(plt, fig, ctx.figuras / "pow_curva.png"))
    return {"csv": ["pow_curva.csv", "pow_curva_crudo.csv"], "figuras": figs}


def exp_retarget(ctx) -> dict:
    """Convergencia del reajuste de dificultad (P2-5) con tiempos de minado SIMULADOS.

    Cada bloque tarda Exp(media = 2^bits / hash_rate) s (semilla fija). El hash rate cambia
    por escalones (x16 en la época 6, ÷8 en la 12). Usa ``retarget_step`` de la cadena real
    con los mismos parámetros por defecto (ventana 10, objetivo 5 s, ±2 bits por época).
    No hay minado real: es el comportamiento del algoritmo, no una medición de hardware.
    """
    ventana, objetivo_ms, paso_max, bits0 = 10, 5000, 2, 16
    epocas = 10 if ctx.rapido else 18
    hr0 = 2 ** 16 / (objetivo_ms / 1000)           # hash rate que da justo el objetivo con 16 bits
    cambios = {6: 16, 12: 1 / 8} if not ctx.rapido else {4: 16}
    semillas = [SEMILLA_BASE + k for k in range(ctx.semillas)]
    por_epoca = {e: [] for e in range(epocas)}
    detalle = []
    for semilla in semillas:
        rng = random.Random(semilla)
        bits, hr = bits0, hr0
        for e in range(epocas):
            hr *= cambios.get(e, 1)
            ts = []
            for b in range(ventana):
                dt = rng.expovariate(1.0) * (2 ** bits / hr)
                ts.append(dt)
            actual_ms = int(round(sum(ts[1:]) * 1000))      # ventana-1 intervalos, como en chain.py
            esperado_ms = objetivo_ms * (ventana - 1)
            detalle.append({"semilla": semilla, "epoca": e, "bits": bits,
                            "hash_rate_rel": round(hr / hr0, 4),
                            "tiempo_medio_bloque_s": round(statistics.mean(ts), 3)})
            por_epoca[e].append((bits, statistics.mean(ts)))
            bits = max(1, min(32, bits + retarget_step(esperado_ms, actual_ms, paso_max)))
    resumen = []
    for e in range(epocas):
        mb, sb = media_std([x[0] for x in por_epoca[e]])
        mt, st = media_std([x[1] for x in por_epoca[e]])
        resumen.append({"epoca": e, "hash_rate_rel": round(cambios_acum(cambios, e), 4),
                        "bits_media": _r(mb, 2), "bits_std": _r(sb, 2),
                        "tiempo_bloque_media_s": _r(mt, 2), "tiempo_bloque_std_s": _r(st, 2),
                        "objetivo_s": objetivo_ms / 1000})
    escribir_csv(ctx.datos / "retarget_convergencia.csv", resumen)
    escribir_csv(ctx.datos / "retarget_detalle.csv", detalle)
    figs = []
    plt = ctx.plt
    if plt:
        fig, (a1, a2) = plt.subplots(2, 1, figsize=(5.5, 5), sharex=True)
        x = [r["epoca"] for r in resumen]
        a1.errorbar(x, [r["bits_media"] for r in resumen], yerr=[r["bits_std"] for r in resumen],
                    fmt="o-", capsize=2)
        a1.set_ylabel("dificultad (bits)")
        a2.errorbar(x, [r["tiempo_bloque_media_s"] for r in resumen],
                    yerr=[r["tiempo_bloque_std_s"] for r in resumen], fmt="o-", capsize=2)
        a2.axhline(objetivo_ms / 1000, color="gray", ls="--", label="objetivo")
        a2.set_ylabel("tiempo medio por bloque (s)")
        a2.set_xlabel("época (10 bloques)")
        a2.legend()
        a1.set_title(f"Reajuste de dificultad, {len(semillas)} semillas (simulado)")
        figs.append(_guardar_fig(plt, fig, ctx.figuras / "retarget_convergencia.png"))
    return {"csv": ["retarget_convergencia.csv", "retarget_detalle.csv"], "figuras": figs}


def cambios_acum(cambios: dict, e: int) -> float:
    f = 1.0
    for k, v in cambios.items():
        if k <= e:
            f *= v
    return f


def exp_anomalias(ctx) -> dict:
    """Isolation Forest vs heurística (P1-6) sobre datos sintéticos, varias semillas."""
    mod = _cargar("scripts/evaluar_anomalias.py", "evaluar_anomalias")
    dias = 3 if ctx.rapido else 14
    semillas = [SEMILLA_BASE + k for k in range(1 if ctx.rapido else ctx.semillas)]
    crudo, por_metodo = [], {"iforest": {}, "heuristica": {}}
    for s in semillas:
        g = mod.evaluar(seed=s, dias=dias)["global"]
        for metodo in ("iforest", "heuristica"):
            fila = {"semilla": s, "metodo": metodo, **{k: round(v, 4) for k, v in g[metodo].items()}}
            crudo.append(fila)
            for k, v in g[metodo].items():
                por_metodo[metodo].setdefault(k, []).append(v)
    resumen = []
    for metodo, mets in por_metodo.items():
        fila = {"metodo": metodo, "semillas": len(semillas), "dias": dias}
        for k, v in mets.items():
            m, sd = media_std([x for x in v if x == x])
            fila[f"{k}_media"], fila[f"{k}_std"] = _r(m), _r(sd)
        resumen.append(fila)
    escribir_csv(ctx.datos / "anomalias_global.csv", resumen)
    escribir_csv(ctx.datos / "anomalias_crudo.csv", crudo)
    figs = []
    plt = ctx.plt
    if plt:
        fig, ax = plt.subplots(figsize=(5, 3.2))
        mets = ["precision", "recall", "f1", "auc"]
        for i, r in enumerate(resumen):
            ax.bar([j + 0.4 * i for j in range(4)], [r[f"{m}_media"] for m in mets], 0.4,
                   yerr=[r[f"{m}_std"] for m in mets], capsize=2, label=r["metodo"])
        ax.set_xticks([j + 0.2 for j in range(4)])
        ax.set_xticklabels(mets)
        ax.set_title(f"Detección de anomalías, {len(semillas)} semillas (datos sintéticos)")
        ax.legend()
        figs.append(_guardar_fig(plt, fig, ctx.figuras / "anomalias_global.png"))
    return {"csv": ["anomalias_global.csv", "anomalias_crudo.csv"], "figuras": figs}


def exp_carrera(ctx) -> dict:
    """PoW vs PBFT con 4 nodos en proceso (P1-1), varias semillas de carga (media ± std)."""
    mod = _cargar("scripts/experiments/carrera_consensos.py", "carrera_consensos")
    for nombre in ("upb_chain", "upb_chain.network", "upb_chain.pbft"):
        logging.getLogger(nombre).setLevel(logging.ERROR)
    if ctx.rapido:
        n_tx, tasa, bits, semillas, lim, conv = 3, 20.0, 4, [SEMILLA_BASE], 30, 0.5
    else:
        n_tx, tasa, bits, semillas, lim, conv = 40, 10.0, 14, \
            [SEMILLA_BASE + k for k in range(ctx.semillas)], 180.0, 10.0
    crudo, acum = [], {"pow": [], "pbft": []}
    for s in semillas:
        for modo in ("pow", "pbft"):
            print(f"  carrera {modo} semilla {s}...", flush=True)
            r, _ = mod.correr(modo, n_tx, tasa, s, bits, limite=lim, convergencia=conv)
            crudo.append({"semilla": s, **r})
            acum[modo].append(r)
    escribir_csv(ctx.datos / "carrera_semillas.csv", crudo)
    resumen = []
    for modo, rs in acum.items():
        fila = {"modo": modo, "semillas": len(rs), "tx_por_corrida": n_tx}
        for k in ("latencia_media_ms", "latencia_p95_ms", "tps", "cpu_proceso_s", "mensajes_p2p", "bloques"):
            m, sd = media_std([r[k] for r in rs])
            fila[f"{k}_media"], fila[f"{k}_std"] = _r(m, 2), _r(sd, 2)
        resumen.append(fila)
    escribir_csv(ctx.datos / "carrera_resumen.csv", resumen)
    figs = []
    plt = ctx.plt
    if plt:
        fig, axes = plt.subplots(1, 3, figsize=(8, 3))
        for ax, k, t in zip(axes, ("latencia_media_ms", "tps", "cpu_proceso_s"),
                            ("latencia media (ms)", "TPS (carga ofrecida)", "CPU del proceso (s)")):
            ax.bar([r["modo"] for r in resumen], [r[f"{k}_media"] for r in resumen],
                   yerr=[r[f"{k}_std"] for r in resumen], capsize=3, color=["#c2410c", "#1d4ed8"])
            ax.set_title(t, fontsize=9)
        fig.suptitle(f"PoW vs PBFT, {len(semillas)} semillas (4 nodos en proceso, esta máquina)", fontsize=9)
        figs.append(_guardar_fig(plt, fig, ctx.figuras / "carrera_consensos.png"))
    return {"csv": ["carrera_resumen.csv", "carrera_semillas.csv"], "figuras": figs}


EXPERIMENTOS = {
    "merkle": exp_merkle, "pow_curva": exp_pow_curva, "retarget": exp_retarget,
    "anomalias": exp_anomalias, "carrera": exp_carrera,
}


class Contexto:
    def __init__(self, salida: Path, rapido: bool, semillas: int):
        self.rapido, self.semillas = rapido, 1 if rapido else semillas
        self.datos, self.figuras = salida / "datos", salida / "figuras"
        self.plt = _plt()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--rapido", action="store_true", help="tamaños mínimos (CI/tests)")
    ap.add_argument("--solo", choices=sorted(EXPERIMENTOS), help="correr un solo experimento")
    ap.add_argument("--salida", default=str(RAIZ / "docs" / "experimentos"))
    ap.add_argument("--semillas", type=int, default=5, help="semillas donde hay varianza (def. 5)")
    a = ap.parse_args(argv)
    salida = Path(a.salida)
    ctx = Contexto(salida, a.rapido, a.semillas)
    if ctx.plt is None:
        print("matplotlib no está instalado: solo se escriben tablas (CSV).")
    # En --rapido la carrera (4 nodos, ~25 s) solo corre si se pide con --solo carrera.
    nombres = [a.solo] if a.solo else [n for n in EXPERIMENTOS if not (a.rapido and n == "carrera")]
    maquina = info_maquina()
    maquina["modo"] = "rapido" if a.rapido else "completo"
    maquina["semillas"] = ctx.semillas
    ctx.datos.mkdir(parents=True, exist_ok=True)
    salidas = {}
    for n in nombres:
        print(f"[{n}]", flush=True)
        t0 = time.perf_counter()
        salidas[n] = EXPERIMENTOS[n](ctx)
        salidas[n]["segundos"] = round(time.perf_counter() - t0, 1)
        print(f"[{n}] listo en {salidas[n]['segundos']} s", flush=True)
    maquina["experimentos"] = salidas
    with open(salida / "maquina.json", "w", encoding="utf-8") as f:
        json.dump(maquina, f, ensure_ascii=False, indent=2)
    print(f"Escrito en {salida}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
