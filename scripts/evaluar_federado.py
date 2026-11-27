"""
Evalúa la detección federada (Idea 6) contra el detector local, con datos SINTÉTICOS.

Uso:  venv\\Scripts\\python.exe scripts\\evaluar_federado.py [--seed 7] [--dias 14]

El mismo flujo etiquetado de `ai/anomaly/dataset.py` se reparte entre 4 nodos simulados por
hash del emisor (55/25/15/5 % del tráfico), de modo que cada uno ve otra mezcla y, por ejemplo,
una ráfaga de un solo emisor cae entera en un nodo. Cada nodo extrae SUS características con
su propio contexto y entrena su Isolation Forest sólo con su tramo de entrenamiento (70 %
cronológico, sin etiquetas). Se comparan, sobre el tramo de prueba de cada nodo:
  - local:      Isolation Forest del propio nodo;
  - federado:   puntaje z robusto contra la referencia agregada de los 4 resúmenes (umbral a priori);
  - combinado:  local O federado (como marca el nodo en producción).
Ningún parámetro se ajusta con el tramo de prueba. La parte de alerta k-de-n no se mide aquí
(cada TX sintética la ve un solo nodo): está cubierta por pruebas funcionales.
"""
import argparse
import hashlib
import platform
import sys
from pathlib import Path

import numpy as np

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from sklearn.metrics import precision_recall_fscore_support, roc_auc_score  # noqa: E402

from ai.anomaly import federated as fed  # noqa: E402
from ai.anomaly.dataset import dividir_cronologico, generar_dataset, resumen  # noqa: E402
from ai.anomaly.detector import ContextoTx, TransactionAnomalyDetector  # noqa: E402

PESOS = [55, 80, 95, 100]     # umbrales acumulados de hash(sender) % 100 -> nodo 0..3


def nodo_de(sender: str) -> int:
    h = int(hashlib.sha256(sender.encode("utf-8")).hexdigest(), 16) % 100
    return next(i for i, t in enumerate(PESOS) if h < t)


def _m(y, pred, score=None) -> dict:
    p, r, f, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
    auc = float(roc_auc_score(y, score)) if score is not None and 0 < sum(y) < len(y) else float("nan")
    return {"p": float(p), "r": float(r), "f1": float(f), "auc": auc}


def evaluar(seed: int = 7, dias: int = 14) -> dict:
    regs = generar_dataset(seed, dias)
    (r_tr, _), (r_te, _) = dividir_cronologico(regs, [0] * len(regs), 0.7)
    nodos = []
    for i in range(4):
        tr = [r for r in r_tr if nodo_de(r.tx["sender"]) == i]
        te = [r for r in r_te if nodo_de(r.tx["sender"]) == i]
        det = TransactionAnomalyDetector()
        ctx = ContextoTx()
        feats = []
        for r in tr:
            feats.append(det.extract_features(r.tx, ctx))
            ctx.observe(r.tx)
        feats_te = []
        for r in te:
            feats_te.append(det.extract_features(r.tx, ctx))
            ctx.observe(r.tx)
        if len(feats) < det.MIN_SAMPLES:
            raise RuntimeError(f"nodo {i}: sólo {len(feats)} TX de entrenamiento")
        det.fit_features(feats, seed=seed)
        nodos.append({"det": det, "tr": tr, "te": te, "X_te": feats_te})
    ref = fed.agregar([n["det"].federated_summary() for n in nodos])

    filas, todo = [], {"y": [], "if": [], "fed": [], "comb": [], "s_if": [], "z": []}
    for i, n in enumerate(nodos):
        det = n["det"]
        y = np.array([r.label for r in n["te"]])
        Xs = det._scaler.transform(det._matrix(n["X_te"]))
        p_if = (det._model.predict(Xs) == -1).astype(int)
        s_if = det.scores_from_features(n["X_te"])
        z = np.array([fed.puntaje(list(x), ref)[0] for x in det._matrix(n["X_te"])])
        p_fed = (z >= fed.Z_UMBRAL).astype(int)
        p_comb = np.maximum(p_if, p_fed)
        filas.append({"nodo": i, "n_train": len(n["tr"]), "ataques_train": sum(r.label for r in n["tr"]),
                      "n_test": len(y), "ataques_test": int(y.sum()),
                      "local": _m(y, p_if, s_if), "federado": _m(y, p_fed, z), "combinado": _m(y, p_comb)})
        for k, v in (("y", y), ("if", p_if), ("fed", p_fed), ("comb", p_comb), ("s_if", s_if), ("z", z)):
            todo[k].extend(v.tolist())
    y = np.array(todo["y"])
    glob = {"local": _m(y, np.array(todo["if"]), np.array(todo["s_if"])),
            "federado": _m(y, np.array(todo["fed"]), np.array(todo["z"])),
            "combinado": _m(y, np.array(todo["comb"])),
            "n_test": len(y), "ataques_test": int(y.sum())}
    return {"seed": seed, "dias": dias, "nodos": filas, "global": glob, "referencia": ref,
            "resumen_train": resumen(r_tr), "resumen_test": resumen(r_te)}


def _f(x) -> str:
    return "n/d" if x != x else f"{x:.3f}"


def _cols(d) -> str:
    return f"{_f(d['p'])} / {_f(d['r'])} / {_f(d['f1'])} / {_f(d['auc'])}"


def seccion(res: dict) -> list:
    """Sección del informe (Markdown) con lo medido."""
    g = res["global"]
    L = ["", "## Detección federada entre nodos (Idea 6) — datos sintéticos", "",
         f"> **Sintético**, semilla **{res['seed']}**, {res['dias']} días, medido en esta máquina "
         f"({platform.system()} {platform.release()}, Python {platform.python_version()}). "
         "No es tráfico real ni medición en la Raspberry Pi. Regenerar con "
         f"`venv\\Scripts\\python.exe scripts\\evaluar_federado.py --seed {res['seed']} --dias {res['dias']}` "
         "(o `scripts\\evaluar_anomalias.py`, que lo incluye).", "",
         "**Qué se comparte.** Cada nodo publica un resumen de su entrenamiento (mediana y MAD de 5 características "
         "en espacio log1p y el número de muestras; ~0,5 KB), nunca TX ni el modelo. La referencia federada es la "
         "media ponderada por muestras de las medianas y la varianza agrupada de las escalas; el puntaje federado es "
         f"el máximo z robusto (|x − mediana| / max(1,4826·escala, 0,5)); una TX se marca si z ≥ {fed.Z_UMBRAL:g} "
         "(umbral y piso fijados antes de medir, no ajustados).", "",
         "**Protocolo.** El flujo etiquetado se reparte entre 4 nodos por hash del emisor (55/25/15/5 % del tráfico): "
         "cada nodo ve otra mezcla y los ataques de un solo emisor caen en un único nodo. Cada nodo calcula sus "
         "características con su propio contexto y entrena su Isolation Forest sólo con su 70 % cronológico inicial, "
         "sin etiquetas. Se mide en el 30 % final. Columnas: precisión / recall / F1 / AUC "
         "(AUC sólo donde hay puntaje continuo; el combinado es local O federado).", "",
         f"Entrenamiento: {res['resumen_train']}. Prueba: {res['resumen_test']}.", "",
         "| Nodo | TX entren. (ataques) | TX prueba (ataques) | Local IF | Federado | Combinado |",
         "|---|---|---|---|---|---|"]
    for n in res["nodos"]:
        L.append(f"| {n['nodo']} | {n['n_train']} ({n['ataques_train']}) | {n['n_test']} ({n['ataques_test']}) | "
                 f"{_cols(n['local'])} | {_cols(n['federado'])} | {_cols(n['combinado'])} |")
    L += [f"| **Todos** | | {g['n_test']} ({g['ataques_test']}) | {_cols(g['local'])} | {_cols(g['federado'])} | "
          f"{_cols(g['combinado'])} |", ""]
    mejor = g["combinado"]["f1"] - g["local"]["f1"]
    L += ["**Lectura.** " + (
        f"En conjunto el combinado cambia el F1 en {mejor:+.3f} respecto del IF local "
        f"({_f(g['local']['f1'])} -> {_f(g['combinado']['f1'])}); el federado solo tiene recall bajo "
        f"({_f(g['federado']['r'])}) con precisión alta. La diferencia no es uniforme por nodo y los nodos 2 y 3 "
        "tienen 1 y 2 ataques de prueba: sus cifras son anecdóticas, no evidencia. "),
        "El puntaje federado sólo ve magnitudes (tamaño, comisión, ráfagas, repeticiones, direcciones nuevas); "
        "no detecta `odd_hour` ni usa el tipo de TX.", "",
        "Limitaciones: el reparto por hash del emisor es un supuesto del autor; con 4 nodos simulados en un solo "
        "proceso no hay latencia, pérdida ni pares maliciosos; el resumen revela estadísticos agregados del "
        "tráfico de cada nodo (no TX); sin TLS la identidad del par es declarada y un par puede aparentar varios "
        "nodos (la alerta k-de-n sólo es fiable con `P2P_TLS=on` y lista blanca). La alerta `FEDERATED_ANOMALY` "
        "(k nodos distintos marcan la misma TX/emisor) está cubierta por pruebas funcionales, no medida aquí."]
    return L


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--dias", type=int, default=14)
    a = ap.parse_args()
    print("\n".join(seccion(evaluar(a.seed, a.dias))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
