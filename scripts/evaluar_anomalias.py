"""
Evalúa el detector de anomalías (Isolation Forest) contra la heurística fija (P1-6).

Uso:  venv\\Scripts\\python.exe scripts\\evaluar_anomalias.py [--seed 7] [--dias 14]

Entrena SÓLO con el tramo cronológico de entrenamiento (sin etiquetas, como en producción) y
mide en el tramo de prueba. Ningún parámetro se ajusta mirando el tramo de prueba.
Escribe docs/evaluacion_anomalias.md. Los datos son sintéticos (ai/anomaly/dataset.py).
"""
import argparse
import platform
import sys
from pathlib import Path

import numpy as np

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from sklearn.metrics import precision_recall_fscore_support, roc_auc_score  # noqa: E402

from ai.anomaly.dataset import (ATAQUES, dividir_cronologico, extraer_matriz,  # noqa: E402
                                generar_dataset, resumen)
from ai.anomaly.detector import TransactionAnomalyDetector  # noqa: E402


def _metricas(y, pred, score) -> dict:
    p, r, f, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
    auc = float(roc_auc_score(y, score)) if 0 < sum(y) < len(y) else float("nan")
    return {"precision": float(p), "recall": float(r), "f1": float(f), "auc": auc}


def evaluar(seed: int = 7, dias: int = 14, tx_normales_por_dia: int = 300,
            episodios_por_ataque: int = 4, frac_train: float = 0.7) -> dict:
    """Devuelve métricas globales y por tipo de ataque para Isolation Forest y la heurística."""
    regs = generar_dataset(seed, dias, tx_normales_por_dia, episodios_por_ataque)
    X = extraer_matriz(regs)
    (r_tr, X_tr), (r_te, X_te) = dividir_cronologico(regs, X, frac_train)

    det = TransactionAnomalyDetector()
    det.fit_features(X_tr, seed=seed)
    sc_if = det.scores_from_features(X_te)
    pred_if = (det._model.predict(det._scaler.transform(det._matrix(X_te))) == -1).astype(int)
    sc_h = np.array([det._heuristic_score(x) for x in X_te])
    pred_h = (sc_h > det.threshold).astype(int)      # umbral actual del detector (0,6), sin retocar
    y = np.array([r.label for r in r_te])
    tipos = np.array([r.attack for r in r_te])

    def bloque(mask):
        yy = y[mask]
        return {"iforest": _metricas(yy, pred_if[mask], sc_if[mask]),
                "heuristica": _metricas(yy, pred_h[mask], sc_h[mask]),
                "n_ataque": int(yy.sum()), "n_normal": int((yy == 0).sum())}

    res = {"seed": seed, "dias": dias, "frac_train": frac_train,
           "n_train": len(r_tr), "n_test": len(r_te),
           "resumen_train": resumen(r_tr), "resumen_test": resumen(r_te),
           "global": bloque(np.ones(len(y), dtype=bool)), "por_ataque": {}}
    for a in ATAQUES:
        m = (tipos == a) | (y == 0)
        if (tipos == a).sum() > 0:
            res["por_ataque"][a] = bloque(m)
    return res


def _f(x) -> str:
    return "n/d" if x != x else f"{x:.3f}"


def _fila(nombre, b) -> str:
    i, h = b["iforest"], b["heuristica"]
    return (f"| {nombre} | {b['n_ataque']} | {_f(i['precision'])} | {_f(i['recall'])} | {_f(i['f1'])} | {_f(i['auc'])} "
            f"| {_f(h['precision'])} | {_f(h['recall'])} | {_f(h['f1'])} | {_f(h['auc'])} |")


def informe(res: dict) -> str:
    g = res["global"]
    cumple = g["iforest"]["auc"] > 0.85
    L = [
        "# Evaluación de detección de anomalías (P1-6)", "",
        "> Resultados sobre **datos sintéticos** medidos en esta máquina "
        f"({platform.system()} {platform.release()}, Python {platform.python_version()}). "
        "No son mediciones de campo ni de la Raspberry Pi.", "",
        "Generado por `scripts/evaluar_anomalias.py`; regenerar con "
        f"`venv\\Scripts\\python.exe scripts\\evaluar_anomalias.py --seed {res['seed']} --dias {res['dias']}`.", "",
        "## Protocolo", "",
        f"- Semilla: **{res['seed']}** (generador y bosque). Días simulados: {res['dias']}.",
        f"- Split cronológico {int(res['frac_train'] * 100)}/{int((1 - res['frac_train']) * 100)}: "
        f"entrenamiento **{res['n_train']}** TX, prueba **{res['n_test']}** TX.",
        f"- Entrenamiento (sin etiquetas, con ataques mezclados como en producción): {res['resumen_train']}.",
        f"- Prueba: {res['resumen_test']}.",
        "- Isolation Forest: 100 árboles, `contamination=0.05` (valor por defecto, no ajustado), "
        "9 características (5 por TX + 4 de contexto en ventana de 60 s).",
        "- Heurística: reglas fijas del detector antiguo (payload > 10000, fee > 100, hora < 5), "
        "umbral 0,6 (el actual); su AUC usa su puntaje continuo. Sólo ve las 5 características base.",
        "- Los hiperparámetros del modelo no se ajustaron con el tramo de prueba. Transparencia: tras la "
        "primera corrida el generador se modificó una vez (los ataques eran ~23 % del entrenamiento; se "
        "acortaron las ráfagas y se estratificaron los episodios en el tiempo) para que el tráfico sea "
        "plausible; el generador no se retocó después.", "",
        "## Resultados (tramo de prueba)", "",
        "Para cada ataque, el conjunto es ese ataque + todo el tráfico normal de prueba.", "",
        "| Conjunto | n ataque | IF prec. | IF recall | IF F1 | IF AUC | Heur. prec. | Heur. recall | Heur. F1 | Heur. AUC |",
        "|---|---|---|---|---|---|---|---|---|---|",
        _fila("**Global**", g),
    ]
    for a, b in res["por_ataque"].items():
        L.append(_fila(a, b))
    L += ["", "## Lectura", ""]
    if cumple:
        L.append(f"El AUC global de Isolation Forest es {_f(g['iforest']['auc'])} (> 0,85) en este conjunto sintético "
                 f"(semilla {res['seed']}).")
    else:
        L.append(f"El AUC global de Isolation Forest es {_f(g['iforest']['auc'])}: **no alcanza** el objetivo > 0,85 "
                 "de OE-4 en este conjunto.")
    L += ["",
          "Limitaciones: el tráfico normal y los ataques son supuestos del autor del generador, de modo que el "
          "resultado mide qué tan separables son estos patrones y no el desempeño en la red real. Los ataques "
          "que sólo difieren en una dimensión débil (p. ej. `odd_hour`, porque el tráfico normal incluye ~1 % "
          "de madrugada legítima) son más difíciles para un detector no supervisado. La validación con tráfico "
          "real de UPB queda pendiente."]
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--dias", type=int, default=14)
    ap.add_argument("--salida", default=str(RAIZ / "docs" / "evaluacion_anomalias.md"))
    a = ap.parse_args()
    res = evaluar(seed=a.seed, dias=a.dias)
    texto = informe(res)
    Path(a.salida).write_text(texto, encoding="utf-8")
    print(texto)
    print(f"Escrito en {a.salida}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
