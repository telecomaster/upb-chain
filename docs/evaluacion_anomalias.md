# Evaluación de detección de anomalías (P1-6)

> Resultados sobre **datos sintéticos** medidos en esta máquina (Windows 11, Python 3.12.6). No son mediciones de campo ni de la Raspberry Pi.

Generado por `scripts/evaluar_anomalias.py`; regenerar con `venv\Scripts\python.exe scripts\evaluar_anomalias.py --seed 7 --dias 14`.

## Protocolo

- Semilla: **7** (generador y bosque). Días simulados: 14.
- Split cronológico 70/30: entrenamiento **3158** TX, prueba **1379** TX.
- Entrenamiento (sin etiquetas, con ataques mezclados como en producción): {'normal': 2907, 'huge_payload': 12, 'replay': 46, 'new_address_flood': 59, 'odd_hour': 24, 'spam_burst': 99, 'fee_outlier': 11}.
- Prueba: {'normal': 1293, 'fee_outlier': 13, 'huge_payload': 3, 'odd_hour': 6, 'replay': 16, 'new_address_flood': 15, 'spam_burst': 33}.
- Isolation Forest: 100 árboles, `contamination=0.05` (valor por defecto, no ajustado), 9 características (5 por TX + 4 de contexto en ventana de 60 s).
- Heurística: reglas fijas del detector antiguo (payload > 10000, fee > 100, hora < 5), umbral 0,6 (el actual); su AUC usa su puntaje continuo. Sólo ve las 5 características base.
- Los hiperparámetros del modelo no se ajustaron con el tramo de prueba. Transparencia: tras la primera corrida el generador se modificó una vez (los ataques eran ~23 % del entrenamiento; se acortaron las ráfagas y se estratificaron los episodios en el tiempo) para que el tráfico sea plausible; el generador no se retocó después.

## Resultados (tramo de prueba)

Para cada ataque, el conjunto es ese ataque + todo el tráfico normal de prueba.

| Conjunto | n ataque | IF prec. | IF recall | IF F1 | IF AUC | Heur. prec. | Heur. recall | Heur. F1 | Heur. AUC |
|---|---|---|---|---|---|---|---|---|---|
| **Global** | 86 | 0.965 | 0.640 | 0.769 | 0.964 | 0.000 | 0.000 | 0.000 | 0.624 |
| spam_burst | 33 | 0.929 | 0.788 | 0.852 | 0.986 | 0.000 | 0.000 | 0.000 | 0.495 |
| fee_outlier | 13 | 0.778 | 0.538 | 0.636 | 0.998 | 0.000 | 0.000 | 0.000 | 1.000 |
| odd_hour | 6 | 0.000 | 0.000 | 0.000 | 0.733 | 0.000 | 0.000 | 0.000 | 0.995 |
| huge_payload | 3 | 0.000 | 0.000 | 0.000 | 0.979 | 0.000 | 0.000 | 0.000 | 1.000 |
| replay | 16 | 0.778 | 0.438 | 0.560 | 0.941 | 0.000 | 0.000 | 0.000 | 0.495 |
| new_address_flood | 15 | 0.882 | 1.000 | 0.938 | 1.000 | 0.000 | 0.000 | 0.000 | 0.495 |

## Lectura

El AUC global de Isolation Forest es 0.964 (> 0,85) en este conjunto sintético (semilla 7).

Limitaciones: el tráfico normal y los ataques son supuestos del autor del generador, de modo que el resultado mide qué tan separables son estos patrones y no el desempeño en la red real. Los ataques que sólo difieren en una dimensión débil (p. ej. `odd_hour`, porque el tráfico normal incluye ~1 % de madrugada legítima) son más difíciles para un detector no supervisado. La validación con tráfico real de UPB queda pendiente.
