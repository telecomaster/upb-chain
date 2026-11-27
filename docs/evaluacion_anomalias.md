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
| **Global** | 86 | 0.952 | 0.698 | 0.805 | 0.962 | 0.000 | 0.000 | 0.000 | 0.624 |
| spam_burst | 33 | 0.903 | 0.848 | 0.875 | 0.987 | 0.000 | 0.000 | 0.000 | 0.495 |
| fee_outlier | 13 | 0.769 | 0.769 | 0.769 | 0.998 | 0.000 | 0.000 | 0.000 | 1.000 |
| odd_hour | 6 | 0.000 | 0.000 | 0.000 | 0.687 | 0.000 | 0.000 | 0.000 | 0.995 |
| huge_payload | 3 | 0.000 | 0.000 | 0.000 | 0.978 | 0.000 | 0.000 | 0.000 | 1.000 |
| replay | 16 | 0.700 | 0.438 | 0.538 | 0.942 | 0.000 | 0.000 | 0.000 | 0.495 |
| new_address_flood | 15 | 0.833 | 1.000 | 0.909 | 1.000 | 0.000 | 0.000 | 0.000 | 0.495 |

## Lectura

El AUC global de Isolation Forest es 0.962 (> 0,85) en este conjunto sintético (semilla 7).

Limitaciones: el tráfico normal y los ataques son supuestos del autor del generador, de modo que el resultado mide qué tan separables son estos patrones y no el desempeño en la red real. Los ataques que sólo difieren en una dimensión débil (p. ej. `odd_hour`, porque el tráfico normal incluye ~1 % de madrugada legítima) son más difíciles para un detector no supervisado. La validación con tráfico real de UPB queda pendiente.

## Explicación por característica (Idea 7)

Cada alerta `ANOMALY` y cada `anomaly` de `POST /transactions` lleva `explicacion` (lista ordenada) y `resumen` (frase en español). Los campos anteriores no cambian.

**Método (oclusión).** Para cada una de las 9 características se reemplaza su valor por la **mediana del entrenamiento** y se recalcula el score crudo del bosque (`-score_samples`). `contribucion = score(x) - score(x con la característica neutralizada)`: positiva empuja hacia anómalo, negativa hacia normal. Es determinista (el bosque entrenado es fijo) y cuesta una sola llamada vectorizada de 10 filas. Cada elemento: `{caracteristica, valor, referencia (mediana), contribucion, rango_normal [Q1, Q3]}`, en unidades originales. Limitación: la oclusión es univariada; si dos características están correlacionadas (p. ej. `new_senders_recent` e `is_new_sender`) se reparten o se tapan la contribución. Los modelos guardados antes de esta versión no traen la mediana y usan la media del escalador.

**Sin modelo entrenado (heurística).** `explicacion` lista cada regla: `{caracteristica, valor, referencia = umbral, contribucion = puntos que suma, regla}`.

**Anomalías de bloque y demás alertas del monitor.** `BlockAnomalyDetector` es heurístico: su `explicacion` usa el mismo formato por regla (`desvio_intervalo`, `bloque_vacio`, `n_transactions`) y el mismo `resumen`. Las alertas del `SecurityMonitor` que no son `ANOMALY` (tasa de TX, salto de dificultad, reorg, huérfano, comisión alta, bloque inválido, par desconocido, PBFT) llevan en `metadata` `explicacion = [{regla, valor, umbral, operador, cumple}]` y un `resumen`; los campos y el mensaje previos no cambian.

**Evaluación sintética (semilla 7, 14 días, entrenamiento 70 %, tramo de prueba).** Fracción de TX de ataque en que la característica inyectada queda primera / en el top-3 (80 TX; `odd_hour` se omite):

| Ataque | n | #1 | top-3 |
|---|---|---|---|
| fee_outlier (`fee`) | 13 | 13 | 13 |
| huge_payload (`payload_size`) | 3 | 3 | 3 |
| replay (`payload_repeats`) | 16 | 15 | 15 |
| new_address_flood (`new_senders_recent`) | 15 | 1 | 15 |
| spam_burst (`sender_rate`) | 33 | 32 | 32 |
| **Total** | 80 | 64 (80,0 %) | 78 (97,5 %) |

Cuando una característica correlacionada (p. ej. `is_new_sender` en `new_address_flood`) absorbe la primera posición, la inyectada suele seguir en el top-3. Resultado sobre datos sintéticos, no sobre tráfico real.

## Detección federada entre nodos (Idea 6) — datos sintéticos

> **Sintético**, semilla **7**, 14 días, medido en esta máquina (Windows 11, Python 3.12.6). No es tráfico real ni medición en la Raspberry Pi. Regenerar con `venv\Scripts\python.exe scripts\evaluar_federado.py --seed 7 --dias 14` (o `scripts\evaluar_anomalias.py`, que lo incluye).

**Qué se comparte.** Cada nodo publica un resumen de su entrenamiento (mediana y MAD de 5 características en espacio log1p y el número de muestras; ~0,5 KB), nunca TX ni el modelo. La referencia federada es la media ponderada por muestras de las medianas y la varianza agrupada de las escalas; el puntaje federado es el máximo z robusto (|x − mediana| / max(1,4826·escala, 0,5)); una TX se marca si z ≥ 6 (umbral y piso fijados antes de medir, no ajustados).

**Protocolo.** El flujo etiquetado se reparte entre 4 nodos por hash del emisor (55/25/15/5 % del tráfico): cada nodo ve otra mezcla y los ataques de un solo emisor caen en un único nodo. Cada nodo calcula sus características con su propio contexto y entrena su Isolation Forest sólo con su 70 % cronológico inicial, sin etiquetas. Se mide en el 30 % final. Columnas: precisión / recall / F1 / AUC (AUC sólo donde hay puntaje continuo; el combinado es local O federado).

Entrenamiento: {'normal': 2907, 'huge_payload': 12, 'replay': 46, 'new_address_flood': 59, 'odd_hour': 24, 'spam_burst': 99, 'fee_outlier': 11}. Prueba: {'normal': 1293, 'fee_outlier': 13, 'huge_payload': 3, 'odd_hour': 6, 'replay': 16, 'new_address_flood': 15, 'spam_burst': 33}.

| Nodo | TX entren. (ataques) | TX prueba (ataques) | Local IF | Federado | Combinado |
|---|---|---|---|---|---|
| 0 | 1933 (142) | 833 (37) | 1.000 / 0.703 / 0.825 / 0.978 | 1.000 / 0.243 / 0.391 / 0.973 | 1.000 / 0.811 / 0.896 / n/d |
| 1 | 893 (50) | 404 (46) | 0.973 / 0.783 / 0.867 / 0.941 | 1.000 / 0.348 / 0.516 / 0.894 | 0.973 / 0.783 / 0.867 / n/d |
| 2 | 152 (12) | 62 (1) | 1.000 / 1.000 / 1.000 / 1.000 | 0.000 / 0.000 / 0.000 / 0.975 | 1.000 / 1.000 / 1.000 / n/d |
| 3 | 180 (47) | 80 (2) | 0.250 / 0.500 / 0.333 / 0.744 | 1.000 / 0.500 / 0.667 / 0.702 | 0.250 / 0.500 / 0.333 / n/d |
| **Todos** | | 1379 (86) | 0.941 / 0.744 / 0.831 / 0.951 | 1.000 / 0.302 / 0.464 / 0.924 | 0.944 / 0.791 / 0.861 / n/d |

**Lectura.** En conjunto el combinado cambia el F1 en +0.030 respecto del IF local (0.831 -> 0.861); el federado solo tiene recall bajo (0.302) con precisión alta. La diferencia no es uniforme por nodo y los nodos 2 y 3 tienen 1 y 2 ataques de prueba: sus cifras son anecdóticas, no evidencia. 
El puntaje federado sólo ve magnitudes (tamaño, comisión, ráfagas, repeticiones, direcciones nuevas); no detecta `odd_hour` ni usa el tipo de TX.

Limitaciones: el reparto por hash del emisor es un supuesto del autor; con 4 nodos simulados en un solo proceso no hay latencia, pérdida ni pares maliciosos; el resumen revela estadísticos agregados del tráfico de cada nodo (no TX); sin TLS la identidad del par es declarada y un par puede aparentar varios nodos (la alerta k-de-n sólo es fiable con `P2P_TLS=on` y lista blanca). La alerta `FEDERATED_ANOMALY` (k nodos distintos marcan la misma TX/emisor) está cubierta por pruebas funcionales, no medida aquí.
