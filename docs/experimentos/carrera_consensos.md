# Carrera de consensos: PoW vs PBFT (P1-1)

> **Medido en un portátil de desarrollo, red en proceso (loopback), 4 nodos en un mismo intérprete de Python. NO son mediciones en Raspberry Pi ni en LAN** (esas son P1-10).

- Fecha: 2026-11-25 14:50 UTC
- Máquina: Windows 11, AMD64, Python 3.12.6
- Carga: 40 TX `DATA_RECORD`, llegadas de Poisson a 10.0 TX/s, semilla 7, nodo de entrada al azar (misma carga en ambos modos)
- PoW: 4 mineros, dificultad fija 14 bits, minan solo con TXs pendientes. PBFT: 4 réplicas (f = 1), el primario propone cada ≥ 0,05 s si hay TXs.
- Latencia = desde que la TX entra al mempool de un nodo hasta que está en la cadena de los 4 nodos. En PoW es la primera inclusión (1 confirmación, reversible); en PBFT es final.
- `tps` = TX confirmadas / (última confirmación − primer envío) con ESTA carga ofrecida; no es la capacidad máxima (si un modo da cerca de la tasa ofrecida, está limitado por la carga).
- `cpu_proceso_s` = CPU de todo el proceso (los 4 nodos juntos). `mensajes_p2p` = mensajes enviados por los 4 nodos durante la carga.
- `cadenas_iguales` = misma punta en los 4 nodos al terminar (tras forzar una sincronización). En PoW puede ser False por un empate: dos puntas con el mismo trabajo, cada nodo conserva la suya hasta el próximo bloque (regla de Nakamoto); ver `alturas_finales`.
- Regenerar: `venv\Scripts\python.exe scripts\experiments\carrera_consensos.py`

| modo | tx_confirmadas | latencia_media_ms | latencia_p50_ms | latencia_p95_ms | latencia_max_ms | tps | bloques | cpu_proceso_s | mensajes_p2p | reorgs | cambios_de_vista | alturas_finales | cadenas_iguales |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| pow | 40 | 4329.6 | 2781.7 | 10922.5 | 11705.7 | 1.14 | 17 | 38.7 | 884 | 10 | 0 | 17/17/17/17 | True |
| pbft | 40 | 77.8 | 77.2 | 116.8 | 174.1 | 12.68 | 28 | 3.83 | 1236 | 0 | 0 | 28/28/28/28 | True |

Detalle por TX en `carrera_consensos.csv`.
