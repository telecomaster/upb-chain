# Experimentos reproducibles

Todo lo de esta carpeta lo regenera `scripts/experiments/run_all.py` con semillas fijas
(semilla base 7; donde hay varianza se repite con 5 semillas y se reporta media ± desviación
estándar muestral).

```powershell
venv\Scripts\python.exe scripts\experiments\run_all.py            # corrida completa (~25 min, casi todo la carrera)
venv\Scripts\python.exe scripts\experiments\run_all.py --rapido   # tamaños mínimos, segundos (CI/tests)
venv\Scripts\python.exe scripts\experiments\run_all.py --solo retarget
venv\Scripts\python.exe scripts\experiments\run_all.py --salida <dir> --semillas 5
```

`--rapido` omite la carrera de consensos (4 nodos, ~25 s) salvo con `--solo carrera`.

> **Máquina de la corrida versionada aquí** (`maquina.json`, capturada automáticamente):
> Windows 11, AMD64, `AMD64 Family 23 Model 1 Stepping 1, AuthenticAMD`, 12 núcleos lógicos,
> Python 3.12.6. Son números de una laptop/PC de desarrollo con carga de fondo.
>
> **Las cifras de Raspberry Pi salen únicamente de `scripts/bench_rpi.py`, ejecutado por el
> dueño de las RPi** (`docs/benchmark_hardware.md`). Nada de lo de aquí es una medición de las Pi.

| Tabla / figura | Experimento | Script | Comando |
| --- | --- | --- | --- |
| `datos/merkle_prueba.csv`, `figuras/merkle_prueba.png` | Pasos y tiempo de verificación de la prueba Merkle según TXs por bloque | `run_all.py` (`merkle`) | `run_all.py --solo merkle` |
| `datos/pow_curva.csv`, `datos/pow_curva_crudo.csv`, `figuras/pow_curva.png` | Intentos y tiempo de minado PoW por dificultad, 10 repeticiones (media ± std) | `run_all.py` (`pow_curva`) | `run_all.py --solo pow_curva` |
| `datos/retarget_convergencia.csv`, `datos/retarget_detalle.csv`, `figuras/retarget_convergencia.png` | Convergencia del reajuste de dificultad (P2-5) con tiempos de bloque **simulados** (exponenciales, 5 semillas; hash rate x16 en la época 6 y ÷8 en la 12) | `run_all.py` (`retarget`) | `run_all.py --solo retarget` |
| `datos/anomalias_global.csv`, `datos/anomalias_crudo.csv`, `figuras/anomalias_global.png` | Isolation Forest vs heurística (P1-6), datos sintéticos, 5 semillas | `run_all.py` + `scripts/evaluar_anomalias.py` | `run_all.py --solo anomalias` |
| `datos/carrera_resumen.csv`, `datos/carrera_semillas.csv`, `figuras/carrera_consensos.png` | PoW vs PBFT, 4 nodos en un proceso, 40 TX, 5 semillas de carga | `run_all.py` + `scripts/experiments/carrera_consensos.py` | `run_all.py --solo carrera` |
| `carrera_consensos.csv/.md` (anteriores) | Una sola corrida de P1-1 | `scripts/experiments/carrera_consensos.py` | ver su docstring |
| `../evaluacion_anomalias.md` | Informe de P1-6 (una semilla) | `scripts/evaluar_anomalias.py` | ver su docstring |

Notas de lectura:

- `retarget` no mina: simula tiempos de bloque y aplica el `retarget_step` real de la cadena.
  Muestra el comportamiento del algoritmo, no el de un hardware.
- La carrera de consensos corre los 4 nodos en un solo intérprete (GIL) y por loopback. En PoW los
  4 mineros compiten con dificultad fija de 14 bits y generan bifurcaciones y reorganizaciones, por
  eso su latencia y su desviación son muy altas; en PBFT la inclusión ya es final. El TPS es con la
  carga ofrecida (10 TX/s), no la capacidad máxima.
- El Isolation Forest usa la configuración por defecto sin ajustar; la heurística fija tiene
  precisión y recall 0 con el umbral actual (0,6) en estos datos sintéticos. No es tráfico real.
- Los tiempos (minado, CPU, verificación) varían entre corridas y máquinas; los conteos
  de intentos siguen una distribución geométrica con media 2^bits.
