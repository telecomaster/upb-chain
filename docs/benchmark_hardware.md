# Benchmark de hardware (P1-10)

Estado: **las herramientas están listas; las mediciones en Raspberry Pi están pendientes y las
toma el dueño de las RPi.** Las tablas de la Pi 5 siguen vacías a propósito: no se estiman ni se
extrapolan desde el portátil.

## Qué se mide y cómo

`scripts/bench_rpi.py` usa el mismo código que el nodo, sin servidor, sin puertos y con un
`DATA_DIR` temporal (nunca toca `data/`):

| Medida | Cómo |
|---|---|
| Hash rate | hashes/s de `Block.compute_hash` (SHA-256 sobre el JSON del bloque), por lotes durante unos segundos |
| Curva dificultad/tiempo | minado real con `ProofOfWork.mine` de varios bloques por cada dificultad en **bits** (objetivo `2**(256-bits)`); tiempo medio/máximo e intentos medios frente a los esperados (`2**bits`) |
| Temperatura | `vcgencmd measure_temp`; si no existe, `/sys/class/thermal/thermal_zone0/temp`; si no, "no disponible". Se lee antes y después de la carga |
| RAM | `/proc/meminfo` (total y disponible) y `/proc/self/status` (RSS y pico del proceso); solo biblioteca estándar, sin `psutil` |
| TPS | en proceso y en un solo nodo: construir y firmar, admitir al mempool (firma + contratos) y minar, validar y aplicar bloques de hasta 50 TX `TOKEN_TRANSFER`; se reporta cada fase y el total |

Cada informe lleva el equipo (anfitrión, plataforma, CPU, núcleos, Python, fecha UTC): ninguna cifra
se debe citar sin él.

Alcance y límites:

- El TPS es de **un nodo con consenso PoW** y dificultad de minado baja (4 bits), de modo que
  refleja firma ECDSA, validación y SQLite, no el minado. No incluye red P2P ni PBFT: el TPS con
  PBFT de 4 réplicas no se mide aquí (queda para una extensión; la latencia comparada PoW/PBFT en
  una sola máquina está en `scripts/experiments/carrera_consensos.py`).
- La temperatura bajo carga sostenida y el estrangulamiento térmico requieren una corrida larga en
  la Pi; este script toma solo dos lecturas (antes/después).

## Cómo ejecutarlo en la Raspberry Pi

```bash
git pull && venv/bin/python -m pip install -r requirements.txt   # o uv pip install
venv/bin/python scripts/bench_rpi.py --rapido      # prueba de humo (segundos)
venv/bin/python scripts/bench_rpi.py               # medición completa (hasta 18 bits)
```

Los resultados se escriben en `docs/mediciones/bench_<anfitrion>_<perfil>_<fecha>.md` y `.csv`
(cambie el directorio con `--salida`). Recomendaciones: sin otros procesos pesados, con el nodo
detenido, ventilación/disipador en su estado habitual, y repetir la corrida completa 3 veces.
Ejecutarlo en cada Pi y copiar las tablas de abajo (o enviar los `.md`/`.csv`).

### Semilla de 50+ bloques

```bash
venv/bin/python scripts/semilla_bloques.py --data-dir /ruta/a/semilla --bloques 55 --bits 2
```

Crea una cadena con un emisor registrado, credenciales, `TOKEN_MINT` y `TOKEN_TRANSFER`, firmadas
con las reglas reales (nonce = confirmado + 1). Si existe la llave de autoridad del génesis
(`data/keys/authority.json`) se usa; si no, se genera una autoridad local en
`<data-dir>/keys/` y la cadena solo valida en nodos construidos con esa dirección (útil para
bancos de medición, no para unirse a la red). La dificultad inicial es regla de consenso: el nodo
que lea la cadena debe arrancar con `MINING_DIFFICULTY` igual a `--bits`. El script exige
`--data-dir` y nunca escribe en `data/` por su cuenta.

## Cobertura de pruebas

`pytest-cov` está en `requirements.txt` y la configuración en `.coveragerc` (excluye `venv`,
`tests`, `scripts` y `contratos_estudiantes`):

```bash
venv\Scripts\python.exe -m pytest tests -q --cov
```

Medido en el portátil de desarrollo (2026-11-25, 456 pruebas): **90 % de cobertura total**
(6068 sentencias). Módulos por debajo de 80 %: `blockchain/consensus/proof_of_work.py` (66 %),
`security/monitor.py` (70 %) y `security/attacks/eclipse.py` (74 %).

## Resultados en Raspberry Pi 5

**Pendiente: lo mide el dueño de las RPi.**

| Campo | Pi 1 | Pi 2 |
|---|---|---|
| Modelo / SO / Python | pendiente | pendiente |
| Fecha | pendiente | pendiente |
| Hash rate (H/s) | pendiente | pendiente |
| TPS total (TX/s) | pendiente | pendiente |
| TPS firma / admisión / bloques | pendiente | pendiente |
| Temperatura antes / después (°C) | pendiente | pendiente |
| RAM total / pico del proceso (MiB) | pendiente | pendiente |

Curva dificultad/tiempo (pendiente):

| Bits | Tiempo medio (s) Pi 1 | Tiempo medio (s) Pi 2 | Intentos esperados |
|---:|---|---|---:|
| 8 | pendiente | pendiente | 256 |
| 12 | pendiente | pendiente | 4096 |
| 14 | pendiente | pendiente | 16384 |
| 16 | pendiente | pendiente | 65536 |
| 18 | pendiente | pendiente | 262144 |

## Referencia: portátil de desarrollo (NO es una Raspberry Pi)

Salida real de `scripts/bench_rpi.py` (perfil completo) el 2026-11-25 en un portátil/equipo de
escritorio de desarrollo: Windows 11, AMD64 (AuthenticAMD Family 23), 12 núcleos, Python 3.12.6,
16 GiB de RAM. Solo sirve para comprobar que el script funciona y para comparar órdenes de magnitud
en el futuro; **no** representa a la Pi. La temperatura no está disponible en este equipo.

| Hashes | Segundos | Hashes/s |
|---:|---:|---:|
| 292000 | 3.014 | 96877 |

| Bits | Bloques | Tiempo medio (s) | Tiempo máx. (s) | Intentos medios | Intentos esperados |
|---:|---:|---:|---:|---:|---:|
| 8 | 5 | 0.0047 | 0.01 | 406 | 256 |
| 12 | 5 | 0.0282 | 0.0526 | 2502 | 4096 |
| 14 | 5 | 0.2412 | 0.5094 | 21091 | 16384 |
| 16 | 5 | 0.7001 | 2.0474 | 62153 | 65536 |
| 18 | 5 | 3.425 | 6.66 | 303562 | 262144 |

Con solo 5 bloques por punto los tiempos son muy variables (distribución geométrica): por eso se
reportan también los intentos medios frente a `2**bits`.

| Fase del TPS (500 TX en 10 bloques, 4 bits) | Segundos | TX/s |
|---|---:|---:|
| Construir y firmar | 0.911 | 549.1 |
| Admitir al mempool (validación) | 1.545 | 323.7 |
| Minar, validar y aplicar bloques | 0.515 | 970.9 |
| Total | 2.971 | 168.3 |

RAM: proceso 35.3 MiB (pico 35.8 MiB).
