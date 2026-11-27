# UPB-Chain: Blockchain Académica con Inteligencia Artificial

**Universidad Privada Boliviana: Carrera de Ingeniería en Inteligencia Artificial**
**Carrera de Electrónica y Telecomunicaciones: mención: Redes y Ciberseguridad**

---

## Resumen del Proyecto

UPB-Chain es una red blockchain permisionada implementada sobre dos nodos **Raspberry Pi 5** (16 GB RAM, 128 GB almacenamiento), diseñada como plataforma de investigación y demostración académica. Integra:

- Blockchain con consenso dual: **Proof of Work adaptativo** y **PBFT**
- **Smart contracts** para certificación y verificación de credenciales académicas
- Capa de **Inteligencia Artificial**: detección de anomalías (Isolation Forest) y analítica de cadena
- Módulo de **ciberseguridad**: simulación de ataques (51 %, Sybil, doble gasto) y monitoreo en tiempo real
- **Dashboard web** interactivo con API REST completa, billetera en el navegador y kiosco verificador
- Cuentas con saldo y nonce, tokens PUPB, insignias, votación y una **máquina virtual** para contratos de estudiantes
- Credenciales verificables (W3C VC con `did:web`), pruebas Merkle y almacenamiento SQLite (`chain.db`)

---

## Arquitectura General

```
┌─────────────────────────────────┐    ┌─────────────────────────────────┐
│   Raspberry Pi 5 — Nodo 1       │    │   Raspberry Pi 5 — Nodo 2       │
│   (Primario PBFT)               │    │   (Secundario PBFT)             │
│                                 │    │                                 │
│  ┌─────────────────────────┐    │    │  ┌─────────────────────────┐    │
│  │   API REST (FastAPI)    │    │    │  │   API REST (FastAPI)    │    │
│  │   Puerto 8000           │    │    │  │   Puerto 8010           │    │
│  └────────────┬────────────┘    │    │  └────────────┬────────────┘    │
│               │                 │    │               │                 │
│  ┌────────────▼────────────┐    │    │  ┌────────────▼────────────┐    │
│  │   Blockchain Core       │◄───┼────┼──►   Blockchain Core       │    │
│  │   Chain + Mempool       │    │P2P │  │   Chain + Mempool       │    │
│  └────────────┬────────────┘    │8001│  └────────────┬────────────┘    │
│               │                 │8011│               │                 │
│  ┌────────────▼────────────┐    │    │  ┌────────────▼────────────┐    │
│  │   Consenso (PoW/PBFT)  │    │    │  │   Consenso (PoW/PBFT)  │    │
│  └─────────────────────────┘    │    │  └─────────────────────────┘    │
│                                 │    │                                 │
│  ┌─────────────────────────┐    │    │  ┌─────────────────────────┐    │
│  │   IA: Anomalías         │    │    │  │   IA: Analítica         │    │
│  │   Isolation Forest      │    │    │  │   Estadísticas          │    │
│  └─────────────────────────┘    │    │  └─────────────────────────┘    │
│                                 │    │                                 │
│  ┌─────────────────────────┐    │    │  ┌─────────────────────────┐    │
│  │   Seguridad             │    │    │  │   Seguridad             │    │
│  │   Monitor + Crypto      │    │    │  │   Attack Simulator      │    │
│  └─────────────────────────┘    │    │  └─────────────────────────┘    │
└─────────────────────────────────┘    └─────────────────────────────────┘
              │                                        │
              └─────────────── LAN / WiFi ─────────────┘
                              192.168.x.x
```

---


---

## Inicio rápido

Requisitos: Python 3.12 (también probado con 3.11, el de Raspberry Pi OS Bookworm). En Windows usar siempre `venv\Scripts\python.exe` (el `python` del sistema
suele ser el alias de la Store); en Linux/RPi, `venv/bin/python`.

```powershell
python -m venv venv
venv\Scripts\python.exe -m pip install -r requirements.txt
copy .env.example .env      # Linux: cp .env.example .env
```

### Un nodo

```powershell
venv\Scripts\python.exe -m uvicorn api.app:app --host 127.0.0.1 --port 8000
```

Dashboard en `http://127.0.0.1:8000/`, Swagger en `/docs`, estado en `/health`; el P2P escucha en
8001. No hay recarga automática (agregar `--reload` solo al desarrollar). Los endpoints de
administración (minar, pares, emisores, entrenar IA) aceptan solo peticiones desde la propia
máquina, o la cabecera `X-API-Key` si se define `ADMIN_API_KEY`.

```powershell
curl -X POST http://127.0.0.1:8000/blocks/mine      # mina un bloque (PoW)
curl http://127.0.0.1:8000/health
```

Demo sin servidor: `venv\Scripts\python.exe scripts\demo.py`.

### Dos nodos locales

Cada nodo necesita su propio `DATA_DIR` y puertos. El segundo nodo (PowerShell), con el primero
ya en marcha:

```powershell
$env:NODE_ID="node_2"; $env:DATA_DIR="data/node_2"; $env:NODE_PORT="8011"; $env:PEERS="127.0.0.1:8001"
venv\Scripts\python.exe -m uvicorn api.app:app --host 127.0.0.1 --port 8010
```

Mine un bloque en uno y compruebe con `GET /blocks` que el otro lo recibe (`GET /network` muestra
los pares). Solo un proceso puede ocupar los puertos 8000/8001 a la vez.

### Red de 4 nodos con Docker Compose

```bash
export ADMIN_API_KEY=cambiame            # PowerShell: $env:ADMIN_API_KEY="cambiame"
docker compose up --build -d
for p in 8000 8010 8020 8030; do curl http://127.0.0.1:$p/health; echo; done
docker compose down                      # conserva las cadenas; con -v las borra
```

Detalles (llave de la autoridad, métricas, Grafana) en [Docker y CI](#docker-y-ci).

### Actualizar un nodo existente

Las reglas de consenso cambiaron (dificultad en bits, nonces por cuenta, almacenamiento SQLite), así
que una cadena creada antes **no es compatible**: en cada nodo, detenerlo, borrar su `DATA_DIR`
(p. ej. `data/chain`) y volver a arrancarlo; se resincroniza desde los pares o empieza desde el
génesis. Un `chain.json` antiguo se importa una vez a `chain.db` solo si su contenido sigue siendo
válido con las reglas actuales. Además, el historial de git de este repositorio se reescribió:
quien tenga un clon previo debe ejecutar `git fetch && git reset --hard origin/main` (cuidado: descarta
cambios locales no guardados).

---

## Mapa de funciones

| Tema | Qué incluye | Documentación |
|---|---|---|
| Consenso y red | PoW con dificultad en bits y reajuste; PBFT firmado (`CONSENSUS=pow\|pbft`); P2P con TLS mutuo opcional | [`docs/arquitectura.md`](docs/arquitectura.md) |
| Credenciales | Emisión, verificación, revocación, historial, QR y página `/verify/{id}`, kiosco `/kiosco`, prueba Merkle de una TX (`/tx/{id}/proof`), divulgación selectiva | [`docs/arquitectura.md`](docs/arquitectura.md) §3 |
| Credenciales verificables | Exportación W3C VC con `did:web` y verificador independiente `scripts/verificar_vc.py` | [`docs/credenciales_vc.md`](docs/credenciales_vc.md) |
| Cuentas, tokens y votación | Saldo y nonce por cuenta, tokens PUPB, insignias, catálogo y canjes, elecciones | [`docs/contratos.md`](docs/contratos.md) |
| Contratos de estudiantes | Máquina virtual de pila con ensamblador `.upbasm` (`scripts/upbasm.py`) y gas en PUPB | [`docs/vm.md`](docs/vm.md) |
| IA | Isolation Forest + heurísticas, alertas explicables, analítica de cadena | [`docs/evaluacion_anomalias.md`](docs/evaluacion_anomalias.md) |
| Seguridad | Monitor con alertas, simulador de ataques, laboratorio de ataques en vivo con nodos reales | [`docs/laboratorio_ataques.md`](docs/laboratorio_ataques.md) |
| Experimentos del paper | Arnés reproducible `scripts/experiments/run_all.py` (tablas CSV y figuras) | [`docs/experimentos/README.md`](docs/experimentos/README.md) |
| Hardware | Benchmark para la Raspberry Pi 5 (`scripts/bench_rpi.py`) | [`docs/benchmark_hardware.md`](docs/benchmark_hardware.md) |
| Billetera | Firma en el navegador en `/billetera` (la llave no sale del cliente) | Dashboard |
| Operación | Métricas Prometheus `/metrics`, Docker Compose, CI | [Docker y CI](#docker-y-ci) |
| Estado del trabajo | Trabajos, prioridades y criterios de aceptación | [`docs/ROADMAP.md`](docs/ROADMAP.md) |

Las cifras de rendimiento (hash rate, TPS, latencias, AUC) están únicamente en esos documentos, con su
etiqueta de si fueron medidas (y en qué máquina) o estimadas; las de Raspberry Pi solo las aporta
quien ejecuta `scripts/bench_rpi.py` en las Pi.

---

## Notas de seguridad

- **Solo para una red de confianza (LAN).** No exponer la API a Internet: el endpoint
  `POST /wallet/generate` devuelve la llave privada por diseño didáctico.
- Los endpoints que reciben `private_key_hex` (emitir, revocar, transferir, etc.) firman en el servidor;
  es solo educativo y está **en desuso**. La firma real va en el navegador (`/billetera`).
- Los endpoints de administración exigen `ADMIN_API_KEY` (cabecera `X-API-Key`; 401 si falta o es
  incorrecta). Sin llave solo aceptan loopback (403 desde otra IP) y además exigen `Host` y `Origin`
  locales (defensa contra CSRF y DNS rebinding desde el navegador del nodo). **Recomendado definir
  `ADMIN_API_KEY` en las Raspberry Pi.** Con Docker la llave es obligatoria.
- `/metrics` sigue la misma regla salvo con `METRICS_PUBLIC=true` (solo red interna).
- **Nunca versionar** `data/`, `.env`, `venv/`, wallets ni llaves (`authority.json`, llaves de réplica
  PBFT, `ca.key`).

---

## Estructura del Proyecto

```
upb-chain/
├── config.py                  # Settings (pydantic-settings): todas las variables de entorno
├── blockchain/
│   ├── core/                  # block, chain, transaction, wallet, state, storage (SQLite)
│   ├── consensus/             # proof_of_work.py, pbft.py
│   ├── network/               # node.py (P2P, sincronización), tls.py
│   ├── contracts/             # accounts, credential, tokens, badges, voting, programs (vm), registry
│   └── vm/                    # máquina de pila y ensamblador .upbasm
├── ai/
│   ├── anomaly/detector.py    # Isolation Forest + heurísticas
│   └── analytics/chain_stats.py
├── security/                  # crypto_utils, monitor, hardening, pki, attacks/ (simulador, laboratorio, eclipse)
├── api/app.py                 # fábrica create_app(settings); `app = create_app()` para uvicorn
├── dashboard/                 # templates/index.html, billetera, kiosco y estáticos
├── contratos_estudiantes/     # ejemplos .upbasm
├── monitoring/                # Prometheus y Grafana
├── scripts/                   # setup_rpi.sh, demo.py, llaves y CA, bench_rpi.py, laboratorio_ataques.py,
│                              #   evaluar_anomalias.py, exportar_cadena.py, experiments/run_all.py, ...
├── tests/                     # suite pytest; los nodos de prueba se arman con tests.helpers.make_app
└── docs/                      # arquitectura, ROADMAP y guías por tema
```

---

## Instalación en Raspberry Pi 5

**Despliegue previsto (4 réplicas PBFT, 2 por Pi, mTLS): seguir la guía paso a paso
[`docs/despliegue_rpi.md`](docs/despliegue_rpi.md)** (genera llaves y certificados con
`scripts/preparar_despliegue_rpi.py`, instala con `setup_rpi.sh` y comprueba con
`scripts/verificar_red.py`).

Dos nodos PoW sencillos, uno por Pi:

```bash
# En el Nodo 1 (RPi5 #1), desde la raíz del repo clonado en ~/upb-chain:
sudo bash scripts/setup_rpi.sh node_1 8000 8001

# En el Nodo 2 (RPi5 #2):
sudo bash scripts/setup_rpi.sh node_2 8000 8001
# Luego agregar el par: PEERS=<IP_NODO1>:8001 en nodes/node_2.env y reiniciar upbchain-node_2
```

El script crea el venv, `nodes/<node_id>.env`, un servicio systemd `upbchain-<node_id>` (un solo
worker por nodo; se puede ejecutar varias veces para varias réplicas por Pi) y reglas de firewall.
Toda la configuración está en ese archivo (ver `.env.example`, comentado variable por variable):
dificultad en bits (`MINING_DIFFICULTY`, 16 por defecto), `CONSENSUS`, `P2P_TLS`, `ADMIN_API_KEY`,
`PUBLIC_BASE_URL` (URL de los QR), `DID_WEB_DOMAIN`, `TX_RATE_LIMIT`, `REVALIDATE_ON_START`,
`SNAPSHOT_INTERVAL`, `METRICS_PUBLIC`, `CORS_ORIGINS`.

---

## Uso de la API

El listado completo y los esquemas están en Swagger (`/docs`). Los principales:

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| GET | `/`, `/billetera`, `/kiosco` | Dashboard, billetera en el navegador, kiosco verificador |
| GET | `/health`, `/stats`, `/network`, `/events` | Estado, estadísticas, pares, eventos en tiempo real |
| GET | `/blocks`, `/blocks/{index}` | Bloques (paginado) |
| POST | `/blocks/mine` | Minar un bloque (admin; 409 en modo PBFT) |
| GET | `/consensus` | Modo de consenso; en PBFT vista, primario y réplicas |
| POST | `/transactions` | Enviar una TX firmada |
| GET | `/tx/{tx_id}/proof` | Prueba Merkle de inclusión |
| GET | `/accounts/{address}` | Saldo y nonce |
| POST | `/credentials/issuers` | Registrar emisor (admin; requiere la llave de la autoridad) |
| POST | `/credentials/issue`, `/credentials/revoke` | Emitir y revocar credencial |
| GET | `/credentials/verify/{id}`, `/verify/{id}`, `/credentials/{id}/qr` | Verificar (JSON o HTML) y QR |
| GET | `/credentials/{id}/vc`, `/.well-known/did.json` | Credencial verificable W3C y DID del emisor |
| GET | `/contracts`, `/contracts/vm` | Contratos registrados y programas de la VM |
| GET | `/ai/analytics`, `/ai/anomaly/stats` | Analítica y estado del detector |
| POST | `/ai/train` | Entrenar el detector (admin) |
| GET | `/security/alerts`, `/security/attack-simulation`, `/security/hardening` | Seguridad |
| GET | `/metrics` | Métricas Prometheus (ver [Docker y CI](#docker-y-ci)) |

### Ejemplo: Emitir credencial académica

Los ejemplos usan `private_key_hex` por brevedad; ese camino de firma en el servidor es educativo y
está en desuso (ver Notas de seguridad).

```bash
# 1. Generar wallet para la universidad
curl -X POST http://localhost:8000/wallet/generate

# 2. Registrar emisor (admin; el nodo necesita data/keys/authority.json,
#    se crea con scripts/crear_llave_autoridad.py; su dirección debe ser la del génesis,
#    GENESIS_AUTHORITY_ADDRESS: una llave nueva responde 503 hasta cambiarla ahí y en GENESIS_HASH)
curl -X POST http://localhost:8000/credentials/issuers \
  -H "Content-Type: application/json" \
  -d '{"issuer_address": "UPB...", "institution_code": "UPB"}'

# 3. Emitir credencial
curl -X POST http://localhost:8000/credentials/issue \
  -H "Content-Type: application/json" \
  -d '{
    "issuer_address": "UPB...",
    "student_address": "UPBestudiante...",
    "private_key_hex": "...",
    "credential_data": {
      "student_name": "Ana Lucía Mamani",
      "degree": "Licenciatura en IA",
      "program": "Ingeniería en IA",
      "issue_date": "2025-11-28",
      "credential_type": "DEGREE",
      "grade": 91.5
    }
  }'

# 4. Minar un bloque (PoW) y verificar (cualquiera puede verificar con el ID)
curl -X POST http://localhost:8000/blocks/mine
curl http://localhost:8000/credentials/verify/<credential_id>
```

---

## Ejecutar Tests

```powershell
venv\Scripts\python.exe -m pytest tests -q                       # toda la suite
venv\Scripts\python.exe -m pytest tests\test_security.py -q      # un archivo
```

Estado actual: 793 pruebas pasan y 1 está marcada `xfail`, en unos 3,5 minutos (3 min 28 s en un portátil de desarrollo; la cifra cambia al aterrizar trabajos nuevos).

Los tests que necesitan su propio nodo lo arman con `tests.helpers.make_app(tmp_path, ...)`
(`create_app` + `Settings`), así que varias apps conviven en un mismo proceso.

---

## Docker y CI

Red de 4 nodos (`node_1`..`node_4`) con `docker-compose.yml`. Las APIs quedan en `127.0.0.1`
puertos 8000, 8010, 8020 y 8030. `ADMIN_API_KEY` es obligatoria (desde el host las peticiones
no son loopback, así que los endpoints de administración exigen la cabecera `X-API-Key`).

```bash
export ADMIN_API_KEY=cambiame            # PowerShell: $env:ADMIN_API_KEY="cambiame"
docker compose up --build -d
for p in 8000 8010 8020 8030; do curl http://127.0.0.1:$p/health; echo; done
docker compose down          # conserva las cadenas (volúmenes); con -v las borra
```

### Docker Compose con PBFT (4 réplicas)

`docker-compose.yml` corre PoW. Para PBFT (4 réplicas, tolera 1 falla) se añade el override
`docker-compose.pbft.yml`, que fija `CONSENSUS=pbft`, `PBFT_REPLICAS_FILE` y la
`PBFT_KEY_FILE` de cada nodo (montadas en solo lectura desde `./data/pbft/`, que git ignora):

```bash
venv\Scripts\python.exe scripts\preparar_pbft_compose.py        # una vez: llaves + lista en data/pbft/
export ADMIN_API_KEY=cambiame                                   # PowerShell: $env:ADMIN_API_KEY="cambiame"
docker compose -f docker-compose.yml -f docker-compose.pbft.yml up --build -d
docker compose -f docker-compose.yml -f docker-compose.pbft.yml down
```

El script no sobrescribe llaves existentes (para regenerarlas, borrar `data/pbft/`; si los
volúmenes ya tienen una cadena PoW, usar `down -v`). Para TLS mutuo, generar certificados
(ver [TLS mutuo](#tls-mutuo-y-lista-blanca-de-nodos-p2-6)) y descomentar en el override
`P2P_TLS`, `P2P_TLS_DIR` y los montajes `./data/tls/<nodo>:/tls:ro`. Nota: el archivo se valida
en las pruebas (YAML y llaves), pero `docker compose` no se ha ejecutado con él.

Para registrar emisores, descomentar en `node_1` el montaje de `./data/keys/authority.json`
(solo lectura). Sin esa llave, el registro de emisores responde 503.

### Métricas (Prometheus y Grafana)

Cada nodo expone `GET /metrics` en formato de texto de Prometheus (`prometheus_client`, un
registro por app). Los valores se leen al momento del scrape: `upb_chain_height`,
`upb_chain_work` (float64: pierde precisión sobre 2^53), `upb_difficulty_bits`,
`upb_mempool_size`, `upb_peers_total`/`upb_peers_active`, `upb_mining_in_progress`,
`upb_last_block_age_seconds`, `upb_alerts{severity}`, `upb_node_info{node_id}` y los
contadores `upb_blocks_mined_total` y `upb_tx_total{result=admitted|rejected|rate_limited}`
(solo TX recibidas por la API, no las llegadas por P2P).

Acceso: `/metrics` revela la topología, así que por defecto sigue la regla de los endpoints de
administración (loopback sin llave, o cabecera `X-API-Key` si hay `ADMIN_API_KEY`). Con
`METRICS_PUBLIC=true` queda abierto; `docker-compose.yml` lo activa porque Prometheus raspa
desde otro contenedor, y los puertos del host siguen enlazados a `127.0.0.1`.

```bash
ADMIN_API_KEY=cambiame docker compose --profile monitoring up --build -d
# Prometheus: http://127.0.0.1:9090 · Grafana: http://127.0.0.1:3000 (admin / $GRAFANA_PASSWORD, por defecto admin)
```

El tablero "UPB-Chain" (altura por nodo, dificultad, mempool, pares, alertas, edad del último
bloque y bloques minados por minuto) se provisiona desde `monitoring/grafana/`.

La integración continua (`.github/workflows/tests.yml`) corre `python -m pytest tests -q` en
Ubuntu con Python 3.11 y 3.12 en cada push y pull request a `main`.

---

## Componentes Académicos Clave

### Mecanismos de Consenso

| | Proof of Work | PBFT |
|--|--|--|
| **Tipo** | No permisionado | Permisionado |
| **Finalidad** | Probabilística | Inmediata |
| **Tolerancia** | 51% hash rate | f < n/3 nodos |
| **Consumo** | Alto (CPU) | Bajo |
| **Ideal para** | Redes públicas | Redes institucionales |

**Dificultad en bits (P2-5).** La dificultad del PoW es el número de bits iniciales en cero del
hash (`int(hash, 16) < 2**(256 - bits)`); el trabajo de un bloque es `2**bits` y la red elige la
cadena con mayor `Σ 2**bits`. `MINING_DIFFICULTY` está en **bits** (por defecto 16; antes contaba
ceros hexadecimales: un 4 antiguo equivale a 16). Cada 10 bloques la dificultad se reajusta en
`round(log2(esperado/real))` bits (máx. ±2) hacia 10 s por bloque. Es un cambio de consenso: al
actualizar, todos los nodos deben borrar su `DATA_DIR` (p. ej. `data/chain`). Detalle en
[`docs/arquitectura.md`](docs/arquitectura.md) §2.4.

**PBFT real (P1-1).** `CONSENSUS=pbft` (toda la red en el mismo modo) reemplaza el minado por
PBFT de Castro & Liskov con 4 réplicas firmadas (f = 1): el primario `replicas[v mod 4]` propone un
bloque cuando hay TXs, los demás lo validan y lo confirman con PRE-PREPARE / PREPARE / COMMIT; cada
bloque se guarda con su certificado (2f+1 COMMIT firmados), que los nodos verifican al sincronizar.
Si el primario cae, VIEW-CHANGE / NEW-VIEW elige al siguiente. Preparación, una vez por réplica:

```bash
venv\Scripts\python.exe scripts\crear_llave_replica.py --id node_1 --address 192.168.1.100:8001 --llave data/keys/pbft_node_1.json
# … node_2, node_3, node_4; copiar pbft_replicas.json (sin reordenar) a todos los nodos
# .env de cada réplica: CONSENSUS=pbft, NODE_ID=node_1, PBFT_KEY_FILE=data/keys/pbft_node_1.json
```

En modo pbft `POST /blocks/mine` responde 409; `GET /consensus` muestra vista, primario y réplicas.
Despliegue previsto: 2 réplicas por Raspberry Pi, así que **si cae un Pi caen 2 réplicas y PBFT se
detiene** (sin perder seguridad). Comparación con PoW (medida en un portátil, no en las Pi):
`scripts/experiments/carrera_consensos.py` → [`docs/experimentos/carrera_consensos.md`](docs/experimentos/carrera_consensos.md).
Protocolo, variante, qué se omite y diagramas en [`docs/arquitectura.md`](docs/arquitectura.md) §4.

### Criptografía Implementada

- **ECDSA secp256k1**: firma y verificación (mismo estándar que Bitcoin)
- **SHA-256**: hashing de bloques y transacciones (SHA3-256 y BLAKE2b solo en `benchmark_crypto`)
- **Merkle Tree**: integridad eficiente de conjuntos de transacciones

### Inteligencia Artificial

- **Isolation Forest**: detección no supervisada de transacciones anómalas
- **Estadísticas de cadena**: TPS, distribución de TXs, salud de red
- **Análisis de credenciales**: tendencias de emisión, revocación y verificación

### TLS mutuo y lista blanca de nodos (P2-6)

Por defecto el P2P va en claro (`P2P_TLS=off`); en las Raspberry Pi se recomienda `P2P_TLS=on`.
Detalle del diseño en `docs/arquitectura.md` §4.8.

```powershell
# 1. Una vez, en la máquina del administrador: la CA de la red (data/tls/ca.key + ca.crt)
venv\Scripts\python.exe scripts\crear_ca.py
# 2. Un certificado por nodo (CN = NODE_ID; --host = IP o nombre con el que lo alcanzan)
venv\Scripts\python.exe scripts\emitir_cert_nodo.py node_1 --host 192.168.1.100
```

Copiar a cada nodo SOLO `ca.crt`, `<node_id>.crt` y `<node_id>.key` (nunca `ca.key`) a su
`P2P_TLS_DIR` (por defecto `data/tls/`; `data/` no se versiona) y poner en su `.env`:
`P2P_TLS=on` y, opcionalmente, `P2P_ALLOWLIST=node_1,node_2,...` (en `CONSENSUS=pbft` el valor por
defecto son los ids de las réplicas; en PoW vacía acepta cualquier certificado de la CA). Si faltan
los archivos el nodo no arranca.

- **Rotar el certificado de un nodo:** volver a ejecutar `emitir_cert_nodo.py <node_id>` (dura 365 días
  por defecto, `--dias`), copiar los archivos nuevos y reiniciar ese nodo; el CN no cambia.
- **Revocar un nodo:** quitar su id de `P2P_ALLOWLIST` en los demás nodos y reiniciarlos. No hay listas
  de revocación (CRL/OCSP): están fuera de alcance. Sin TLS la lista blanca solo genera alertas, porque
  el `node_id` anunciado no está autenticado.
- **Docker Compose:** montar por nodo su carpeta de certificados, p. ej. en `node_1`:
  `volumes: ["./data/tls/node_1:/tls:ro"]` con `P2P_TLS: "on"` y `P2P_TLS_DIR: /tls` (esa carpeta debe
  contener `ca.crt`, `node_1.crt` y `node_1.key`; emitir con `--host node_1`).

### Seguridad

- TLS 1.3 mutuo y lista blanca de nodos en el P2P (opcional, ver arriba)
- Simulación educativa de ataques del 51 %, Sybil y doble gasto
- Monitor en tiempo real con niveles INFO / WARNING / CRITICAL
- Límite de TX por minuto y emisor al mempool (`TX_RATE_LIMIT`, por defecto 100; 429 y alerta; política local, no de consenso)
- Detección de reorganizaciones de cadena

---

## Hardware: Raspberry Pi 5

| Especificación | Valor |
|---|---|
| CPU | ARM Cortex-A76 quad-core 2.4 GHz |
| RAM | 16 GB LPDDR4X |
| Almacenamiento | 128 GB microSD |
| Red | Gigabit Ethernet + WiFi 6 |
| Hash rate SHA-256 (estimado, sin medir) | ~500,000 – 800,000 H/s; resultados de las Pi: pendientes de medir, ver [`docs/benchmark_hardware.md`](docs/benchmark_hardware.md) |
| Tiempo de bloque | objetivo 10 s; la dificultad en bits se reajusta sola (P2-5) |

---

## Posibles Extensiones del Proyecto

1. **Zero-Knowledge Proofs** — verificar credenciales sin revelar datos personales
2. **Sharding** — dividir la cadena en particiones para mayor escalabilidad
3. **Layer 2** — canales de estado para micro-transacciones instantáneas
4. **Interoperabilidad** — puente con Ethereum o Hyperledger Fabric
5. **Federated Learning** — entrenar el detector de anomalías sin compartir datos de TXs

---

## Autores

Proyecto desarrollado en la carrera de **Ingeniería en Inteligencia Artificial**
Universidad Privada Boliviana (UPB) — 2025

---

## Licencia

MIT License — Uso académico y de investigación.
