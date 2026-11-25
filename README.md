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
- **Dashboard web** interactivo con API REST completa

---

## Arquitectura General

```
┌─────────────────────────────────┐    ┌─────────────────────────────────┐
│   Raspberry Pi 5 — Nodo 1       │    │   Raspberry Pi 5 — Nodo 2       │
│   (Primario PBFT)               │    │   (Secundario PBFT)             │
│                                 │    │                                 │
│  ┌─────────────────────────┐    │    │  ┌─────────────────────────┐    │
│  │   API REST (FastAPI)    │    │    │  │   API REST (FastAPI)    │    │
│  │   Puerto 8000           │    │    │  │   Puerto 8002           │    │
│  └────────────┬────────────┘    │    │  └────────────┬────────────┘    │
│               │                 │    │               │                 │
│  ┌────────────▼────────────┐    │    │  ┌────────────▼────────────┐    │
│  │   Blockchain Core       │◄───┼────┼──►   Blockchain Core       │    │
│  │   Chain + Mempool       │    │P2P │  │   Chain + Mempool       │    │
│  └────────────┬────────────┘    │8001│  └────────────┬────────────┘    │
│               │                 │8003│               │                 │
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

## Estructura del Proyecto

```
blockchain_upb_ia/
├── blockchain/
│   ├── core/
│   │   ├── block.py          # Estructura de bloque + Merkle Tree
│   │   ├── chain.py          # Cadena principal + persistencia + fork resolution
│   │   ├── transaction.py    # Modelo de TX + tipos + constructores
│   │   └── wallet.py         # ECDSA secp256k1 + derivación de direcciones
│   ├── consensus/
│   │   ├── proof_of_work.py  # PoW adaptativo + benchmark RPi5
│   │   └── pbft.py           # PBFT firmado: caso normal, cambio de vista, certificados (P1-1)
│   ├── network/
│   │   └── node.py           # P2P TCP + gossip + heartbeat
│   └── contracts/
│       └── credential.py     # Smart contract de credenciales académicas
├── ai/
│   ├── anomaly/
│   │   └── detector.py       # Isolation Forest + heurísticas
│   └── analytics/
│       └── chain_stats.py    # TPS, distribución TX, salud de red
├── security/
│   ├── crypto_utils.py       # ECDSA, AES-GCM, PBKDF2, benchmark
│   ├── monitor.py            # Monitor en tiempo real + alertas
│   └── attacks/
│       └── simulator.py      # 51%, Sybil, Doble Gasto (educativo)
├── api/
│   └── app.py                # FastAPI: 20+ endpoints REST
├── dashboard/
│   └── templates/
│       └── index.html        # Dashboard responsive (Tailwind + Chart.js)
├── tests/
│   ├── test_blockchain.py    # 15+ tests unitarios de core
│   ├── test_consensus.py     # Tests PoW
│   ├── test_pbft.py          # PBFT en memoria (reloj falso)
│   ├── test_pbft_red.py      # PBFT con 4 apps reales por P2P
│   └── test_security.py      # Tests crypto + ataques + monitor
└── scripts/
    ├── setup_rpi.sh          # Instalación automatizada en RPi5
    └── demo.py               # Demo completo sin servidor
```

---

## Instalación

### Opción 1: Setup automatizado en Raspberry Pi 5

```bash
# En el Nodo 1 (RPi5 #1):
sudo bash scripts/setup_rpi.sh node_1 8000 8001

# En el Nodo 2 (RPi5 #2), apuntando al Nodo 1:
sudo bash scripts/setup_rpi.sh node_2 8002 8003
# Luego agregar peer: PEERS=<IP_NODO1>:8001 en .env
```

### Opción 2: Instalación manual

```bash
python -m venv venv
source venv/bin/activate         # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
# Editar .env con NODE_ID, puertos, PEERS

uvicorn api.app:app --host 0.0.0.0 --port 8000 --reload
```

### Demo rápido (sin servidor)

```bash
python scripts/demo.py
```

---

## Uso de la API

### Endpoints principales

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| GET | `/` | Dashboard web |
| GET | `/health` | Estado del nodo |
| GET | `/stats` | Estadísticas completas |
| GET | `/blocks` | Lista de bloques (paginado) |
| POST | `/blocks/mine` | Minar un bloque (PoW; 409 en modo PBFT) |
| GET | `/consensus` | Modo de consenso; en PBFT vista, primario y réplicas (P1-1) |
| POST | `/transactions` | Nueva transacción |
| POST | `/wallet/generate` | Generar wallet ECDSA |
| POST | `/credentials/issue` | Emitir credencial académica |
| GET | `/credentials/verify/{id}` | Verificar credencial |
| GET | `/ai/analytics` | Análisis estadístico IA |
| POST | `/ai/train` | Entrenar detector de anomalías |
| GET | `/security/attack-simulation` | Simulación de ataques |
| GET | `/security/crypto-benchmark` | Benchmark criptográfico |
| GET | `/docs` | Documentación interactiva (Swagger) |

### Ejemplo: Emitir credencial académica

```bash
# 1. Generar wallet para la universidad
curl -X POST http://localhost:8000/wallet/generate

# 2. Registrar emisor
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

# 4. Verificar (cualquiera puede verificar con el ID)
curl http://localhost:8000/credentials/verify/<credential_id>
```

---

## Ejecutar Tests

```bash
pytest tests/ -v
pytest tests/test_security.py -v    # Solo seguridad
pytest tests/test_consensus.py -v  # Solo consenso
```

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
Ubuntu con Python 3.12 en cada push y pull request a `main`.

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
- **SHA-256 / SHA3-256 / BLAKE2b**: hashing de bloques y transacciones
- **Merkle Tree**: integridad eficiente de conjuntos de transacciones
- **AES-256-GCM**: cifrado simétrico autenticado
- **PBKDF2-HMAC-SHA256**: derivación segura de contraseñas

### Inteligencia Artificial

- **Isolation Forest**: detección no supervisada de transacciones anómalas
- **Estadísticas de cadena**: TPS, distribución de TXs, salud de red
- **Análisis de credenciales**: tendencias de emisión, revocación y verificación

### Seguridad

- Simulación educativa de ataques del 51 %, Sybil y doble gasto
- Monitor en tiempo real con niveles INFO / WARNING / CRITICAL
- Rate limiting por dirección (100 TX/min)
- Detección de reorganizaciones de cadena

---

## Hardware: Raspberry Pi 5

| Especificación | Valor |
|---|---|
| CPU | ARM Cortex-A76 quad-core 2.4 GHz |
| RAM | 16 GB LPDDR4X |
| Almacenamiento | 128 GB microSD |
| Red | Gigabit Ethernet + WiFi 6 |
| Hash rate SHA-256 (estimado) | ~500,000 – 800,000 H/s |
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
