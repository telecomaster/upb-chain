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
│   │   └── pbft.py           # PBFT completo (Pre-prepare/Prepare/Commit)
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
│   ├── test_consensus.py     # Tests PoW + PBFT
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
| POST | `/blocks/mine` | Minar un bloque (PoW) |
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

## Componentes Académicos Clave

### Mecanismos de Consenso

| | Proof of Work | PBFT |
|--|--|--|
| **Tipo** | No permisionado | Permisionado |
| **Finalidad** | Probabilística | Inmediata |
| **Tolerancia** | 51% hash rate | f < n/3 nodos |
| **Consumo** | Alto (CPU) | Bajo |
| **Ideal para** | Redes públicas | Redes institucionales |

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
| Tiempo de bloque (dificultad 4) | 3–15 segundos |
| Tiempo de bloque (dificultad 6) | 30–180 segundos |

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
