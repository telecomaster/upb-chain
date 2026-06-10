# Documento de Arquitectura — UPB-Chain

## 1. Visión General

UPB-Chain es una blockchain permisionada de propósito académico que demuestra, en hardware real (Raspberry Pi 5), los principios fundamentales de los sistemas distribuidos confiables: inmutabilidad, transparencia, descentralización y consenso tolerante a fallos.

El sistema está diseñado para ser **demostrable en clase**, **modificable por estudiantes** y **suficientemente completo** para servir de base a investigaciones de posgrado.

---

## 2. Decisiones de Diseño

### 2.1 ¿Por qué dos mecanismos de consenso?

| Escenario | Mecanismo elegido | Justificación |
|-----------|-------------------|---------------|
| Demo pública / clase | **PoW** | Visual, comprensible, ajustable en segundos |
| Producción universitaria | **PBFT** | Finalidad instantánea, bajo consumo energético |
| Investigación | Intercambiable | Permite comparar latencia y throughput directamente |

PoW en RPi5 con dificultad 4 produce bloques en 3–15 s, suficiente para visualizar el proceso en tiempo real sin tiempos de espera frustrantes.

### 2.2 ¿Por qué ECDSA secp256k1 y no RSA?

- Llaves 32 veces más pequeñas con la misma seguridad (256 bits vs 3072 bits RSA)
- Estándar en Bitcoin y Ethereum: validado por millones de implementaciones
- Operaciones de firma ~10× más rápidas en ARM Cortex-A76 (RPi5)

### 2.3 ¿Por qué Isolation Forest para anomalías?

- **No supervisado**: no requiere etiquetas previas (datos de ataque)
- **O(n log n)** de entrenamiento: escala bien a miles de TXs por día
- **Interpretable**: se puede explicar qué características activaron la alarma
- **Liviano**: corre cómodamente en RPi5 con 16 GB RAM

---

## 3. Flujo de una Credencial Académica

```
Universidad (Emisor)                    Blockchain                    Estudiante / Empleador
        │                                    │                                │
        │─── 1. Generar wallet ──────────────►│                                │
        │◄── address, private_key ───────────│                                │
        │                                    │                                │
        │─── 2. Registrar como emisor ───────►│                                │
        │◄── OK (on-chain) ──────────────────│                                │
        │                                    │                                │
        │─── 3. Emitir credencial ───────────►│                                │
        │    (TX firmada con ECDSA)          │── TX al mempool                │
        │◄── credential_id ─────────────────│                                │
        │                                    │                                │
        │                                    │── Minado (PoW/PBFT) ──────────►│ (notificación)
        │                                    │── Bloque confirmado            │
        │                                    │                                │
        │                                    │◄── 4. Verificar ID ────────────│
        │                                    │─── ✓ VÁLIDA ──────────────────►│
        │                                    │    (sin revelar datos privados)│
```

**Propiedad clave**: la verificación en el paso 4 no requiere contactar a la universidad. Cualquier nodo de la red puede confirmar la autenticidad con solo el `credential_id`.

---

## 4. Protocolo PBFT Simplificado

Para una red de **n = 4 nodos** (2 × RPi5 + 2 simulados), el sistema tolera **f = 1 nodo** defectuoso.

```
Nodo 1 (Primario)    Nodo 2           Nodo 3           Nodo 4
      │                 │                │                │
      │── PRE-PREPARE ──►│── PRE-PREPARE ──►│── PRE-PREPARE ──►│
      │                 │                │                │
      │◄── PREPARE ─────│◄── PREPARE ─────│◄── PREPARE ─────│
      │── PREPARE ──────►│── PREPARE ──────►│── PREPARE ──────►│
      │                 │                │                │
      │  (≥ 2f+1 = 3 PREPARE recibidos) │                │
      │                 │                │                │
      │── COMMIT ───────►│── COMMIT ───────►│── COMMIT ───────►│
      │◄── COMMIT ──────│◄── COMMIT ──────│◄── COMMIT ──────│
      │                 │                │                │
      │  (≥ 2f+1 = 3 COMMIT recibidos)  │                │
      │                 │                │                │
      │══ BLOQUE COMPROMETIDO ══════════►│════════════════►│
```

**Latencia esperada** en LAN: < 100 ms (2 round-trips de red local).

---

## 5. Modelo de Amenazas

| Ataque | Descripción | Mitigación en UPB-Chain |
|--------|-------------|------------------------|
| **51 %** | Atacante con >50% del hash rate reorganiza la cadena | PBFT elimina este vector; PoW: monitoreo de hash rate |
| **Sybil** | Identidades falsas para controlar la votación | Lista blanca de nodos + certificados TLS mutuo |
| **Doble Gasto** | Enviar la misma TX a dos destinatarios | Requerir 6+ confirmaciones; PBFT da finalidad inmediata |
| **Eclipse** | Aislar un nodo de la red real | Conexión a múltiples peers independientes |
| **Replay** | Re-enviar una TX válida anterior | TX ID único basado en hash + timestamp |
| **Timestamp manipulation** | Alterar timestamp para validar TXs futuras | Ventana de 60 s máximo en el futuro |

---

## 6. Rendimiento Estimado en RPi5

| Métrica | Valor estimado |
|---------|---------------|
| Hash rate SHA-256 | 500,000–800,000 H/s |
| Tiempo de bloque (dif. 4) | 3–15 s |
| Latencia P2P (LAN) | < 5 ms |
| Latencia PBFT (4 nodos, LAN) | < 100 ms |
| Transacciones por bloque | 50–200 |
| TPS efectivo (PBFT, dif. 4) | 5–20 TPS |
| Consumo energético (1 RPi5) | ~12 W en carga |

---

## 7. Extensibilidad

El proyecto está diseñado para ser extendido en trabajos finales de carrera o tesis:

- **`blockchain/consensus/`**: añadir PoS, DPoS, Tendermint
- **`blockchain/contracts/`**: nuevos smart contracts (votación académica, registro de investigaciones)
- **`ai/`**: modelos de RL para optimización de consenso, GNNs para análisis de grafos de transacciones
- **`security/attacks/`**: ataques de routing BGP, ataques de tiempo, análisis de privacidad
