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

La dificultad del PoW se mide en bits (§2.4) y se reajusta sola hacia 10 s por bloque, un ritmo que permite visualizar el proceso en clase sin esperas frustrantes.

### 2.4 Dificultad en bits y trabajo acumulado (P2-5)

**Unidad.** `header.difficulty` es el número de bits iniciales en cero que debe tener el hash
SHA-256 del bloque. Leído como entero de 256 bits, el hash debe cumplir

```
int(hash, 16) < 2**(256 - bits)
```

Cada intento acierta con probabilidad 2⁻ᵇⁱᵗˢ, así que el **trabajo esperado** de un bloque es
2ᵇⁱᵗˢ intentos. Antes se contaban ceros hexadecimales: cada paso multiplicaba el trabajo por 16
y un Raspberry Pi no podía acercarse a 10 s (saltaba entre ~1 s y ~16 s). Con bits cada paso lo
multiplica por 2. Equivalencias: 4 bits = un `0` hex inicial; 8 bits = `00`; 16 bits = `0000`.

**Reajuste (épocas de `difficulty_window` bloques, por defecto 10).** Al empezar cada época se
mide la anterior: los `w` bloques (sin el génesis) abarcan `w-1` intervalos, así que el tiempo
esperado es `10 s · (w-1)`. La dificultad cambia en

```
Δbits = round(log2(esperado / real)),  acotado a ±2 por época y a [min, max]
```

Ejemplos: la época tardó la mitad → +1 bit; un cuarto → +2; el doble → -1; diez veces menos →
+2 (tope). Dentro de una época la dificultad no cambia; así se evita la sobrecorrección de una
ventana deslizante. El redondeo se hace sin floats comparando cuadrados
(`log2(e/r) ≥ k + ½ ⇔ e² ≥ r²·2^(2k+1)`), con tiempos en milisegundos enteros: todos los nodos
calculan exactamente lo mismo (`retarget_step` en `blockchain/core/chain.py`).

**Elección de cadena.** Ante dos cadenas válidas con el mismo génesis se adopta la de mayor
trabajo acumulado `Σ 2^bits` (entero), no la más larga: una cadena corta minada con más bits puede
pesar más que una larga y fácil. En empate se conserva la propia.

**Configuración.** `MINING_DIFFICULTY` (dificultad de la primera época) está en bits; por defecto
16. Medido en un portátil de desarrollo (no en un Pi), con bloques vacíos: ~85 000 H/s con el hash de bloque en
Python, 16 bits ≈ 0,7 s de media por bloque (20 bloques); con transacciones el hash es más lento
(serializa el bloque entero). El tiempo en el Pi lo debe medir su
dueño; la regla de reajuste lo lleva hacia 10 s en cualquier caso.

**Migración.** Es un cambio de consenso: el hash del génesis no cambia (su dificultad es 0 en
ambas unidades), pero los bloques guardados con la unidad hexadecimal ya no validan. Todos los
nodos deben actualizarse a la vez y borrar su `DATA_DIR` (p. ej. `data/chain`) antes de arrancar.

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
| Tiempo de bloque | objetivo 10 s, reajustado por bits (§2.4) |
| Latencia P2P (LAN) | < 5 ms |
| Latencia PBFT (4 nodos, LAN) | < 100 ms |
| Transacciones por bloque | 50–200 |
| TPS efectivo (PBFT) | 5–20 TPS |
| Consumo energético (1 RPi5) | ~12 W en carga |

---

## 7. Extensibilidad

El proyecto está diseñado para ser extendido en trabajos finales de carrera o tesis:

- **`blockchain/consensus/`**: añadir PoS, DPoS, Tendermint
- **`blockchain/contracts/`**: nuevos smart contracts (votación académica, registro de investigaciones)
- **`ai/`**: modelos de RL para optimización de consenso, GNNs para análisis de grafos de transacciones
- **`security/attacks/`**: ataques de routing BGP, ataques de tiempo, análisis de privacidad
