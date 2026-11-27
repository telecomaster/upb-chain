# Documento de Arquitectura — UPB-Chain

## 1. Visión General

UPB-Chain es una blockchain permisionada de propósito académico que demuestra, en hardware real (Raspberry Pi 5), los principios fundamentales de los sistemas distribuidos confiables: inmutabilidad, transparencia, descentralización y consenso tolerante a fallos.

El sistema está diseñado para ser **demostrable en clase**, **modificable por estudiantes** y **suficientemente completo** para servir de base a investigaciones de posgrado.

### Mapa de módulos

| Capa | Dónde | Qué hace |
|---|---|---|
| Configuración | `config.py` | `Settings` inmutable y validado; las variables de entorno ganan al `.env` |
| API | `api/app.py` | Fábrica `create_app(settings)`; el estado del nodo vive en `NodeState` (`app.state.node`); `app = create_app()` para uvicorn. Dos apps en un proceso son independientes (los tests usan `tests.helpers.make_app`) |
| Cadena | `blockchain/core/` | Bloques, transacciones firmadas (ECDSA secp256k1, con `nonce` por cuenta), cadena con resolución de bifurcaciones y almacenamiento SQLite `chain.db` (§2.5) |
| Contratos | `blockchain/contracts/`, `blockchain/vm/` | El estado es la reproducción de las TX confirmadas: cuentas, credenciales, tokens, insignias, votación y programas de la VM (guías en `docs/contratos.md` y `docs/vm.md`) |
| Consenso | `blockchain/consensus/` | PoW con dificultad en bits o PBFT firmado, elegido con `CONSENSUS=pow\|pbft` para toda la red (§2.4, §4) |
| Red | `blockchain/network/` | P2P TCP con conexiones persistentes y TLS mutuo opcional `P2P_TLS=on` (§4.8) |
| IA y seguridad | `ai/`, `security/` | Detector de anomalías, analítica, monitor, simulador y laboratorio de ataques |

La configuración completa, variable por variable, está en `.env.example`.

---

## 2. Decisiones de Diseño

### 2.1 ¿Por qué dos mecanismos de consenso?

| Escenario | Mecanismo elegido | Justificación |
|-----------|-------------------|---------------|
| Demo pública / clase | **PoW** | Visual, comprensible, ajustable en segundos |
| Producción universitaria | **PBFT** | Finalidad instantánea, bajo consumo energético |
| Investigación | Intercambiable | Permite comparar latencia y throughput directamente |

La dificultad del PoW se mide en bits (§2.4) y se reajusta sola hacia 10 s por bloque, un ritmo que permite visualizar el proceso en clase sin esperas frustrantes.

### 2.2 ¿Por qué ECDSA secp256k1 y no RSA?

- Llaves 32 veces más pequeñas con la misma seguridad (256 bits vs 3072 bits RSA)
- Estándar en Bitcoin y Ethereum: validado por millones de implementaciones
- Operaciones de firma ~10× más rápidas en ARM Cortex-A76 (RPi5)

### 2.3 ¿Por qué Isolation Forest para anomalías?

- **No supervisado**: no requiere etiquetas previas (datos de ataque)
- **O(n log n)** de entrenamiento: escala bien a miles de TXs por día
- **Interpretable**: se puede explicar qué características activaron la alarma
- **Liviano**: corre cómodamente en RPi5 con 16 GB RAM

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

### 2.4.1 Límites de tamaño de TX y de bloque (P0-3, consenso)

Una auditoría admitió por `POST /transactions` un `DATA_RECORD` de 3 MB: no había tope y la cadena
podía crecer sin control. Los topes viven en un solo lugar, `blockchain/core/limits.py`, y se miden
de forma determinista sobre el JSON canónico (`sort_keys`, separadores compactos, UTF-8):

| Límite | Valor | Por qué |
|---|---|---|
| `MAX_TX_BYTES` | 64 KiB (65 536 B) | La TX legítima más grande es un `CONTRACT_DEPLOY` al máximo de la VM (4096 B de código = 8192 hex + 256 casillas con palabras de 256 bits): ~49,8 KB. Deja ~30 % de margen. Una credencial, un voto o una fila del CSV de premios ocupan < 2 KB. |
| `MAX_BLOCK_BYTES` | 1 MiB (1 048 576 B) | Bloque completo (encabezado + TXs + hash). Caben ≥ 16 TX máximas; un lote de sincronización siempre lleva al menos un bloque entero. |
| `MAX_BLOCK_TXS` | 1000 | Acota la CPU por bloque (una verificación ECDSA por TX en la RPi). |

Dónde se aplican: `Transaction.is_consensus_valid` (por tanto mempool, P2P `NEW_TX` y cada TX de
un bloque), `Blockchain._validate_block_at` (bloque recibido, minado o descargado al sincronizar)
y la API, que responde **413** antes de correr el detector de anomalías. El minero
(`create_candidate_block`) toma hasta 50 TX y corta el prefijo que se pasaría de 1 MiB; lo que no
cabe queda para el bloque siguiente.

**Cambio de consenso.** El génesis no cambia y ninguna cadena previa legítima viola los topes, pero
un nodo sin la regla aceptaría bloques que los demás rechazan: todos los nodos deben actualizarse a
la vez.

### 2.6 Anclaje público con OpenTimestamps (idea 3)

**No es consenso.** Es un trabajo local de mejor esfuerzo: nunca bloquea ni cambia la validación,
y con `ANCHOR_INTERVAL=0` (por defecto) no existe. Con `ANCHOR_INTERVAL=N`, cada vez que el
nodo anuncia un bloque de altura múltiplo de N, un hilo en segundo plano (`blockchain/anchoring.py`)
envía el **hash del bloque como 32 bytes** (el hash ya es un SHA-256; se usa tal cual como
"hash del archivo" del formato OTS) con `POST <calendario>/digest` (solo `urllib`, timeout 10 s)
a cada calendario de `ANCHOR_CALENDARS`. La respuesta (un timestamp con atestación "pending")
se guarda en la tabla `anchors` de `chain.db` (`block_index, block_hash, calendar, submitted_at,
ots_bytes, status`: `pending`, `failed`, `orphaned`; `upgraded` queda reservado). Los fallos se
registran y se reintentan con el siguiente bloque y al arrancar. Si una reorganización descarta el
bloque, sus anclajes pasan a `orphaned` (misma transacción que la reorg) y la API los ignora.
Regla contra anclar historia: un bloque múltiplo de N solo se ancla si está a lo sumo a N bloques
de la punta y su marca de tiempo tiene menos de un día; así un nodo que sincroniza no sella el
pasado. Reintentos: hasta 5 envíos por (bloque, calendario), con espera de 60 s x 2^(k-1) tras el
intento k; agotados, la fila queda `failed` (el kiosco muestra "falló el anclaje").
`scripts/actualizar_anclajes.py` pide a cada calendario `GET <uri>/timestamp/<commitment>` y, si la
respuesta trae la atestación de Bitcoin (`0588960d73d71901`), sustituye la pendiente y marca
`upgraded` (solo probado con transporte falso).

`GET /anchors?from_block=N` lista los bloques anclados; `GET /anchors/{n}.ots` descarga un `.ots`
escrito a mano (cabecera mágica + versión 1 + op SHA-256 + digest + respuestas de los calendarios
separadas por `0xff`). El kiosco muestra el estado del primer anclaje en o después del bloque de la
credencial. No se implementa la verificación contra Bitcoin: se usa el cliente oficial
(`pip install opentimestamps-client`):

    ots upgrade bloque-100.ots                     # tras unas horas: trae la prueba de Bitcoin
    ots verify -d <hash del bloque en hex> bloque-100.ots

Sin archivo original: se pasa el digest con `-d`. **Estado de la prueba:** el formato y el flujo
se comprueban en `tests/test_anclaje.py` con un calendario simulado; no se ha probado contra los
calendarios reales en CI ni se ha confirmado con `ots verify`; eso lo hace el dueño del nodo.

### 2.5 Almacenamiento en SQLite, índices y fotos de estado (P2-4)

**Antes.** La cadena vivía en `chain.json`, reescrito ENTERO (temporal + fsync + rename, P1-8)
con cada bloque: O(altura) bytes por bloque. Al arrancar se revalidaba todo desde el génesis
(firmas ECDSA y contratos), y buscar una TX, un bloque por hash o las credenciales de una
dirección recorría la cadena completa.

**Ahora.** `blockchain/core/storage.py` (`ChainStore`, solo `sqlite3` de la biblioteca estándar)
guarda `<DATA_DIR>/chain.db`:

| Tabla | Columnas | Para qué |
|-------|----------|----------|
| `blocks` | `height` PK, `hash` UNIQUE, `prev_hash`, `timestamp`, `difficulty`, `n_txs`, `data` (JSON del bloque) | la cadena; bloque por hash con el índice UNIQUE |
| `txs` | `tx_id` PK, `height`, `position`, `type`, `sender`, `recipient` (+ índices por `sender`, `recipient`, `height`) | TX por id → (altura, posición) para la prueba Merkle; TXs de una dirección |
| `snapshots` | `height` PK, `block_hash`, `contracts`, `states` (JSON), `digest` (SHA-256) | foto del estado de los contratos cada `SNAPSHOT_INTERVAL` bloques (100); se guardan las 3 últimas |
| `meta` | `key`, `value` | versión del esquema |

- **Agregar un bloque** = una transacción SQLite: INSERT del bloque, de sus TXs y, si toca, de la
  foto. **Reorganización** = una transacción: DELETE de las alturas mayores que la bifurcación
  (bloques, TXs y fotos) e INSERT de las nuevas. El disco se escribe ANTES de cambiar la memoria;
  si la escritura falla, el bloque no entró y la cadena en memoria sigue igual.
- **Cortes de energía.** `BEGIN IMMEDIATE … COMMIT`: si el proceso muere a la mitad, al reabrir
  SQLite descarta la transacción (lo prueba `tests/test_storage.py` matando un proceso con
  `os._exit` dentro de ella). `journal_mode=WAL` deja leer a la API mientras la red escribe.
  `synchronous=FULL` hace fsync del WAL en cada COMMIT: en una microSD un bloque confirmado
  sobrevive a un corte de luz. Con `NORMAL` la base tampoco se corrompe, pero se pueden perder los
  últimos bloques; se eligió FULL porque a ~1 bloque cada 10 s el fsync extra no importa.
- **chain.db dañado** (no es SQLite o falla `PRAGMA quick_check`): el nodo no arranca y explica
  qué hacer (mover `chain.db*` y resincronizar desde los pares, o reimportar `chain.json.migrated`
  renombrándolo a `chain.json`). Nunca se borra nada automáticamente.
- **Memoria.** `Blockchain.chain` sigue siendo la lista de bloques en memoria (la usan la
  validación, la red y varios endpoints); P2-4 elimina las reescrituras y los recorridos, no la
  lista. Siguen recorriendo la cadena, porque necesitan todos los bloques: `/ai/analytics`,
  `/ai/train` y la búsqueda del punto de bifurcación al sincronizar (`GET_HASHES`). El antiguo
  `GET /network/sync` (volcado HTTP de la cadena entera, sin autenticación y sin uso) se eliminó;
  queda `POST /network/sync` (admin), que fuerza la sincronización por lotes (§4.8).

**Arranque (`REVALIDATE_ON_START`).**

- `fast` (por defecto): (1) verificación barata de TODOS los bloques: índice, enlace con el
  anterior, hash, dificultad exigida, PoW y raíz Merkle (solo SHA-256 y enteros); (2) estado de los
  contratos desde la foto más alta que coincida con la cadena (mismo hash de bloque, mismos
  contratos, SHA-256 correcto); (3) validación de consenso COMPLETA (firmas + contratos) de los
  bloques posteriores a la foto. Sin foto utilizable equivale a `full`.
- `full`: validación completa desde el génesis, como antes; además descarta las fotos y guarda una
  nueva en la punta. Usarlo tras cambiar las reglas de un contrato.

Se eligió `fast` por defecto porque lo caro de revalidar es verificar cada firma ECDSA y reproducir
los contratos, y eso crece con la historia: en un Pi el arranque crecería sin límite. Con 300
bloques de prueba, en un portátil de desarrollo (no medido en un Pi), el arranque rápido fue del
orden de 10 veces más corto que el completo; la prueba solo exige que sea menos de la mitad.

**Modelo de amenazas del arranque rápido.** La foto se cree porque la escribió ESTE nodo después
de validar los bloques que resume; nunca se recibe de la red (un par solo puede mandar bloques, que
se validan por completo). Su SHA-256 detecta daños del medio (microSD), no a un atacante con
permiso de escritura en `DATA_DIR`: ese podría recalcular el SHA-256, y también cambiar el código
del nodo, así que la defensa ahí son los permisos del sistema operativo. Lo que SÍ detecta el modo
rápido: bloques o TXs manipulados en disco (cambian el hash o la raíz Merkle), bloques sin PoW o con
otra dificultad, y fotos dañadas (se ignoran y se reproduce desde la anterior). Si hay duda,
`REVALIDATE_ON_START=full`.

**Migración.** Si existe `chain.json` (o su `.bak`) y no hay `chain.db`, se importa una vez con
validación completa y el archivo se renombra a `chain.json.migrated` (no se borra). Para ver la
cadena como JSON: `venv\Scripts\python.exe scripts\exportar_cadena.py [DATA_DIR] [-o salida.json]`
(abre la base en solo lectura; sirve con el nodo encendido).

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

## 4. Consenso PBFT (P1-1)

`CONSENSUS=pbft` cambia el consenso de **toda la red** (un par con otro modo se rechaza en el
HANDSHAKE, igual que con otro génesis). Código: `blockchain/consensus/pbft.py` (≈ 950 líneas
comentadas), cadena en `blockchain/core/chain.py`, transporte en `blockchain/network/node.py`.
Referencia: Castro, M. & Liskov, B. (1999), *Practical Byzantine Fault Tolerance*, OSDI'99 —
§4.1 (vistas y primario), §4.2 (caso normal), §4.4 (cambio de vista), §4.5.2 (vivacidad).

### 4.1 Réplicas, llaves y quórums

- `PBFT_REPLICAS_FILE` (por defecto `pbft_replicas.json`, igual en todos los nodos):
  `{"replicas": [{"id", "address": "host:puerto P2P", "public_key"}]}`. El **orden** define el
  primario de la vista *v*: `replicas[v mod n]`.
- `PBFT_KEY_FILE`: llave ECDSA secp256k1 de esta réplica (formato wallet, nunca versionada). Se
  crea con `scripts/crear_llave_replica.py --id node_1 --address 192.168.1.100:8001`, que además
  agrega la llave pública a la lista. Si la llave no coincide con la de la lista, el nodo no arranca.
- Un nodo en modo pbft cuyo `NODE_ID` no está en la lista es **observador**: verifica
  certificados y sigue la cadena, pero no vota.
- *n* réplicas toleran *f* = ⌊(*n* − 1)/3⌋ fallas bizantinas. Quórum de COMMIT y de VIEW-CHANGE:
  2*f* + 1. Quórum de PREPARE: 2*f* respaldos + el PRE-PREPARE del primario.

**Decisión de despliegue: 4 réplicas, 2 por Raspberry Pi (f = 1).** Limitación honesta para el
paper: las dos réplicas de un mismo Pi comparten hardware, alimentación y red. Si **un Pi cae se
pierden 2 réplicas**, quedan 2 < 2*f* + 1 = 3 y **PBFT se detiene** (no hay commit: se pierde la
vivacidad, no la seguridad; nunca se confirman dos bloques distintos). La configuración tolera la
caída de *un proceso* de réplica, no la de un equipo. Para tolerar la caída de un equipo hace
falta un tercer equipo (p. ej. 2 + 1 + 1 réplicas en tres máquinas) o más réplicas en más
equipos.

### 4.2 Validez de un bloque según el modo

| Regla | `pow` | `pbft` |
|---|---|---|
| Génesis | fijo (`GENESIS_HASH`) | **idéntico** |
| Índice, enlace, hash, raíz Merkle, timestamp (mediana / futuro), TXs firmadas y sin duplicados, contratos | sí | sí (mismas reglas) |
| `header.difficulty` | la de la regla de bits (§2.4) | **0** en todas las alturas |
| Prueba de trabajo | hash < 2^(256−bits) | no hay (0 bits: cualquier hash cumple) |
| `header.nonce` | libre (lo busca el minero) | **0** (no hay minado) |
| Certificado de commit | — | **obligatorio** para cada bloque > 0 |
| Elección entre cadenas | mayor Σ 2^bits | mayor altura entre cadenas con certificados válidos; **nunca** se reemplaza un bloque certificado |

El **certificado de commit** de la altura *h* es `{"view", "seq": h, "digest": hash, "commits":
[2f+1 COMMIT firmados]}`: misma vista, misma altura, mismo hash, firmantes distintos de la lista,
todas las firmas válidas (`ReplicaSet.check_commit_certificate`, sin reloj ni azar). Se guarda en
la tabla `certificates` de `chain.db`, **fuera del hash del bloque**: dos réplicas pueden juntar
subconjuntos distintos de COMMIT igualmente válidos, y el bloque debe ser el mismo para todas.
Se verifica al agregar un bloque (`add_block(bloque, certificate)`), al sincronizar
(`GET_BLOCKS` → `BLOCKS` lleva los `certificates` del lote; `replace_chain` los verifica en vez del trabajo) y al
arrancar (fast y full). Si una cadena recibida trae otro bloque certificado en una altura que ya
tenemos, se rechaza y el monitor emite la alerta **CRITICAL `PBFT_CONFLICT`** (solo puede pasar
con más de *f* réplicas bizantinas). Un `DATA_DIR` de una red PoW no arranca en modo pbft.

### 4.3 Caso normal (§4.2 del artículo)

El número de secuencia es la altura. El primario propone cuando hay TXs en el mempool (como
mínimo cada `PBFT_BATCH_INTERVAL` = 0,2 s; sin TXs no hay bloques vacíos) y con **ventana de 1**:
no propone *h* + 2 hasta confirmar *h* + 1. `POST /blocks/mine` responde 409 en modo pbft.

```
 Primario r0           r1                 r2                 r3
     │  PRE-PREPARE⟨v,h,d⟩ + bloque (firmado por r0)            │
     ├──────────────────►├──────────────────►├──────────────────►│
     │                   │ valida el bloque (check_block)        │
     │    PREPARE⟨v,h,d,i⟩ (solo respaldos, firmados)            │
     │◄──────────────────┼──────────────────►│◄─────────────────►│
     │  prepared = PRE-PREPARE + 2f PREPARE (el PRE-PREPARE es el voto del primario)
     │    COMMIT⟨v,h,d,i⟩ (todos, firmados)                      │
     │◄─────────────────►│◄─────────────────►│◄─────────────────►│
     │  committed = prepared + 2f+1 COMMIT (incluido el propio)  │
     ▼  add_block(bloque, certificado = 2f+1 COMMIT)  — en cada réplica
     └─► el primario difunde NEW_BLOCK + certificado (observadores y réplicas atrasadas);
         una réplica que perdió los COMMIT pide CERT_REQUEST y recibe bloque + certificado
```

**Variante implementada:** la del artículo. El primario **no** envía PREPARE; su PRE-PREPARE
cuenta como su voto, así que "prepared" exige el PRE-PREPARE más 2*f* PREPARE de respaldos
distintos (quórum efectivo 2*f* + 1). Antes de P1-1 el código pedía 2*f* + 1 PREPARE de respaldos
y el primario nunca contaba: con una réplica caída no había commit. COMMIT exige 2*f* + 1
firmantes incluido el propio.

Cada mensaje va firmado con la llave de la réplica; la firma cubre el JSON canónico del mensaje
excepto `signature` y `block` (el bloque queda atado por *d* = su hash). Se descartan: firmas
inválidas, réplicas fuera de la lista, PRE-PREPARE de quien no es el primario, PREPARE del
primario, mensajes de otra vista o fuera de la ventana (contador `upb_pbft_rejected_messages`).
Dos mensajes del mismo tipo, vista y altura con distinto *d* firmados por la misma réplica son
una **equivocación**: se ignora el segundo y el monitor emite **CRITICAL `PBFT_EQUIVOCATION`**.

### 4.4 Cambio de vista (§4.4 y §4.5.2 del artículo)

```
 r1, r2, r3: hay TXs pendientes o un bloque aceptado sin confirmar durante PBFT_VIEW_TIMEOUT (5 s)
     │  VIEW-CHANGE⟨v+1, h, P, i⟩   h = altura confirmada, P = certificados "prepared" > h
     ├──────────────── a todas ───────────────►
 nuevo primario = replicas[(v+1) mod n], con 2f VIEW-CHANGE de otros + el propio:
     │  NEW-VIEW⟨v+1, V, O⟩   V = las 2f+1 pruebas, O = PRE-PREPARE del bloque "prepared"
     │                         de mayor vista en la altura max(h)+1 (o nada)
     ├──────────────── a todas ───────────────►
 cada réplica verifica V (firmas, certificados prepared) y RECALCULA O; si coincide, instala v+1
 y procesa O como un PRE-PREPARE normal → PREPARE → COMMIT
```

- Si la vista *v* + 1 tampoco avanza, se intenta *v* + 2 con el doble de espera (exponencial,
  tope 32×). Con *f* + 1 VIEW-CHANGE para vistas mayores, una réplica se une a la menor de ellas.
- Un bloque "prepared" en la vista vieja se **re-propone** en la nueva (lo prueban
  `test_bloque_preparado_se_repropone_tras_el_cambio_de_vista` y la prueba del primario que
  equivoca: el bloque B preparado en r2 y r3 es el que se confirma tras el cambio de vista).
- Los mensajes de una vista que aún no se instaló (la red reordena) se guardan y se reprocesan al
  instalarla.

**Réplica rezagada: ponerse al día con el certificado de commit.** Si una réplica pierde los
COMMIT de la altura *h* + 1, las demás ya confirmaron y no tienen trabajo pendiente: su cambio de
vista no prospera (nadie se une sin *f* + 1 pedidos) y antes solo la sacaba la consulta periódica
del P2P (`sync_interval` = 15 s); si la rezagada era el primario, además nadie difundía el bloque
a los observadores. Ahora, con trabajo pendiente durante `catch_up_delay` (= `PBFT_VIEW_TIMEOUT`/5,
1 s por defecto, **antes** de que venza el temporizador de vista), la réplica difunde
`CERT_REQUEST⟨h⟩` ("estoy en *h*"); también lo hace en cuanto ve un mensaje para una altura mayor
que *h* + 1. Toda réplica con más altura contesta **solo a quien pregunta** con `CERT_REPLY`: el
bloque *h* + 1 (y siguientes, hasta 10; más allá se usa la sincronización por lotes `GET_BLOCKS`) con su certificado de commit.
La misma respuesta recibe un VIEW-CHANGE que trae una altura menor a la propia. Quien recibe un
`CERT_REPLY` **no confía en el emisor**: acepta el bloque solo si el certificado tiene 2*f* + 1
COMMIT con firma válida de réplicas distintas para ese hash, vista y altura
(`check_commit_certificate`, el mismo chequeo que al sincronizar), y luego valida el bloque como
siempre (`add_block`). Al agregarlo se reinicia el temporizador, así que una réplica que puede
ponerse al día no inicia un cambio de vista; si el primario rezagado se pone al día, difunde el
bloque a los observadores. Un VIEW-CHANGE **ya enviado no se retira**: volver a la vista *v*
después de prometer *v* + 1 rompería la intersección de quórums que protege al NEW-VIEW; esa
réplica se une a *v* + 1 cuando las demás también lo pidan. Las respuestas solo se encolan (sin E/S
de red con el lock tomado) y hay como máximo una por réplica cada `catch_up_delay`/2.

### 4.5 Qué se omite (y por qué)

- **Checkpoints y recolección de basura (§4.3 del artículo):** con ventana 1 el log solo guarda
  la altura siguiente; la cadena confirmada con sus certificados hace de checkpoint estable.
- **Peticiones nulas en NEW-VIEW:** con ventana 1 no hay huecos que rellenar.
- **Clientes y REPLY:** el "cliente" consulta la cadena por la API. Las TXs llegan a las
  réplicas por el gossip P2P existente (`NEW_TX`); el primario no reenvía peticiones.
- **Transferencia de estado completa:** una réplica muy atrasada pide la cadena a sus pares
  por lotes (`GET_HASHES`/`GET_BLOCKS`) y verifica certificado por certificado; para pocos bloques basta `CERT_REQUEST`.
- **Retransmisión de mensajes de fase:** un PREPARE o COMMIT perdido no se reenvía; si las demás
  confirmaron, la réplica se pone al día con el certificado (§4.4); si no, el temporizador provoca
  un cambio de vista.
- **Vista en disco:** al reiniciar, la réplica toma la vista del certificado del último bloque.
- **Firmas por mensaje en vez de MACs (§4.1 usa autenticadores):** más simple y más caro en CPU.
- **Cambio de membresía:** la lista de réplicas es fija; cambiarla es una red nueva.

### 4.6 Observabilidad

- `GET /consensus`: modo, vista, primario, ¿cambio de vista en curso?, *n*, *f*, quórum, última
  altura confirmada, cambios de vista, mensajes descartados, bloques agregados por certificado
  (`caught_up_blocks`) y estado de cada réplica (último mensaje recibido).
- `GET /events`: eventos `pbft_phase` (`PRE_PREPARE`, `PREPARED`, `COMMITTED`, `VIEW_CHANGE`,
  `NEW_VIEW`, `EQUIVOCATION`, `CATCH_UP`).
- `/metrics`: `upb_consensus_info{mode}`, `upb_pbft_view`, `upb_pbft_committed_seq`,
  `upb_pbft_in_view_change`, `upb_pbft_view_changes_total`, `upb_pbft_rejected_messages_total`.

### 4.7 Carrera de consensos (medida en un portátil, no en las Pi)

`scripts/experiments/carrera_consensos.py` corre la misma carga con semilla en 4 nodos en
proceso, primero en PoW y luego en PBFT, y escribe `docs/experimentos/carrera_consensos.{csv,md}`.
Los números de ese archivo son **medidos en un portátil de desarrollo con red en proceso
(loopback) y los 4 nodos en un mismo intérprete de Python**; no son mediciones de las Raspberry Pi
ni de una LAN (eso es P1-10). Resultado de la última corrida: ver ese archivo. Es UNA corrida:
la latencia PoW varía mucho entre corridas (empates, reorgs, minado aleatorio), así que para el
paper conviene repetir con varias semillas y reportar la dispersión.

---

### 4.8 Transporte P2P: conexiones persistentes, TLS mutuo y lista blanca (P2-6)

**Conexiones.** Antes, cada mensaje abría una conexión TCP nueva (connect, enviar, leer, cerrar). Ahora
hay **una conexión larga por par y canal** (`ctl`: handshake, sincronización y gossip; `pbft`: mensajes
PBFT, para que bajar una cadena grande no retrase al consenso), con el mismo framing de 4 bytes + JSON.
El servidor atiende mensajes en bucle; el cliente serializa petición/respuesta con un candado por
conexión, comprueba que siga viva antes de reutilizarla (si el par la cerró, reabre y reintenta una vez)
y la reconexión tras una caída sigue siendo el backoff exponencial de `_mark_failed`. El latido es TCP
keepalive más el `SYNC_REQUEST` periódico; el servidor cierra tras `idle_timeout` sin tráfico. Encima
siguen las colas de envío por réplica de PBFT (§4.1), que ahora escriben en la conexión `pbft`.

**TLS mutuo (`P2P_TLS=on`, solo `ssl` de la biblioteca estándar).** TLS 1.3 como mínimo y
`CERT_REQUIRED` en ambos lados: quien conecta y quien escucha presentan un certificado firmado por la CA
privada de la red (`scripts/crear_ca.py`, `scripts/emitir_cert_nodo.py`, `security/pki.py`). No se
verifica el nombre de host (`check_hostname = False`) porque los nodos se direccionan por IP en una LAN
y esa IP puede cambiar; la identidad es el **CN = `node_id`** del certificado, que se compara con la lista
blanca. Además, el `node_id` anunciado en `HANDSHAKE` debe coincidir con el CN (un nodo con el
certificado de otro recibe `REJECT`).

**Lista blanca (`P2P_ALLOWLIST`).** Con TLS, un par cuyo CN no figure se desconecta en el apretón de
manos y se avisa por `on_unknown_peer` (alerta `UNKNOWN_PEER` del monitor, una vez por identidad). Por
defecto en `pbft` son los ids de la lista de réplicas; en `pow` vacía significa "cualquier certificado
de la CA". **Sin TLS la lista solo es informativa**: el `node_id` anunciado no está autenticado, así
que únicamente se avisa y no se rechaza. Revocar = quitar el id de la lista en los demás nodos (no hay
CRL ni OCSP); un certificado robado sigue siendo válido para otros nodos que no tengan la lista al día.

**Costo (medido en un portátil, loopback, no en las Pi), mediana de 300 mensajes:** ida y vuelta de un
`PING` 0,85 ms con conexión por mensaje → 0,24 ms persistente sin TLS → 0,27 ms persistente con mTLS; envío
de un mensaje PBFT 0,58 ms → 0,12 ms → 0,10 ms. El apretón de manos TLS se paga una vez por conexión,
no por mensaje.

### 4.9 Sincronización por lotes (P0-5, auditoría)

**Problema.** `GET_CHAIN` mandaba la cadena entera en un solo marco. Cada mensaje tiene un tope de
`_MAX_PAYLOAD` = 10 MB; una cadena normal lo supera con el tiempo (o enseguida con TXs grandes), y
desde ese momento un nodo nuevo o con el `DATA_DIR` borrado no podía sincronizar nunca ("Longitud de
mensaje inválida" en bucle) mientras el que servía registraba trazas de `SSLEOFError`. En PoW no había
otro camino.

**Ahora** (`P2PNode.sync_with`):

1. **Punto de bifurcación.** `GET_HASHES {from, count}` → `HASHES {data: [hash…], height}`, desde
   nuestra punta hacia atrás en lotes de hasta 2000 hashes. Como cada hash incluye al anterior, la
   primera altura que coincide desde arriba es el último bloque común. Si el par solo nos extiende,
   basta un pedido; si ni el génesis coincide, es otra red y no se sigue.
2. **Descarga.** `GET_BLOCKS {from, count, max_bytes}` → `BLOCKS {data, certificates, height}`:
   bloques consecutivos desde la bifurcación + 1, hasta 500 por lote y sin pasar de la mitad del
   menor `_MAX_PAYLOAD` de ambos extremos (siempre al menos un bloque; un bloque mide ≤ 1 MiB, §2.4.1).
   Se baja hasta la altura que el par anunció al empezar, y cada lote se comprueba (índice y
   `previous_hash` encadenados) antes de pedir el siguiente.
3. **Adopción.** Nuestro prefijo hasta la bifurcación + lo bajado → **una** llamada a `replace_chain`,
   que valida todo y decide por trabajo acumulado (en pbft, por certificados: los de nuestro prefijo
   más los del lote).

`GET_CHAIN` se eliminó (nadie más lo usaba; el nodo malicioso del laboratorio ahora sobrescribe
`_serving_chain`). Un marco que supera el tope o no es JSON se registra en **una línea** y se cierra
esa conexión; un par que se va mientras se le responde, también (sin traza).

**Validación desde la bifurcación (P2-4).** `replace_chain` ya no revalida la cadena desde el génesis:
el prefijo común (mismo hash y contenido que de verdad da ese hash) ya lo validó este nodo, así que
solo se validan por completo (firmas, contratos, certificados PBFT) los bloques nuevos. El estado de
los contratos en la bifurcación sale de un anillo en memoria con los últimos 16 estados
(`Blockchain.RECENT_STATES`), o de la foto de `chain.db` más cercana por debajo + reproducción, solo
de contratos, de nuestros bloques hasta la bifurcación. Lo que sigue siendo O(altura) es barato
(decodificar los bloques recibidos, un SHA-256 por bloque del prefijo, sumar el trabajo). El camino
antiguo queda como `replace_chain(..., full_validation=True)`; `tests/test_reorg_incremental.py`
compara ambos en bifurcaciones aleatorias.

**Cambio de protocolo.** Un nodo con la versión anterior pide `GET_CHAIN` y no recibe respuesta:
todos los nodos deben actualizarse a la vez (es el mismo despliegue que los topes de P0-3).

## 5. Modelo de Amenazas

| Ataque | Descripción | Mitigación en UPB-Chain |
|--------|-------------|------------------------|
| **51 %** | Atacante con >50% del hash rate reorganiza la cadena | PBFT elimina este vector; PoW: monitoreo de hash rate |
| **Sybil** | Identidades falsas para controlar la votación | Lista blanca de nodos + certificados TLS mutuo |
| **Doble Gasto** | Enviar la misma TX a dos destinatarios | Requerir 6+ confirmaciones; PBFT da finalidad inmediata |
| **Eclipse** | Aislar un nodo de la red real | Conexión a múltiples peers independientes |
| **Replay** | Re-enviar una TX válida anterior | TX ID único (hash) y `nonce` por cuenta: cada TX firmada debe llevar nonce confirmado + 1 (P0-9), así una TX no puede confirmarse dos veces |
| **Timestamp manipulation** | Alterar timestamp para validar TXs futuras | La TX con timestamp en el futuro se rechaza (`Timestamp en el futuro`, hasta 60 s de tolerancia; una TX de más de 1 h se rechaza al admitirla al mempool, política local) |

---

## 6. Rendimiento Estimado en RPi5

| Métrica | Valor estimado |
|---------|---------------|
| Hash rate SHA-256 | 500,000–800,000 H/s |
| Tiempo de bloque | objetivo 10 s, reajustado por bits (§2.4) |
| Latencia P2P (LAN) | < 5 ms |
| Latencia PBFT (4 nodos, LAN) | < 100 ms (estimación sin medir; la carrera de §4.7 mide en un portátil, no en la Pi) |
| Transacciones por bloque | 50–200 |
| TPS efectivo (PBFT) | 5–20 TPS (estimación sin medir) |
| Consumo energético (1 RPi5) | ~12 W en carga |

---

## 6.1 Freno térmico local del minero (idea 5)

Con `THERMAL_THROTTLE=on` el hilo de minado PoW hace pausas cortas entre lotes de 2048 nonces
(`blockchain/consensus/termico.py`). Por debajo de `THERMAL_SOFT_C` (70 °C) trabaja a ciclo 1.0;
entre `THERMAL_SOFT_C` y `THERMAL_HARD_C` (80 °C) el ciclo baja linealmente hasta `THERMAL_MIN_DUTY`
(0.2). Es solo local: la dificultad es consenso y sale de los datos de la cadena, y la temperatura
difiere de un nodo a otro, así que NUNCA interviene en la dificultad ni en la validación; un bloque
minado con freno es idéntico en validez a uno sin freno. Sin sensor (Windows) no hace nada.
La temperatura y el ciclo salen en `/health` (`thermal`), en `/metrics`
(`upb_soc_temperature_celsius`, `upb_miner_duty`) y en los eventos `mining_progress`.
Que el freno evite el estrangulamiento del firmware (85 °C en la Pi 5) es una HIPÓTESIS: se mide con
`scripts/bench_rpi.py --termico` en la Pi; aún no hay cifras.

---

## 7. Extensibilidad

El proyecto está diseñado para ser extendido en trabajos finales de carrera o tesis:

- **`blockchain/consensus/`**: añadir PoS, DPoS, Tendermint
- **`blockchain/contracts/`**: nuevos smart contracts (votación académica, registro de investigaciones)
- **`ai/`**: modelos de RL para optimización de consenso, GNNs para análisis de grafos de transacciones
- **`security/attacks/`**: ataques de routing BGP, ataques de tiempo, análisis de privacidad
