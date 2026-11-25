# Hoja de ruta — UPB-Chain

Estado verificado al 2026-11-25. Fuente de verdad para prioridades y delegación; `TAREAS.md` y
`docs/PLAN_IMPLEMENTACION.md` conservan el plan original del autor.

## Resumen

UPB-Chain funciona como demo de **un solo nodo**, pero todavía no es una blockchain de dos nodos:
los 78 tests pasan porque prueban cada clase aislada, no las costuras entre ellas. Verificado
ejecutando el código:

- Cada nodo crea un génesis distinto (`time.time()`), así que dos nodos nunca pueden sincronizar.
- Nunca se verifican firmas: se aceptan TXs falsificadas y sin firmar.
- Se aceptan bloques sin prueba de trabajo, y `replace_chain` acepta cualquier cadena más larga,
  incluso con otro génesis.
- Las credenciales viven solo en memoria: son "válidas" antes de minarse y se pierden al reiniciar.
- PBFT no está conectado; la dificultad adaptativa se ignora; `sync.py`, `discovery.py`,
  `eclipse.py` y `hardening.py` no se importan en ningún lado.
- No existe un token real: `TOKEN_TRANSFER` no valida montos y el "balance" suma fees.

**Espíritu del proyecto:** construido desde cero, explicable en un paper, ejecutable en una RPi 5,
útil para enseñar. Las mejoras deben respetar eso.

## Cómo tomar un trabajo

1. Elegir un ID cuyas dependencias estén cerradas y anunciarlo (issue, chat o commit).
2. Escribir primero un test que falle y que pase por la costura (API o dos nodos).
3. Implementar, correr toda la suite, marcar la casilla aquí en el mismo commit `fix(P0-1): …`.

Flujos de trabajo y orden de dependencias:

| Flujo | Trabajos | Depende de |
| --- | --- | --- |
| A — Validez del núcleo | P0-1, P0-2, P0-3, P0-4, P0-9, P1-8 | — (va primero) |
| B — Red y sincronización | P0-5, P0-8, P2-9 | A |
| C — Credenciales | P0-6, P1-2, P1-3, P1-4 | A (en paralelo con B) |
| D — Operación y RPi | P0-7, P1-9, P1-10 | — (P0-7 es lo primero para cualquier colaborador) |
| E — Consenso PBFT | P1-1 | B |
| F — IA y seguridad | P1-5, P1-6, P1-7, P1-11 | — |
| G — Tokens y contratos | P1-12, P1-13, P2-11, P2-12 | A, P0-6 |

## P0 — Bloqueantes

- [x] **P0-1 Génesis determinista.** `block.py:create_genesis` usa `time.time()`. Génesis fijo
  (constante o `genesis.json` versionado, con la llave de autoridad UPB); rechazar peers con otro génesis.
  *Listo cuando:* dos nodos nuevos tienen el mismo hash de bloque 0.
- [x] **P0-2 Autenticación de TXs.** `transaction.py:is_valid` no verifica firmas y la TX no lleva
  llave pública. Agregar `public_key`, comprobar `address == derive(public_key)` y la firma ECDSA,
  rechazar TXs sin firma, incluir `fee` en el mensaje firmado.
  *Listo cuando:* una TX falsificada o sin firma recibe 400.
- [x] **P0-3 Validación completa de bloques.** `chain.py:_validate_block` no revisa PoW ni TXs.
  Validar dificultad esperada, rango de timestamp, cada TX, sin TX repetidas en la cadena. Separar
  "admisión al mempool" (expira en 1 h) de "validez de consenso" (para que resincronizar no rechace
  bloques viejos). *Listo cuando:* un bloque con dificultad 0 se rechaza y la cadena se revalida al cargar.
- [x] **P0-4 Dificultad adaptativa y minado sin bloquear la API.** `ProofOfWork(difficulty=4)`
  sobrescribe la dificultad del encabezado y `/blocks/mine` bloquea el event loop. Tomar la dificultad
  de `chain._calculate_difficulty()`, minar en un thread pool con un lock.
  *Listo cuando:* `/health` responde durante el minado y la dificultad tiende a ~10 s por bloque.
- [x] **P0-5 Sincronización P2P.** `node.py`: `GET_CHAIN` devuelve la petición en lugar de la cadena,
  `SYNC_REQUEST` responde altura 0, los peers anuncian `0.0.0.0`, no hay reconexión.
  `replace_chain` debe comprobar génesis y trabajo acumulado, devolver TXs huérfanas al mempool y
  llamar `on_chain_reorg`. *Listo cuando:* el nodo 2, arrancado después, alcanza al nodo 1 y se
  recupera tras una desconexión.
- [x] **P0-6 Credenciales derivadas de la cadena.** El estado del contrato = reproducción de TXs
  `CREDENTIAL_ISSUE`/`REVOKE` confirmadas (al iniciar y en cada bloque). Verificación devuelve
  `PENDING`/`CONFIRMED` con bloque y confirmaciones; endpoint de revocación firmado; registro de
  emisores por TX de administración firmada con la llave de autoridad del génesis.
  *Listo cuando:* emitir → minar → reiniciar → verificar da VÁLIDA en ambos nodos; tras revocar, REVOCADA.
- [x] **P0-7 Configuración de despliegue.** `setup_rpi.sh` usa `--workers 2` (dos cadenas en dos
  procesos, ambos en el puerto 8001); `.env` no se carga; `DATA_DIR`, `MINING_DIFFICULTY`,
  `LOG_LEVEL` se ignoran. Un worker por nodo, `load_dotenv`, cablear las variables, agregar
  `NODE_ADVERTISE_HOST`. *Listo cuando:* dos nodos locales usan directorios separados y un reinicio
  conserva la cadena.
- [x] **P0-8 Test de integración multinodo.** 2 (idealmente 4) nodos en puertos locales: minar en A
  y ver en B, partir y reunir la red, emitir en A y verificar en B. *Listo cuando:* corre en la suite y
  falla con el código actual.
- [x] **P0-9 Estado de cuentas.** Base para tokens y protección contra replay: saldo y `nonce` por
  dirección, montos enteros (unidad mínima; hoy `fee` es float), chequeo de saldo. Misma capa de
  "estado = reproducción de la cadena" que P0-6. *Listo cuando:* una TX repetida o sin saldo se rechaza.
  Hecho: `AccountState` en `state.py` (lo posee `Blockchain.accounts`); `nonce` firmado en toda TX
  (`nonce == confirmado + 1`, incluye credenciales); `fee` entera y quemada; `TOKEN_MINT` solo de la
  autoridad del génesis (sin cambiar `GENESIS_HASH`); un bloque con una TX sin saldo o nonce
  incorrecto se rechaza entero. API: `GET /accounts/{address}`, `POST /tokens/mint`,
  `POST /tokens/transfer`; `POST /transactions` acepta `nonce` (obligatorio si firma el cliente).
  Cadenas guardadas con TXs anteriores a P0-9 ya no validan (el `tx_id` incluye `nonce`): borrar
  `data/chain`.

## P1 — Funcionalidad prevista que no funciona

- [ ] **P1-1 PBFT real.** Switch `CONSENSUS=pow|pbft`, réplicas desde configuración, mensajes
  firmados por nodo, el primario cuenta su PREPARE, VIEW-CHANGE real, commit tras 2f+1. Con 2 nodos
  f=0: usar 4 réplicas (2 por RPi o una PC de laboratorio) para tolerar 1 falla.
- [ ] **P1-2 Datos personales fuera de la cadena.** Hoy nombre y nota quedan en claro en un registro
  inmutable. En cadena solo hash con sal (o raíz Merkle de campos con sal); el estudiante revela lo
  que quiera. Paso previo a ZKP.
- [x] **P1-3 Verificación por QR.** `GET /credentials/{id}/qr` (PNG) apuntando a una página pública
  `http` de verificación (estado, bloque, confirmaciones, emisor). `qrcode` ya está en requirements.
- [ ] **P1-4 Revocación e historial en el dashboard.** Formularios y el guion de TAREAS 3.1
  (5 emitidas, 1 revocada).
- [ ] **P1-5 Monitor de seguridad conectado.** Llamar `on_block`, `on_invalid_block`,
  `on_chain_reorg`, `on_unknown_peer`; aplicar (no solo alertar) el límite de 100 TX/min; alertas en
  vivo en el dashboard.
- [ ] **P1-6 Detección de anomalías medible (OE-4, AUC > 0,85).** Generador de carga con semilla y
  ataques etiquetados; reportar precisión/recall/F1/AUC vs heurística; persistir el modelo (joblib);
  corregir la regla `hour > 23` (nunca se cumple); quitar el efecto colateral de `GET /blocks/{i}`;
  anomalías → alertas del monitor.
- [x] **P1-7 Módulos muertos.** Integrar lo útil de `sync.py` en P0-5 y borrarlo; exponer
  `hardening.py` y `eclipse.py` en `/security/*` o eliminarlos.
- [x] **P1-8 Almacenamiento a prueba de cortes.** Escritura atómica de `chain.json` (temporal +
  fsync + rename) y respaldo (riesgo R-2, microSD).
- [x] **P1-9 Endpoints de administración protegidos.** API key o solo-local para minar, peers,
  emisores y poda; CORS restringido.
- [ ] **P1-10 Mediciones en RPi.** `scripts/bench_rpi.py` → `docs/benchmark_hardware.md` (hash rate,
  curva dificultad/tiempo, temperatura con `vcgencmd`, RAM, TPS); script de semilla de 50+ bloques;
  `pytest-cov` > 80 %. Lo ejecuta el dueño de las RPi.
- [x] **P1-11 Errores del simulador.** Con 50 % el reorg siempre ocurre pero se reporta
  `success=False` (usa `> 0.5`); el génesis infla el tiempo promedio de bloque.
- [ ] **P1-12 Tokens y insignias para estudiantes.** TXs `TOKEN_MINT` (solo emisores, con `reason`,
  dentro del presupuesto semestral), `TOKEN_TRANSFER`, `TOKEN_REDEEM` (quema en direcciones de
  canje), `BADGE_AWARD` (intransferible), `ISSUER_BUDGET` (llave de autoridad). Formas de ganar:
  premio del docente (individual o CSV), automático al emitir credencial, código QR de un solo uso en
  eventos, recompensas del laboratorio de ataques. Sin recompensa por minado (los mineros son nodos
  de la UPB). Puntos de circuito cerrado, sin valor monetario: confirmar con el área legal de la UPB.
- [ ] **P1-13 Interfaz única de contratos.** `apply(state, tx) -> state` determinista (sin reloj,
  azar ni floats), reproducida en cada nodo. Credential, Token, Badge y Voting como contratos de
  referencia; los estudiantes agregan nuevos por pull request.

## P2 — Mejoras

- [ ] **P2-1** Firma en el navegador (`@noble/secp256k1` o Ed25519): las llaves privadas no tocan el servidor; billetera web del estudiante.
- [ ] **P2-2** Pruebas de inclusión Merkle (`GET /tx/{id}/proof`) y verificador liviano.
- [ ] **P2-3** Credenciales como W3C Verifiable Credentials / Open Badges 3.0 con `did:web` para la UPB.
- [ ] **P2-4** Índice de bloques y estado en SQLite (fin de recorridos O(altura) y reescrituras completas).
- [ ] **P2-5** Dificultad por bits y elección de cadena por trabajo acumulado.
- [ ] **P2-6** Conexiones persistentes con TLS mutuo y lista blanca de nodos.
- [ ] **P2-7** Dashboard en vivo por WebSocket/SSE con progreso de minado (`mine_async_friendly`).
- [x] **P2-8** Docker Compose con 4 nodos y CI en GitHub Actions.
- [ ] **P2-9** Configuración tipada (`pydantic-settings`) y app factory en lugar de globales (desbloquea P0-8).
- [ ] **P2-10** Métricas Prometheus y tablero Grafana.
- [ ] **P2-11** Contratos desplegables por estudiantes: `CONTRACT_DEPLOY`/`CONTRACT_CALL` sobre una VM de
  pila hecha a mano (~500 líneas) con gas pagado en puntos de testnet. Nunca ejecutar Python del
  estudiante con `exec()`. Para Solidity, laboratorios aparte en una testnet pública (Sepolia), no
  compatibilidad EVM.
- [ ] **P2-12** Canjes (entradas, impresiones, turnos de laboratorio), premios automáticos por contrato
  y votación ponderada.

## Ideas fuera de lo común

1. **Laboratorio de ataques en vivo:** un nodo malicioso real intenta doble gasto, reorg del 51 % y
   Sybil; con `CONSENSUS=pbft` el mismo ataque falla frente al tribunal.
2. **Carrera de consensos:** la misma carga en PoW y PBFT, latencia/TPS/CPU lado a lado (figuras OE-2).
3. **Anclaje público:** sellar el hash de la cabeza en Bitcoin con OpenTimestamps cada N bloques.
4. **Kiosco verificador:** QR impreso en el diploma → página móvil con estado, prueba Merkle y anclaje.
5. **RPi consciente de temperatura:** controlador que ajusta la dificultad según la temperatura.
6. **Detección federada de anomalías** entre nodos.
7. **Alertas explicables** con contribución por característica.
8. **Elecciones estudiantiles** sobre el tipo `VOTE` existente.
9. **Arnés reproducible del paper:** `scripts/experiments/` regenera todas las tablas y figuras.

## Qué ve cada usuario

| Usuario | Tras P0 | Tras P1 | Tras P2 |
| --- | --- | --- | --- |
| Estudiante | — | Billetera, saldo, insignias, credenciales, transferir, votar, QR | Usa contratos de compañeros |
| Docente / emisor | Credenciales que sobreviven reinicios y llegan a todos los nodos | Portal: premiar puntos/insignias, carga CSV | Reglas de premio como contratos |
| Empleador / público | Verificación VÁLIDA / REVOCADA / PENDIENTE con confirmaciones | Escanea el QR del diploma, sin ver notas | Verifica prueba Merkle y anclaje sin confiar en la UPB |
| Estudiante desarrollador | API confiable y red local multinodo | Explorador, testnet con faucet, SDK Python | Despliega contratos propios |
| Operador (dueño de las RPi) | Nodo de un proceso, recupera su cadena | Llave de administración, alertas | mTLS, métricas, PBFT de 4 réplicas |

## Trabajo sin las Raspberry Pi

Casi todo se desarrolla en una laptop: el nodo es Python puro. Tras P0-7, cada nodo es un proceso
con sus puertos y su directorio (PowerShell, una terminal por nodo):

```powershell
$env:NODE_ID="node_2"; $env:NODE_PORT="8003"; $env:DATA_DIR="data/node_2"; $env:PEERS="127.0.0.1:8001"
venv\Scripts\python.exe -m uvicorn api.app:app --host 127.0.0.1 --port 8002
```

Solo la red LAN real, systemd, reinicios, temperatura y las cifras de hash rate/TPS del paper
requieren las RPi: el dueño ejecuta `scripts/bench_rpi.py` (P1-10) y devuelve los resultados.

## Decisiones abiertas

- ¿2 réplicas (solo PoW, f=0) o 4 réplicas (2 por RPi o un tercer equipo)? Define el valor de P1-1.
- Nombre del token y política de presupuesto por emisor.
- Visto bueno legal de la UPB para puntos de circuito cerrado y para datos personales (P1-2).
