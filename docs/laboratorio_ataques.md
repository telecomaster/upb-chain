# Laboratorio de ataques en vivo (Idea 1)

Un nodo malicioso **real** ataca a nodos honestos **reales**: todos corren en el mismo proceso,
hablan por sockets TCP en `127.0.0.1` con el protocolo P2P de siempre y validan con el mismo
código de cadena, contratos y consenso que un nodo de producción. Es el complemento práctico de
`security/attacks/simulator.py` y `eclipse.py`, que son modelos matemáticos.

- Código: `security/attacks/laboratorio.py` (escenarios que devuelven resultados estructurados).
- Línea de comandos: `scripts/laboratorio_ataques.py` (narración en español + JSON).
- Pruebas: `tests/test_laboratorio_ataques.py`.

```powershell
venv\Scripts\python.exe scripts\laboratorio_ataques.py --escenario doble_gasto --consenso pow
venv\Scripts\python.exe scripts\laboratorio_ataques.py --escenario doble_gasto --consenso pbft
venv\Scripts\python.exe scripts\laboratorio_ataques.py --escenario reorg --intentos 10 --semilla 7
venv\Scripts\python.exe scripts\laboratorio_ataques.py --escenario sybil --consenso pbft
venv\Scripts\python.exe scripts\laboratorio_ataques.py --escenario equivocacion --consenso pbft
```

Opciones: `--semilla N`, `--cuota` (% de hash del atacante, doble gasto PoW), `--confirmaciones`
(las que exige el comercio), `--cuotas 10,30,60` e `--intentos` (barrido), `--identidades`
(Sybil), `--bits` (dificultad PoW inicial), `--json` (solo JSON), `--verboso` (logs de los nodos).

## Cómo está armado

- **Nodos honestos**: `api.app.build_node`, la misma función que usa la API, arrancados como en el
  `lifespan` de la app (P2P, transporte y réplica PBFT). Tienen su monitor de seguridad: las
  alertas que muestra el laboratorio son las que levantaron ellos.
- **Nodo malicioso**: `NodoMalicioso`, subclase de `P2PNode` con una `Blockchain` real. Lo único
  distinto está marcado `MALICIOSO` en el código y afecta solo a SU nodo: retener una cadena
  privada y anunciarla al liberarla, mandar bloques o mensajes PBFT distintos a pares distintos y
  firmar votos/certificados falsos. **Nunca** se modifica ni se "parcha" el código de consenso de
  los honestos: si un ataque falla es porque sus reglas lo rechazan.
- **"51 %" en PoW**: no hay hardware distinto. La carrera avanza en rondas de 100 intentos de hash
  reales (SHA-256 con la dificultad que exige la regla de consenso, igual para todos); `--cuota`
  de ellos son del atacante y el resto del minero honesto. La cuota es tiempo de CPU dedicado a
  minar, **no** una dificultad más fácil (un bloque con menos bits sería inválido). Si una cadena
  cruza una época de 10 bloques, su dificultad se reajusta con la regla normal; por eso se compara
  trabajo acumulado. El atacante abandona si queda 4 bloques atrás.
- **Semilla**: fija los nonces iniciales y los parámetros. Las llaves ECDSA y las marcas de tiempo
  no son deterministas: dos corridas con la misma semilla pueden dar resultados distintos.

## Escenarios

### 1. Doble gasto (`doble_gasto`)

El atacante recibe 100 PUPB (bloque k-1), paga al comercio (TOKEN_TRANSFER en el bloque k) y, con
el mismo nonce, firma otra TX que manda esos fondos a un cómplice.

| Modo | Qué hace el atacante | Resultado esperado | Qué observar |
| --- | --- | --- | --- |
| `pow` | Mina en secreto una bifurcación desde k-1 con la TX del cómplice; cuando el comercio ya vio sus confirmaciones y la cadena privada tiene más trabajo, la libera. | Con cuota alta, el comercio hace `replace_chain`: su pago desaparece (la TX no vuelve al mempool porque su nonce ya está usado) y el cómplice cobra. | `pago_en_cadena_del_comercio=false`, `profundidad_reorg`, alerta `CHAIN_REORG` en el comercio (llega **después** del daño). |
| `pbft` | Controla la réplica r3 (tiene su llave real, f = 1). Libera una bifurcación más larga con certificados que llevan la firma real de r3 y firmas falsificadas de r0 y r1; inyecta un bloque con certificado falso sobre la punta y envía votos COMMIT falsificados. | Falla siempre: un bloque necesita 2f+1 = 3 firmas válidas de réplicas y un bloque certificado nunca se reemplaza. | Motivos de rechazo (`Certificado con firma inválida…`, `Certificado con 1 firmas; se necesitan 3`), alertas `INVALID_BLOCK`, mensajes PBFT rechazados, pago con certificado `OK`. |

### 2. Reorg del 51 % (`reorg`, solo PoW)

Barre la cuota del atacante (por defecto 10, 30, 45, 60, 75 y 90 %) con varias corridas pequeñas del
doble gasto y reporta la tasa de éxito y la profundidad del reorg. En `pbft` no aplica (no hay
carrera de trabajo; ver el doble gasto en pbft).

Medición de ejemplo, **en proceso en un portátil de desarrollo** (Windows 11, AMD64, Python 3.12.6;
nodos en un mismo intérprete, loopback), 10 corridas por cuota, semilla 7, 1 confirmación, 10 bits
iniciales. Con n = 10 son tasas de laboratorio, no probabilidades exactas ni cifras de las
Raspberry Pi; otra corrida dará números algo distintos:

| Cuota del atacante | Dobles gastos consumados | Profundidad media del reorg |
| --- | --- | --- |
| 10 % | 0/10 | — |
| 30 % | 3/10 | 1,67 |
| 45 % | 5/10 | 3,6 |
| 60 % | 10/10 | 1,0 |
| 75 % | 10/10 | 2,3 |
| 90 % | 10/10 | 1,0 |

Para discutir en clase: con 1 confirmación incluso una minoría del 30 % ganó a veces; con mayoría
ganó en todas estas corridas. Comparar con la fórmula de Nakamoto (sección 11 del artículo de
Bitcoin) teniendo en cuenta que aquí el atacante abandona a los 4 bloques de atraso. Probar
`--confirmaciones 3` para ver cómo cambian las cuotas minoritarias.

### 3. Sybil (`sybil`)

El atacante fabrica `--identidades` nodos (`sybil_0…`) y además usa el **único** certificado válido
que obtuvo de la CA de la red (CN = `atacante`, fuera de la lista blanca).

| Defensa | Resultado | Qué observar |
| --- | --- | --- |
| TLS mutuo + lista blanca (P2-6) | Ninguna identidad entra: los certificados de una CA pirata fallan en el apretón de manos TLS; el certificado válido se corta porque su CN no está en la lista (fabricar node_ids no cambia el CN); suplantar a un nodo permitido tampoco sirve. | `aceptados = 0`; alertas `UNKNOWN_PEER` (una por identidad, no por intento: `127.0.0.1 (certificado inválido)` y `atacante@127.0.0.1`). |
| Sin TLS | La lista blanca es **solo informativa**: el node_id anunciado no está autenticado, todos los Sybil quedan conectados y solo se avisa. Con suficientes Sybil se puede rodear a un nodo (eclipse). | `aceptados = identidades`; una alerta `… (no autenticado)` por Sybil. |
| PBFT (sin TLS) | Los Sybil votan COMMIT con sus propias llaves o suplantando a r0: la réplica descarta todos (firmante desconocido o firma inválida). En PBFT votan réplicas, no conexiones. | `votos_pbft.rechazados = enviados`, la altura no cambia. |

En PoW las identidades no votan (vota el hash), así que un Sybil sirve para aislar o eclipsar,
no para ganar el consenso.

### 4. Equivocación (`equivocacion`)

| Modo | Qué hace el atacante | Resultado esperado | Qué observar |
| --- | --- | --- | --- |
| `pbft` | Es r0, primario de la vista 0, y firma dos PRE-PREPARE distintos para la altura 1 (A a r1; B a r2 y r3; luego el otro a cada una). | Cada réplica honesta detecta los dos mensajes firmados (prueba de falla bizantina), no hay quórum, cambio de vista y el nuevo primario re-propone el bloque que llegó a "prepared": como máximo **un** bloque confirmado. | 3 alertas `PBFT_EQUIVOCATION`, vista ≥ 1 con primario ≠ r0, `bloques_distintos_confirmados_en_altura_1 = 1`. |
| `pow` | Mina dos bloques válidos para la altura 1 y entrega uno a cada nodo honesto. | No existe la noción de equivocación: ambos bloques son válidos, las puntas divergen (empate de trabajo) hasta el siguiente bloque, que provoca un reorg de 1. | Sin alertas de equivocación; `CHAIN_REORG` en el nodo que pierde. |

Hallazgo del laboratorio (PoW), corregido en P0-5: con dos bloques compitiendo, cada nodo honesto,
al recibir el bloque del otro, le pedía la cadena **dentro del mismo hilo de la conexión**; si los
dos lo hacían a la vez se esperaban mutuamente hasta el `timeout` del P2P (10 s). Ahora el nodo
sincroniza en un hilo aparte (`_sync_en_segundo_plano`), con una sola sincronización en vuelo por
par (las ráfagas de NEW_BLOCK se coalescen). En este portátil el escenario pasó de ~12.4 s a
~3.5 s de pared (incluye el arranque de los nodos). Prueba: `tests/test_p2p_sync.py`.

## Nota de seguridad

Solo para el laboratorio y la docencia. Todo escucha en `127.0.0.1`, los datos y certificados
viven en un directorio temporal que se borra al terminar y los nodos se detienen al salir. No
apuntar este código a nodos ajenos ni a la red de las Raspberry Pi.

## Recompensas (P1-12)

El laboratorio no tiene llave de emisor: **no acuña nada**. El flujo es:

```powershell
venv\Scripts\python.exe scripts\laboratorio_ataques.py --escenario equivocacion --consenso pbft --direccion UPB...
```

1. Si el escenario es premiable y se cumplió su logro, el JSON trae un `recibo` (escenario,
   consenso, semilla, dirección, resumen y `digest` SHA-256 que detecta alteraciones).
2. El docente (emisor registrado con presupuesto) lo envía a `POST /laboratorio/recompensas`
   (`issuer_address`, `private_key_hex` como en `/tokens/award`, y `recibo`; solo local o con
   `ADMIN_API_KEY`). El servidor **vuelve a correr** el escenario (3 a 5 s) y comprueba el logro:
   el recibo solo dice qué repetir, no es prueba. Si se cumple, el emisor firma `BADGE_AWARD`
   `lab-<escenario>` y `TOKEN_MINT` de 10 PUPB con motivo `laboratorio:<escenario>`.
   `GET /laboratorio/recompensas` lista los escenarios premiables.
3. Una sola vez por dirección y escenario: la insignia es única (`409` si ya la tiene; la insignia se
   envía antes que los puntos, así un duplicado pendiente tampoco cobra dos veces).

Premiables (desenlace determinista: la defensa gana): `doble_gasto`, `sybil` y `equivocacion` en
`pbft`. Los de PoW y el barrido del 51 % son azarosos y no se premian.

**Alternativa descartada**: un código de evento (`EVENT_CODE_*`) impreso al terminar el laboratorio.
Un estudiante podría compartir el enlace sin correr nada, y el laboratorio tendría que conocer la
llave del evento. **Límite honesto del diseño elegido**: se verifica que el escenario es reproducible
con esa semilla, no que *ese* estudiante lo corrió (la dirección es una etiqueta); lo respalda el
docente al entregar el recibo, como en un premio manual.

## Pendiente

- Correr el laboratorio entre dos máquinas reales (las RPi) en vez de en un solo proceso.
