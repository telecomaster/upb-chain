# Contratos en UPB-Chain (P1-13)

Un **contrato** es un conjunto de reglas que todos los nodos ejecutan igual sobre las
transacciones confirmadas. No es código que se sube a la cadena (eso es P2-11): es un módulo
Python del repositorio, revisado por pull request, que forma parte de las reglas de consenso.

## La idea en una línea

```
estado(H) = apply(... apply(apply(estado_inicial, tx_1, ctx_1), tx_2, ctx_2) ..., tx_n, ctx_n)
```

El estado de un contrato no se guarda en disco: se **deriva** reproduciendo en orden las TXs de
los bloques 1..H. Dos nodos con la misma cadena llegan al mismo estado; reiniciar un nodo o
reorganizar la cadena es volver a reproducir.

## La interfaz (`blockchain/contracts/base.py`)

```python
class Contract:
    NAME: str                      # nombre único: "accounts", "credentials", "voting", ...
    HANDLED_TYPES: frozenset       # tipos de TX que le interesan (None = todos)

    def initial_state(self): ...                       # estado vacío
    def validate(self, state, tx, ctx) -> (bool, str): # ¿es válida? PURA, no modifica nada
    def apply(self, state, tx, ctx) -> state:          # transición; solo si validate dio OK
```

- `tx` es la TX en dict (`type`, `sender`, `recipient`, `payload`, `nonce`, `fee`, `tx_id`).
  La firma ya la verificó la cadena: `tx["sender"]` es quien firmó.
- `ctx` (`TxContext`) trae `block_index`, `block_hash` y `block_timestamp` **del bloque**. En el
  mempool la TX todavía no tiene bloque: `block_index` y `block_hash` valen `None` y
  `block_timestamp` es la hora **estimada** del próximo bloque que pone el nodo (P1-12; `None` en
  la constante `MEMPOOL`). Al armar un bloque se usa la hora del encabezado del candidato, así el
  minero filtra con la misma hora que verá la red. La estimación es política local: lo que vale
  es la hora del bloque.
- `ctx.view("otro")` (P1-12) devuelve el estado de otro contrato, de **solo lectura** (ver
  "Lecturas entre contratos").
- `apply` puede modificar el `state` que recibe y devolverlo: el registro siempre le pasa una
  copia de trabajo. El estado confirmado solo cambia cuando el bloque entero fue válido.
- `execute(state, tx, ctx)` = `validate` + `apply` en un paso; útil en tests y ejemplos.

El **registro** (`blockchain/contracts/registry.py`, `ContractRegistry`) enruta cada TX a los
contratos que la manejan, guarda el estado confirmado de cada uno y lo expone a la API
(`blockchain.contract_state("voting")`). Una TX puede interesar a varios contratos: las cuentas
cobran `nonce` y `fee` a **todas**. El registro valida la TX en todos sus contratos y solo si
todos aceptan la aplica en todos (la TX es atómica).

## Lecturas entre contratos (P1-12)

Un contrato puede **leer** el estado de otro, nunca escribirlo:

```python
creds = ctx.view("credentials")            # None si ese contrato no está registrado
if creds is None or not creds.is_registered_issuer(sender):
    return False, "Solo un emisor registrado puede otorgar insignias"
```

El registro pasa en `ctx.views` su copia de trabajo de **todos** los contratos. Lo que se ve es
el estado justo **antes** de la TX actual: confirmado + TXs anteriores del mismo bloque (o + las
pendientes, en el mempool). Dentro de una TX todos los contratos validan primero y luego aplican,
así que el orden de registro no cambia lo que se lee. Es determinista porque solo depende del
orden de la cadena. Modificar un estado obtenido con `view` está prohibido: rompería la copia al
escribir y el estado confirmado.

Uso actual: `tokens` y `badges` preguntan a `credentials` si el sender es emisor registrado
(`ISSUER_REGISTER` sigue siendo la única alta de emisores), y `accounts` deja que `tokens`
autorice los `TOKEN_MINT` cuando ese contrato está registrado (sin él, solo la autoridad emite).

## Tokens e insignias (P1-12)

Puntos de **circuito cerrado, sin valor monetario** (nombre provisorio `TOKEN_SYMBOL = "PUPB"`,
"puntos UPB", en `blockchain/contracts/tokens.py`; nombre y visto bueno legal pendientes). Los
saldos los lleva `accounts`; `tokens` decide quién emite y dónde se canjea; `badges` guarda las
insignias. No hay recompensa por minado.

| TX | Quién firma | Regla |
|----|-------------|-------|
| `ISSUER_BUDGET` | autoridad | `{issuer_address, semester, amount}`: fija el presupuesto del emisor en ese semestre; no por debajo de lo ya emitido |
| `TOKEN_MINT` | autoridad (sin límite) o emisor | emisor: `reason` obligatorio, no a sí mismo, `amount` ≤ presupuesto restante del semestre **del bloque** |
| `TOKEN_TRANSFER` | dueño | como en P0-9 |
| `REDEEM_ADDRESS_REGISTER` | autoridad | `{redeem_address, label}`, una vez |
| `TOKEN_REDEEM` | dueño | `recipient` = dirección de canje registrada; el monto se **quema** (baja `total_supply`, el destino no recibe saldo) |
| `BADGE_AWARD` | emisor | `{badge_id, name, reason}`; una misma `badge_id` por dirección una sola vez; no existe TX para moverlas |

**Semestre.** `semester_of(ctx.block_timestamp)`: se trunca a segundos (`int`), se pasa a hora
de Bolivia (UTC−4, sin horario de verano) y se calcula la fecha con aritmética entera (sin
`datetime`). Enero–junio = `AAAA-1`, julio–diciembre = `AAAA-2`; el semestre 2 empieza el 1 de
julio a las 00:00:00 hora de Bolivia. Como la hora del bloque la elige el minero dentro de las
reglas de P0-3 (mayor que la mediana, a lo sumo 2 h en el futuro), un premio enviado en los
últimos minutos de un semestre puede caer en el siguiente; el minero lo descarta si ya no cabe.

## Canjes, premios automáticos y votación ponderada (P2-12)

**Orden de contratos (consenso).** No se agregó ningún contrato nuevo: el orden sigue siendo
`accounts, credentials, voting, tokens, badges`. P2-12 amplía `tokens` y `voting`
(`VotingContract` ahora recibe la dirección de la autoridad). Los contratos nuevos de otros
trabajos deben ir **al final** de `default_contracts`. Además, el `ctx` del mempool lleva
`block_index = altura + 1` (antes `None`) para validar ventanas por altura al admitir y al minar.

| TX | Quién firma | Regla |
|----|-------------|-------|
| `CATALOG_ITEM` | autoridad | `{item_id, title, price > 0, stock >= 0, redeem_address registrada}`; un `item_id` una sola vez. "Entradas", "impresiones" o "turnos de laboratorio" son solo datos de ejemplo, no están en el código |
| `TOKEN_REDEEM` + `item_id` | dueño | `amount == price`, `stock > 0`, `recipient == redeem_address` del ítem; descuenta 1 de stock y guarda un recibo con id `R-` + 16 primeros caracteres del `tx_id`. Sin `item_id` funciona como en P1-12 |
| `AWARD_RULE` | autoridad | `{rule_id, credential_type, issuer_address registrado, amount > 0}`; una regla por (tipo, emisor) |
| `ELECTION_CREATE` | autoridad o emisor | `{election_id, options (2-20), weight_rule, start_height, end_height}` + `badge_weights` o `cap` según la regla |

**Premio automático: la excepción a "TX inválida ⇒ bloque inválido".** `tokens` declara
`CREDENTIAL_ISSUE` en `HANDLED_TYPES` y premia con `auto_award(estado, tx, ctx)`, función pura
que lee la regla y el presupuesto del semestre del bloque. Si el presupuesto restante del
emisor no alcanza, **el premio se omite y la credencial se emite igual**; el bloque NO se
invalida. Motivo: el emisor firmó una credencial, no un premio; invalidar el bloque dejaría a un
emisor sin presupuesto sin poder emitir credenciales y permitiría que un presupuesto agotado por
otras TXs del mismo bloque tumbe una credencial válida. Es determinista (mismo estado previo y
misma hora de bloque en todos los nodos). Como los saldos son de `accounts`, ese contrato
acredita el monto llamando a la misma `auto_award` sobre `ctx.view("tokens")`: en una TX,
`accounts` aplica primero y `tokens` después, y ambos ven el estado previo a la TX, así que
coinciden (si se reordenaran los contratos, esto se rompería: no hacerlo).

**Votación ponderada.** Ventana por altura del bloque que incluye el voto
(`start_height <= altura <= end_height`; nunca por hora). Reglas de peso:
`one_per_address` (1), `by_badge` (el mayor peso entre las insignias que tiene la dirección en el
bloque del voto) y `by_pupb_balance_snapshot` (`min(saldo, cap)` según la foto de saldos tomada
justo antes de crear la elección, guardada en el estado). Voto de peso 0, fuera de ventana o con
opción inexistente: inválido (400 y bloque rechazado). `tally` devuelve totales ponderados. Las
elecciones sin `ELECTION_CREATE` siguen con la regla de P1-13 (un voto por dirección, sin
cierre, peso 1). API: `GET|POST /catalog`, `GET /catalog/receipts/{address}`,
`GET|POST /tokens/award-rules`, `GET|POST /elections`, `GET /contracts/voting/{id}` (con
`weighted`, `config` y `weights`). La billetera web (`/billetera`) lista el catálogo, las reglas
y las elecciones y firma el canje con `item_id` en el navegador.

## Elecciones estudiantiles (Idea 8)

Se apoya en `ELECTION_CREATE`/`VOTE` de P2-12 y añade, sin cambiar las reglas existentes:

- Campos opcionales del `ELECTION_CREATE`: `title`, `eligible_credential_type` y `eligible_program`
  (texto 1-64). Si hay elegibilidad, solo vota quien tiene una credencial ACTIVA de ese tipo y/o
  programa (se lee con `ctx.view("credentials")`; un voto de otro es inválido y rechaza el bloque).
- **Votos previos a la creación** (P2-12, cambio de consenso): un `VOTE` sobre un `election_id` sin
  configuración sigue siendo válido (elección "libre" de P1-13), pero ya no ocupa el id: la autoridad
  puede crear la elección después y los votos libres anteriores se descartan de forma determinista.
- `GET /elections` y `GET /elections/{id}` devuelven `status`: `pending` (aún no abre), `open` o
  `closed`, calculado con la altura confirmada (`closed` cuando ya existe el bloque `end_height`),
  más `turnout` (votantes y peso total).
- El resultado es **definitivo solo al cierre**: abierta, `tally` es `null` en `/elections/{id}`
  (el parcial sigue en `/contracts/voting/{id}`). Cerrada, trae `certification` con el recuento, el
  hash del bloque de cierre y un `digest` SHA-256 del JSON canónico, recalculable por cualquiera.
- Los votos son **públicos** en la cadena (dirección y opción): no hay voto secreto. Trabajo futuro:
  compromiso y revelación (commit-reveal) o pruebas de conocimiento cero.

## Una sola regla para TXs inválidas

> Si `validate` rechaza una TX de un bloque, **el bloque entero es inválido**, sea cual sea el
> contrato.

La misma `validate` decide también la admisión al mempool, contra el estado especulativo
(confirmado + pendientes): si la TX no es válida, la API responde **400**. El minero arma bloques
solo con pendientes que siguen siendo válidas (`filter_valid`), así que un nodo honesto nunca
mina un bloque que la red rechace.

Por qué una sola regla: el consenso es que todos los nodos acepten exactamente los mismos
bloques y lleguen al mismo estado. Con dos regímenes (cuentas rechazaba el bloque, credenciales
ignoraba la TX) cada contrato nuevo obligaba a decidir de nuevo y a razonar sobre bloques "válidos
pero con TXs muertas" que igual consumen nonce. Con una sola regla:

- lo que la API acepta es lo que la red acepta (mismo código);
- un bloque válido no tiene TXs ignoradas: todo lo que contiene tuvo efecto;
- un contrato nuevo solo escribe `validate` y `apply`; no decide política.

### Nota de compatibilidad (cambio de consenso)

Antes de P1-13 una TX de credenciales inválida (credencial duplicada, revocación ajena o repetida,
emisor no registrado) entraba en el bloque y se ignoraba al reproducir, y las TXs `VOTE` no se
validaban. `GENESIS_HASH` no cambia, pero una cadena guardada que contenga una de esas TXs ya no
valida al cargar: el nodo no arranca (`cadena inválida en disco: Bloque N: TX … inválida para
…`). En la práctica puede pasar si:

- se envió un `VOTE` por `POST /transactions` con otro payload (p. ej. el anterior
  `{"proposal_id", "vote"}`) o se votó dos veces;
- dos nodos minaron casi a la vez TXs de credenciales que entre sí se excluyen (la misma
  credencial con nonces distintos, dos revocaciones de la misma credencial).

Con un solo nodo usando el dashboard es muy improbable: el mempool ya rechazaba esas TXs de
credenciales (quedaba un caso raro: podar del mempool un `ISSUER_REGISTER` pendiente dejando
emisiones de ese emisor).
Si un nodo no arranca por esto, borrar `data/chain` (como con P0-9). Todos los nodos de la red
deben actualizarse juntos: un nodo viejo aceptaría bloques que uno nuevo rechaza.

### Credenciales: datos personales fuera de la cadena (P1-2, cambio de consenso)

`CREDENTIAL_ISSUE` ya no lleva `student_name`, `grade` ni `metadata`. El payload admitido es solo:
`program`, `degree`, `issue_date`, `credential_type`, `expiry_date` (opcional) y `fields_root`
(hex minúsculas de 64 caracteres, obligatorio). Cualquier otra clave, o las tres prohibidas,
hace que la TX no entre al mempool y que el bloque se rechace. El `credential_id` no cambia
(emisor + estudiante + título + fecha).

**Compromiso (`blockchain/core/commitment.py`).** Los campos privados (todo lo que el emisor
envíe en `credential_data` fuera de los públicos: nombre, nota, metadatos, `institution`...) se
comprometen así, con sha256:

- valor canónico = `json.dumps(valor, sort_keys=True, separators=(",", ":"), ensure_ascii=False)` en UTF-8;
- sal por campo = 16 bytes aleatorios (`secrets`), en hex (32 caracteres), generada en la API al emitir;
- hoja = `sha256(bytes(sal) || nombre_campo_utf8 || valor_canonico)` en hex;
- hojas ordenadas por nombre de campo; árbol de `blockchain/core/merkle.py` (nodo =
  `sha256(hex_izq + hex_der)`, último nodo duplicado si el nivel es impar);
- `fields_root` = raíz.

`POST /credentials/issue` devuelve **una sola vez** el `private_record`
(`{credential_id, fields, salts, fields_root}`). El nodo **no lo guarda** (ni en `data/` ni en la
cadena): se entrega al estudiante; si se pierde, los datos no se pueden demostrar.
`POST /credentials/disclosure` (cómputo puro) arma el paquete `{fields_root, revealed:[{name,
value, salt, proof}]}` para los campos elegidos y `POST /credentials/{id}/disclose-verify` lo
comprueba contra el `fields_root` confirmado en la cadena. Las páginas y endpoints públicos
(`/verify/{id}`, `/credentials/verify/{id}`, QR, historial) muestran solo campos públicos y la raíz.

Limitaciones: las hojas no llevan separación de dominio (ver `merkle.py`); el nombre del campo
entra en el hash, así que un valor no se puede presentar bajo otro campo. `get_stats_by_program`
ya no da `avg_grade/min_grade/max_grade` (la nota no está en la cadena) y `search_credentials`
busca solo por título/programa.

**Compatibilidad.** Las cadenas guardadas con credenciales en formato anterior (nombre/nota en
claro) ya no validan al cargar: borrar `data/chain` y actualizar todos los nodos a la vez. No hay
modo legado por altura (se prefirió la regla simple). Los datos en claro de cadenas ya publicadas
siguen en esas copias; este cambio solo evita nuevas filtraciones.

## Reglas de determinismo

Todos los nodos deben calcular exactamente lo mismo. Dentro de `validate` y `apply`:

1. **Sin reloj:** nada de `time.time()` ni `datetime.now()`. La única hora es
   `ctx.block_timestamp` (igual en todos los nodos; guardarla o compararla, no hacer aritmética
   de punto flotante con ella).
2. **Sin azar:** nada de `random`, `uuid4` ni `secrets`. Los IDs se derivan con hash de datos de
   la TX (ver `generate_credential_id`).
3. **Sin floats:** montos y contadores como `int` (unidad mínima). `0.1 + 0.2 != 0.3`.
4. **Orden estable:** no depender del orden de un `set`. Los `dict` conservan el orden de
   inserción, que aquí es el orden de la cadena.
5. **Sin entrada externa:** no leer archivos, red ni variables de entorno.
6. **Sin excepciones por datos raros:** el payload lo escribe cualquiera; comprobar tipos en
   `validate` (`isinstance`) y devolver `(False, motivo)` en vez de fallar.

`tests/test_contracts.py::test_contratos_sin_reloj_ni_azar` revisa las reglas 1–3 en los
contratos del repositorio.

## Recorrido: el contrato de votación (`blockchain/contracts/voting.py`)

Es la plantilla para copiar. Regla: cada dirección vota una vez por elección.

**1. El estado.** Un dataclass con lo mínimo y sus consultas:

```python
@dataclass
class VotingState:
    elections: Dict[str, Dict[str, str]] = field(default_factory=dict)  # elección → {votante → opción}

    def tally(self, election_id): ...   # {"lista-A": 2, "lista-B": 1}
```

**2. Qué TXs le interesan.** Reutiliza el tipo `VOTE` que ya existía:

```python
class VotingContract(Contract):
    NAME = "voting"
    HANDLED_TYPES = frozenset({"VOTE"})
```

**3. `validate`: todas las reglas, sin modificar nada.**

```python
    def validate(self, state, tx, ctx):
        payload = tx.get("payload")
        if not isinstance(payload, dict):
            return False, "payload debe ser un objeto"
        ...                                    # election_id y choice: texto de 1 a 64
        if state.has_voted(election_id, tx.get("sender", "")):
            return False, f"Ya votó en la elección {election_id}"
        return True, "OK"
```

**4. `apply`: la transición, sabiendo que la TX ya es válida.**

```python
    def apply(self, state, tx, ctx):
        payload = tx["payload"]
        state.elections.setdefault(payload["election_id"], {})[tx["sender"]] = payload["choice"]
        return state
```

**5. Registrarlo.** Agregarlo a `default_contracts` en `blockchain/contracts/__init__.py`. El
orden de la lista es parte del consenso.

**6. Exponerlo.** Una vista de solo lectura en `api/app.py`:

```
GET /contracts/voting/{election_id}
→ {"election_id": "consejo", "total_votes": 2, "tally": {"lista-A": 2},
   "voters": [...], "pending_votes": 0, "height": 7}
```

Para votar no hace falta un endpoint nuevo: `POST /transactions` con `type=VOTE`, `recipient`
no vacío (p. ej. `"VOTING_CONTRACT"`; vacío da 400 "Recipient vacío") y payload
`{"election_id": "consejo", "choice": "lista-A"}`. Un segundo voto de la misma dirección en la
misma elección responde 400, y un bloque que lo contenga se rechaza.

## Cómo proponer un contrato nuevo (pull request)

1. Elegir o crear un tipo de TX en `TransactionType` (`blockchain/core/transaction.py`). Un tipo
   nuevo no cambia `GENESIS_HASH`.
2. Copiar `voting.py` a `blockchain/contracts/<nombre>.py`; definir el estado, `NAME`,
   `HANDLED_TYPES`, `validate` y `apply`. Comentarios y docstrings en español.
3. Sumarlo a `default_contracts`.
4. Tests en `tests/` que pasen por la costura (API o dos nodos), al menos:
   - TX válida → 200 y, tras minar, el estado esperado;
   - TX inválida → 400 en la API **y** bloque rechazado si se mina a mano
     (`tests.helpers.mine_candidate(bc, [tx])` + `bc.add_block`);
   - determinismo: dos nodos con la misma cadena (`replace_chain` o recarga) dan el mismo estado.
5. Si el contrato necesita una vista, agregar un `GET` de solo lectura bajo `/contracts/<nombre>`.
6. Correr toda la suite y describir en el PR las reglas en una lista corta: es lo que los demás
   nodos van a ejecutar.

Lo que **no** va en un contrato: llamadas a la red, al disco o a servicios externos; código del
estudiante ejecutado con `exec()` (los contratos desplegables son P2-11, sobre una VM propia:
ver `docs/vm.md`; ahí una llamada que hace REVERT o se queda sin gas es válida y cobra gas,
única excepción a "TX inválida ⇒ bloque inválido").

## Códigos QR de evento de un solo uso (P1-12)

Sirven para premiar a quienes asisten a un evento sin conocer sus direcciones de antemano. Viven
en `tokens` (que ya tiene presupuestos y premios); **el orden de contratos no cambia**.
`accounts` acredita con la misma función pura `claim_award(ctx.view("tokens"), tx, ctx)`, igual
que con el premio automático.

| TX | Quién firma | Regla |
|----|-------------|-------|
| `EVENT_CODE_CREATE` | emisor registrado | `{code_id, event_pubkey (DER hex secp256k1), amount > 0, max_claims 1..10000, expires_height, reason}`; un `code_id` una sola vez |
| `EVENT_CODE_CLAIM` | estudiante | `{code_id, claim_sig}`; válida si el código existe, `altura del bloque <= expires_height`, quedan cupos, la dirección no lo reclamó, no es el emisor, `claim_sig` verifica y el emisor tiene presupuesto en el semestre del bloque |

**Contra el front-running.** En un mempool público, un código secreto dentro de la TX se
podría copiar y reenviar a nombre de otro. Por eso el QR lleva la **llave privada efímera** del
evento (`/billetera?evento=<code_id>&k=<hex>`) y la TX solo lleva `claim_sig`: firma ECDSA de esa
llave sobre `UPB-EVENT-CLAIM:v1|<GENESIS_HASH>|<code_id>|<dirección>` (`claim_message`). La firma
liga el génesis (no sirve en otra red), el código y la dirección del estudiante; copiarla desde
otra dirección falla. Quien tenga el QR puede reclamar una vez por dirección hasta agotar el
cupo: el control es el cupo, el vencimiento y el presupuesto, no el secreto del QR.

**Presupuesto: se cobra por reclamo, no se reserva al crear.** Crear el código no bloquea
presupuesto; cada reclamo descuenta `amount` del presupuesto del emisor en el semestre del bloque
que lo incluye. Si se agotó, ese reclamo es inválido (400 / bloque rechazado) y se puede reintentar
tras ampliar el presupuesto mientras el código siga vigente. Consecuencia: `amount * max_claims`
puede superar el presupuesto sin error al crear.

**API.** `POST /tokens/event-codes` (educativo, como `/tokens/award`: el emisor manda su llave
privada) genera la llave del evento y devuelve `code_id`, `event_private_key`, `claim_url` y el QR
en PNG (`qr_png_base64`); el nodo no guarda la llave del evento. `GET /tokens/event-codes/{id}`
da reclamos usados, cupos, vencimiento y estado `OPEN|EXPIRED|EXHAUSTED` (404 hasta confirmarse).
En `/billetera` el navegador firma el reclamo con la llave de la URL (`signEventClaim` en
`wallet-core.js`) y luego la TX con la llave del estudiante; hay test cruzado con `node`.
