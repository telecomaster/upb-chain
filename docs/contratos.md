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
  mempool la TX todavía no tiene bloque y los tres valen `None`.
- `apply` puede modificar el `state` que recibe y devolverlo: el registro siempre le pasa una
  copia de trabajo. El estado confirmado solo cambia cuando el bloque entero fue válido.
- `execute(state, tx, ctx)` = `validate` + `apply` en un paso; útil en tests y ejemplos.

El **registro** (`blockchain/contracts/registry.py`, `ContractRegistry`) enruta cada TX a los
contratos que la manejan, guarda el estado confirmado de cada uno y lo expone a la API
(`blockchain.contract_state("voting")`). Una TX puede interesar a varios contratos: las cuentas
cobran `nonce` y `fee` a **todas**. El registro valida la TX en todos sus contratos y solo si
todos aceptan la aplica en todos (la TX es atómica).

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

Para votar no hace falta un endpoint nuevo: `POST /transactions` con `type=VOTE` y payload
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
estudiante ejecutado con `exec()` (los contratos desplegables son P2-11, sobre una VM propia).
