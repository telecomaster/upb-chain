# VM de pila para contratos de estudiantes (P2-11)

Los contratos de `blockchain/contracts/` (credenciales, votación, tokens…) son reglas
escritas en Python y revisadas por pull request (ver `docs/contratos.md`). Esta VM es otra
cosa: permite que un **estudiante despliegue su propio contrato** en la cadena, sin pull
request, como **bytecode** que todos los nodos ejecutan igual.

| Archivo | Qué tiene |
|---------|-----------|
| `blockchain/vm/machine.py` | el intérprete: opcodes, gas, límites (~300 líneas) |
| `blockchain/vm/asm.py` | ensamblador/desensamblador del lenguaje `.upbasm` |
| `blockchain/contracts/programs.py` | reglas de `CONTRACT_DEPLOY`/`CONTRACT_CALL`, cobro de gas |
| `scripts/upbasm.py` | CLI: ensamblar, desensamblar, ejecutar contra un estado local |
| `contratos_estudiantes/` | ejemplos: contador, colecta con plazo, acertijo con premio |

## Por qué una VM propia y nunca `exec()`

Ejecutar Python del estudiante (`exec`, `eval`, `importlib`…) sería entregarle el nodo:
podría leer las llaves de `data/`, abrir sockets, leer el reloj (y romper el consenso),
quedarse en un bucle infinito o agotar la memoria. Ningún "sandbox" de Python es confiable
para eso. La VM, en cambio, **solo sabe hacer lo que está en la tabla de abajo**:

- **sin E/S**: no hay instrucción para archivos, red ni variables de entorno;
- **sin reloj ni azar**: la única noción de tiempo es `BLOCKHEIGHT`, la altura del bloque;
- **solo enteros**: palabras de 256 bits sin signo; no hay floats;
- **terminación garantizada**: cada instrucción cuesta gas y el gas es finito
  (`MAX_GAS_LIMIT` = 200 000 por TX), así que un bucle infinito termina en "sin gas";
- **memoria acotada**: pila ≤ 256, storage ≤ 256 casillas, código ≤ 4096 bytes,
  ≤ 16 LOG y ≤ 16 TRANSFER por llamada, últimos 100 logs guardados por contrato;
- **sin llamadas entre contratos (v1)**: un contrato no puede llamar a otro. Evita la
  reentrada (el error del caso "The DAO") y mantiene la VM chica. Queda para una v2.

`tests/test_vm.py` revisa con el AST que `machine.py`, `asm.py` y `programs.py` no importen
`time`, `random`, `os`… ni nombren `exec`, `eval`, `open` o `float`.

## El modelo

- **Palabra**: entero sin signo de 256 bits. La aritmética es **módulo 2²⁵⁶** (como en la
  EVM): `0 − 1 = 2²⁵⁶ − 1`. Se eligió a propósito: el desborde silencioso es un error clásico
  de contratos y conviene verlo en clase. Lo que no se puede es crear PUPB con él: `TRANSFER`
  comprueba el saldo real del contrato. Dividir por 0 es un error de ejecución.
- **Pila**: operandos y resultados. `PUSH 7`, `PUSH 2`, `SUB` deja `5` (el tope es el
  segundo operando: `a b → a − b`).
- **Storage**: diccionario palabra → palabra, propio de cada contrato, persistente entre
  llamadas. Guardar 0 borra la casilla (no cuenta para el límite).
- **Entorno**: `CALLER` (dirección de quien firmó la TX, como entero de 128 bits: los 32
  hex de `UPB…`), `CALLVALUE` (PUPB enviados), `BLOCKHEIGHT`, `ARG n`, `NARGS`, `BALANCE`
  (PUPB del contrato, ya con `CALLVALUE` sumado).
- **Saltos**: `JUMP`/`JUMPI` sacan el destino de la pila y solo pueden ir a la posición de
  una instrucción `JUMPDEST`. Un byte `0x5B` que está **dentro del dato de un `PUSH`** no es
  un destino válido (se decodifica el código entero antes de ejecutar).

## Opcodes y gas

Codificación: 1 byte de opcode. `PUSH` lleva 1 byte de largo L (0..32) y L bytes
big-endian; `ARG`, `DUP` y `SWAP` llevan 1 byte. "Pila" muestra lo que se saca → lo que se
pone (el tope a la derecha).

| Código | Nombre | Gas | Pila / efecto |
|--------|--------|-----|---------------|
| `0x00` | `STOP` | 0 | termina con éxito, sin valor |
| `0x01` | `ADD` | 3 | a b → a+b (mód 2²⁵⁶) |
| `0x02` | `SUB` | 3 | a b → a−b (mód 2²⁵⁶) |
| `0x03` | `MUL` | 5 | a b → a·b (mód 2²⁵⁶) |
| `0x04` | `DIV` | 5 | a b → a // b (b = 0 es error) |
| `0x05` | `MOD` | 5 | a b → a % b (b = 0 es error) |
| `0x10` | `LT` | 3 | a b → 1 si a < b, si no 0 |
| `0x11` | `GT` | 3 | a b → 1 si a > b, si no 0 |
| `0x12` | `EQ` | 3 | a b → 1 si a = b, si no 0 |
| `0x13` | `ISZERO` | 3 | a → 1 si a = 0, si no 0 |
| `0x14` | `AND` | 3 | a b → a AND b (bit a bit) |
| `0x15` | `OR` | 3 | a b → a OR b |
| `0x16` | `XOR` | 3 | a b → a XOR b |
| `0x17` | `NOT` | 3 | a → NOT a (256 bits) |
| `0x20` | `HASH` | 30 | a → sha256(a en 32 bytes big-endian) |
| `0x30` | `CALLER` | 2 | → dirección de quien firmó la TX |
| `0x31` | `CALLVALUE` | 2 | → PUPB enviados con la llamada |
| `0x32` | `BLOCKHEIGHT` | 2 | → altura del bloque |
| `0x33` | `ARG` | 3 | → argumento n (inmediato; no existe = error) |
| `0x34` | `NARGS` | 2 | → cantidad de argumentos |
| `0x35` | `BALANCE` | 5 | → PUPB del contrato (incluye CALLVALUE) |
| `0x40` | `POP` | 2 | a → |
| `0x41` | `DUP` | 3 | copia el n-ésimo desde arriba (1 = tope) |
| `0x42` | `SWAP` | 3 | intercambia el tope con el (n+1)-ésimo |
| `0x50` | `SLOAD` | 50 | clave → storage[clave] (0 si no existe) |
| `0x51` | `SSTORE` | 200 | valor clave → (storage[clave] = valor) |
| `0x56` | `JUMP` | 8 | destino → (salta; debe ser JUMPDEST) |
| `0x57` | `JUMPI` | 10 | cond destino → (salta si cond ≠ 0) |
| `0x5B` | `JUMPDEST` | 1 | marca un destino de salto |
| `0x60` | `PUSH` | 3 | → constante de hasta 32 bytes |
| `0xA0` | `LOG` | 50 | a → (queda en los logs del contrato) |
| `0xF0` | `TRANSFER` | 100 | monto dirección → (PUPB del contrato a la dirección) |
| `0xF3` | `RETURN` | 0 | a → termina con éxito y devuelve a |
| `0xFD` | `REVERT` | 0 | código → fracasa: revierte todo, cobra el gas usado |

Gas fijo además de las instrucciones: **100** por llamada (`CALL_BASE_GAS`); el despliegue
cuesta **1000 + 20 por byte de código + 200 por casilla de storage inicial**. Los costos
son relativos (SSTORE es caro porque todos los nodos guardan el dato para siempre), no
mediciones de tiempo.

## El lenguaje `.upbasm`

```
; comentario (también con #)
.const CUENTA 0          ; constante con nombre
    NARGS
    JUMPI con_arg        ; azúcar: "OP x" = "PUSH x" + "OP"
    PUSH 1
    JUMP sumar
con_arg:                 ; una etiqueta emite un JUMPDEST y vale su posición en bytes
    ARG 0
sumar:
    SLOAD CUENTA         ; = PUSH 0 + SLOAD
    ADD
    DUP 1
    SSTORE CUENTA
    RETURN
```

- Literales: decimal, `0x…`, una dirección `UPB…` (se convierte al entero de 128 bits que
  apila `CALLER`), una constante o una etiqueta.
- El azúcar `OP x` vale para toda instrucción que saca algo de la pila: `SSTORE 3`,
  `EQ 1`, `REVERT 12`, `JUMPI fin`. Con `CALLER 5` el ensamblador da error.
- Los errores dicen la línea: `línea 7: instrucción desconocida: PUHS`.

CLI (sin nodo; el estado es un JSON local):

```
venv\Scripts\python.exe scripts\upbasm.py ensamblar contratos_estudiantes\contador.upbasm
venv\Scripts\python.exe scripts\upbasm.py ejecutar contratos_estudiantes\contador.upbasm --args 5 --traza
venv\Scripts\python.exe scripts\upbasm.py ejecutar colecta.upbasm --estado e.json --storage 2=10 --args 1 --value 30
venv\Scripts\python.exe scripts\upbasm.py hash 42
```

## Las TXs y el gas en PUPB

| TX | recipient | payload |
|----|-----------|---------|
| `CONTRACT_DEPLOY` | `contract_address(sender, nonce)` = `"UPC"` + 32 hex de sha256(`"sender:nonce"`) | `{code: hex, storage?: [[clave, valor], …], gas_limit, gas_price}` |
| `CONTRACT_CALL` | dirección del contrato | `{args: [int, …], value, gas_limit, gas_price}` |

- `gas_price` ≥ 1 PUPB por unidad de gas; `gas_limit` ≤ 200 000. El sender necesita saldo
  ≥ `fee + value + gas_limit × gas_price` (el peor caso).
- Se cobra el gas **usado** × `gas_price` y se **quema** (como el fee: no hay recompensa de
  minado). El despliegue cobra su gas fijo. Lo quemado se suma a `burned_fees`.
- `value` pasa del sender al contrato solo si la llamada termina bien; `TRANSFER` mueve
  PUPB del contrato a una dirección `UPB…`. Los saldos de los contratos los guarda el
  contrato `vm`; vale `Σ saldos + Σ saldos de contratos = total_supply`. Por eso
  `TOKEN_TRANSFER`/`TOKEN_MINT` a una dirección `UPC…` son inválidas: para darle PUPB a un
  contrato se usa `CONTRACT_CALL` con `value`.

### Regla de validez: fracasar no es ser inválida

La regla general de UPB-Chain es "TX inválida ⇒ bloque inválido" (`docs/contratos.md`).
Una llamada que **se queda sin gas, hace `REVERT` o falla** (pila vacía, salto inválido,
división por 0, `TRANSFER` sin saldo) es en cambio una **TX válida**: entra al bloque,
consume el nonce, **cobra el gas** y no cambia nada más (storage, logs, `value` y saldos del
contrato vuelven a como estaban). Es la regla de Ethereum, y la razón es económica: para
saber si una llamada fracasa hay que ejecutarla, y ese trabajo lo hizo toda la red. Si la
TX fuera inválida nadie lo pagaría y un atacante mandaría bucles infinitos gratis.

| Fracaso | Gas cobrado |
|---------|-------------|
| `REVERT` | el usado hasta ahí (el contrato "se rinde" con cortesía) |
| sin gas, o cualquier error de ejecución | **todo** el `gas_limit` |

Por eso la validez depende solo de lo que se comprueba **sin ejecutar**. Son **inválidas**
(400 en la API y bloque rechazado):

- payload mal formado (tipos, rangos, claves desconocidas, > 16 argumentos);
- saldo < `fee + value + gas_limit × gas_price`;
- `gas_price` < 1, `gas_limit` < gas mínimo (100 para llamar, el gas del despliegue para
  desplegar) o > 200 000;
- despliegue: bytecode mal formado (opcode desconocido, `PUSH` truncado o > 32 bytes, dato
  inmediato fuera de rango, código vacío o > 4096 bytes), storage inicial con más de 256
  casillas, claves repetidas o valores 0, o `recipient` distinto de la dirección derivada;
- llamada: contrato inexistente.

El resultado de cada TX queda en un **recibo**: `GET /contracts/vm/receipts/{tx_id}` →
`status` (`ok`/`revert`/`error`), `error`, `gas_used`, `cost`, `return_value`, `transfers`.

### Cómo se mueven los PUPB sin romper "un contrato no escribe a otro"

Los saldos son del contrato `accounts` (siempre primero en el registro); storage, logs y
saldos de contratos son del contrato `vm` (último en `default_contracts`). Los dos llaman a
la misma función pura `programs.execute_call(estado_vm_previo, tx, ctx)`: `accounts` lee el
estado de la VM con `ctx.view("vm")` (todavía el previo a la TX) y aplica gas, `value` y
`TRANSFER`; `vm` aplica storage, logs y saldo del contrato. Como la ejecución es
determinista, coinciden; el costo es ejecutar dos veces, acotado por el gas.

`BLOCKHEIGHT` es `ctx.block_index`. En el mempool la TX no tiene bloque: el registro pone
`block_index` = altura + 1 (desde P2-12), así el minero arma el bloque con la misma altura que verá
la red.

## API

| Método | Ruta | Qué hace |
|--------|------|----------|
| POST | `/vm/assemble` | `{source}` → `{code, size, disassembly}` |
| POST | `/vm/simulate` | ejecución de prueba **sin cambiar estado**: `{contract}` o `{code\|source, storage, balance}` + `{caller, args, value, gas_limit, block_height, trace}` → estado, gas, retorno, storage, logs, traza (≤ 500 pasos) |
| POST | `/contracts/vm/deploy` | `{sender, private_key_hex, code\|source, storage, gas_limit?, gas_price}` → `{tx_id, address}` |
| POST | `/contracts/vm/call` | `{sender, private_key_hex, contract, args, value, gas_limit, gas_price}` → `{tx_id}` |
| GET | `/contracts/vm` | contratos desplegados |
| GET | `/contracts/vm/{address}` | código, desensamblado, storage, saldo, logs |
| GET | `/contracts/vm/{address}/storage/{key}` | una casilla |
| GET | `/contracts/vm/{address}/logs` | últimos logs |
| GET | `/contracts/vm/receipts/{tx_id}` | recibo de una TX de contrato |

`deploy` y `call` firman en el servidor con `private_key_hex`: **solo educativo y en
desuso**, como los demás endpoints con llave desde P2-1 (la respuesta trae `warning`). Para
uso real se firma en el cliente y se envía por `POST /transactions` con `type`
`CONTRACT_DEPLOY`/`CONTRACT_CALL`. En `args` y `storage` la API acepta direcciones `UPB…` y
las convierte a entero; en la TX solo van enteros. La billetera web (`/billetera`) todavía
no arma estas TXs (queda pendiente para no agrandarla).

Los valores de storage pueden tener hasta 256 bits: la API los devuelve como enteros JSON;
un cliente JavaScript debe leerlos con `BigInt` (más allá de 2⁵³ un `Number` pierde
precisión).

## Ejemplos (`contratos_estudiantes/`)

Ver `contratos_estudiantes/README.md`: contador, colecta con plazo por altura de bloque y
acertijo con premio para los primeros N. Cada uno tiene su test en
`tests/test_vm_contratos.py`, por la API.

## Fuera de alcance

- Compatibilidad EVM o Solidity: para Solidity, laboratorios aparte en una testnet pública
  (Sepolia). Esta VM se parece a la EVM a propósito (pila, gas, storage, `REVERT`) para que
  lo aprendido se traslade, pero no ejecuta su bytecode.
- Llamadas entre contratos, creación de contratos desde contratos, memoria temporal
  (`MLOAD`/`MSTORE`), eventos con tópicos: candidatos para una v2.
