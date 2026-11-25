# Contratos de estudiantes (P2-11)

Ejemplos en `.upbasm`, el ensamblador de la VM de pila de UPB-Chain. La referencia completa
(opcodes, gas, reglas) está en [`docs/vm.md`](../docs/vm.md). Cada ejemplo tiene su test de
punta a punta por la API en `tests/test_vm_contratos.py`.

| Archivo | Qué enseña |
|---------|------------|
| `contador.upbasm` | storage persistente, argumentos opcionales, `LOG` y `RETURN` |
| `colecta.upbasm` | `CALLVALUE`, `TRANSFER`, plazos con `BLOCKHEIGHT`, control de acceso con `CALLER`, `REVERT` con códigos |
| `acertijo.upbasm` | `HASH`, "los primeros N", marcas por dirección, y un fallo de diseño a propósito (front-running) |

## Probar sin nodo

```
venv\Scripts\python.exe scripts\upbasm.py ensamblar contratos_estudiantes\contador.upbasm
venv\Scripts\python.exe scripts\upbasm.py ejecutar contratos_estudiantes\contador.upbasm --args 5 --traza
venv\Scripts\python.exe scripts\upbasm.py ejecutar contratos_estudiantes\contador.upbasm --estado e.json
venv\Scripts\python.exe scripts\upbasm.py hash 42
```

`--estado e.json` guarda storage y saldo entre ejecuciones (como haría la cadena).

## Desplegar y llamar en un nodo

Con un nodo corriendo y una billetera con PUPB (el gas se paga en PUPB y se quema):

```
POST /vm/simulate        {"source": "<texto .upbasm>", "args": [5]}          # prueba, no cambia nada
POST /contracts/vm/deploy {"sender": "UPB…", "private_key_hex": "…", "source": "<texto>",
                           "storage": [[0, "UPB…beneficiario"], [1, 100], [2, 50]]}
POST /blocks/mine
POST /contracts/vm/call  {"sender": "UPB…", "private_key_hex": "…", "contract": "UPC…",
                          "args": [1], "value": 30}
POST /blocks/mine
GET  /contracts/vm/receipts/{tx_id}     # ok / revert / error y gas cobrado
GET  /contracts/vm/{address}            # storage, saldo, logs
```

Firmar en el servidor con `private_key_hex` es solo educativo y está en desuso (P2-1).

## Detalles de los ejemplos

**Colecta** (`ARG 0` = función): `1` aportar (antes del plazo, con `value`), `2` cobrar (el
beneficiario, desde el plazo, si se llegó a la meta: recibe todo), `3` reembolsar (desde el
plazo, si no se llegó: cada uno recupera lo suyo). Storage inicial: `[[0, beneficiario],
[1, meta], [2, plazo]]`. Códigos de `REVERT`: 10 cerrada, 11 sin value, 12 no autorizado,
13 todavía abierta, 14 sin meta, 15 meta alcanzada (no hay reembolso), 16 sin aporte.

**Acertijo**: storage inicial `[[0, HASH(respuesta)], [1, premio], [2, N]]`. Llamar sin
argumentos deposita fondos; con `ARG 0` = intento, gana si acierta, no ganó antes y quedan
cupos. Códigos: 20 sin cupos, 21 incorrecta, 22 ya ganó. **Fallo a propósito**: el intento
viaja en claro y se ve en el mempool; cualquiera puede copiarlo. Ejercicio: rediseñarlo con
compromiso y revelación (primero `HASH(respuesta, sal, dirección)`, después revelar).

## Ejercicios

1. Agregar al contador una función que solo el creador pueda llamar para ponerlo en 0
   (pista: guardar el creador en el storage inicial y compararlo con `CALLER`).
2. En la colecta, una llamada a "cobrar" o "reembolsar" que trae `value` se queda con esos
   PUPB. Corregirlo con `REVERT` si `CALLVALUE` ≠ 0.
3. Provocar un desborde: ¿qué pasa con `SUB` si la cuenta es 0? ¿Por qué `TRANSFER` igual no
   puede crear PUPB?
4. Medir con `--traza` cuánto gas cuesta cada función y explicar por qué `SSTORE` domina.
