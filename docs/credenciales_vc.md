# Credenciales como Verifiable Credentials (P2-3)

Capa de **exportación e interoperabilidad**: no cambia el consenso ni lo que va en la cadena.
El formato está *alineado con* W3C Verifiable Credentials Data Model 2.0, Open Badges 3.0 y
`did:web`. **No está certificado ni validado** contra los esquemas/validadores oficiales (ver
"Qué está y qué no está validado").

Código: `blockchain/contracts/vc_export.py` (funciones puras), endpoints en `api/app.py`,
verificador independiente `scripts/verificar_vc.py` (solo biblioteca estándar; no importa `blockchain`).

## did:web de la UPB

`GET /.well-known/did.json` publica el documento DID. Dominio: `DID_WEB_DOMAIN` (p. ej.
`upb.edu.bo`); si está vacío, el host de `PUBLIC_BASE_URL` o el del request (el puerto se codifica
`%3A`, como pide did:web). **did:web exige servir ese archivo por HTTPS en ese dominio**
(`https://upb.edu.bo/.well-known/did.json`): el nodo habla HTTP, así que el despliegue en la Pi
debe poner un proxy inverso con TLS (y un dominio real) delante. Eso no está hecho aquí.

Cada llave es un `verificationMethod` `did:web:<dominio>#<dirección UPB>` de tipo `JsonWebKey`
(`kty: EC`, `crv: secp256k1`, `x`/`y` en base64url) para la autoridad y cada emisor registrado.
Las llaves públicas salen de las TX firmadas ya confirmadas (la cadena no guarda la llave al
registrar un emisor): un emisor registrado que aún no firmó ninguna TX no aparece hasta que lo haga.

## Endpoints

- `GET /credentials/{id}/vc`: la VC. 404 si la credencial no está confirmada.
- `POST /credentials/{id}/vc/disclose` con `{private_record, fields}` (igual que P1-2): VC con los
  campos privados elegidos, su sal y su prueba Merkle. 400 si el registro no reproduce el
  `fields_root` en cadena. El nodo no guarda el registro privado.

## Decisión de firma

**La VC se entrega sin `proof` propio.** El nodo no guarda la llave del emisor (la TX se firma en
el cliente, P1-2), así que no puede firmar la VC, y no se inventa una suite de firma. La prueba de
emisión es el **ancla en cadena** (`evidence` de tipo `UPBChainAnchor`): la TX `CREDENTIAL_ISSUE`
firmada por el emisor, el bloque que la contiene y la prueba Merkle. Consecuencia: una VC por sí
sola no se puede comprobar sin consultar un nodo; no es verificable sin conexión. Una firma
`ES256K` (JWS) hecha por el emisor/estudiante queda como trabajo futuro.

## Mapeo cadena → VC

| Cadena (`AcademicCredential`) | VC |
|---|---|
| `credential_id` | `id` = `{base}/credentials/{id}/vc`; `achievement.id` = `urn:upb-chain:credential:{id}` |
| `issuer_address` | `issuer.id` = `did:web:<dominio>#<dirección>` (id del `verificationMethod`) |
| `institution` | `issuer.name` |
| `student_address` | `credentialSubject.id` = `urn:upb-chain:address:<dirección>` |
| `degree` / `program` | `achievement.name` / `achievement.program`, `description` |
| `credential_type` | `achievement.achievementType` (DEGREE→Degree, POSTGRADE→MasterDegree, CERTIFICATION→Certificate, TRANSCRIPT→Diploma, AWARD→Achievement) |
| `issue_date` / `expiry_date` | `validFrom` / `validUntil` (fecha + `T00:00:00Z`: la cadena guarda solo el día) |
| estado (`/credentials/verify/{id}`) | `credentialStatus` tipo `UPBChainStatus` (instantánea + `id` con el estado vigente) |
| `tx_hash`, bloque, Merkle, `fields_root` | `evidence[0]` tipo `UPBChainAnchor`: `txId`, `blockIndex`, `blockHash`, `merkleRoot`, `leaf`, `merkleProof`, `fieldsRoot` |
| campos privados revelados | `credentialSubject.upbDisclosure` tipo `UPBSaltedFieldDisclosure`: `{fieldsRoot, revealed:[{name, value, salt, proof}]}` |

Los términos propios (`UPBChainAnchor`, `UPBChainStatus`, `UPBSaltedFieldDisclosure`...) caen bajo un
`@vocab` `https://<dominio>/ns/upb-chain#` que **no está publicado**.

## Cómo verifica un empleador

```
venv\Scripts\python.exe scripts\verificar_vc.py credencial.json http://nodo:8000
```

Comprueba contra el nodo indicado: (1) la llave del emisor está en `did.json` y es la que firmó la
TX; (2) el hash del bloque se recalcula, la TX está en él y la prueba Merkle la enlaza con la
raíz; el payload en cadena coincide con la VC; (3) la credencial no está revocada ni expirada;
(4) si hay divulgación, cada campo (valor + sal + prueba) pertenece al `fields_root` en cadena.
Salida 0 solo si todo pasa. El nodo consultado es la fuente de confianza: no se comprueba la
firma ECDSA de la TX ni que el bloque esté en la cadena canónica de otros nodos.

## Qué está y qué no está validado

- Validado por tests propios (`tests/test_vc_export.py`): forma de `did.json` y que las llaves son
  las de los emisores, miembros de la VC, anclas coherentes con `/tx/{id}/proof`, estado REVOKED,
  divulgación válida y manipulada, 404.
- **No validado**: esquema JSON de Open Badges 3.0, procesamiento JSON-LD/canonicalización,
  resolvedores did:web externos (necesitan HTTPS y dominio real), wallets o verificadores de
  terceros. No se afirma conformidad con ningún estándar.
- No hay `proof` criptográfico de la VC (ver arriba).
