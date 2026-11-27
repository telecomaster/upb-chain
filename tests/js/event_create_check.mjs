// Uso: echo '{"priv","codeId","amount","maxClaims","expires","reason","nonce","timestamp"}' | node event_create_check.mjs
// Imprime la TX EVENT_CODE_CREATE firmada por la billetera JS, la llave del evento y la llave DER (P1-12).
import { buildSignedTx, kinds, newEventKey, privateKeyDer } from '../../dashboard/static/wallet-core.js';
import { readFileSync } from 'node:fs';
const a = JSON.parse(readFileSync(0, 'utf-8'));
const evento = newEventKey();
const campos = kinds.eventCreate(a.codeId, evento.pub, a.amount, a.maxClaims, a.expires, a.reason);
const tx = await buildSignedTx(a.priv, { ...campos, nonce: a.nonce, timestamp: a.timestamp });
console.log(JSON.stringify({ tx, evento, der: privateKeyDer(a.priv) }));
