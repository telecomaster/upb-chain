// Uso: echo '{"priv","genesis","codeId","address"}' | node event_claim_check.mjs
// Imprime la firma del reclamo de evento que produce dashboard/static/wallet-core.js (P1-12).
import { signEventClaim } from '../../dashboard/static/wallet-core.js';
import { readFileSync } from 'node:fs';
const { priv, genesis, codeId, address } = JSON.parse(readFileSync(0, 'utf-8'));
console.log(JSON.stringify({ sig: await signEventClaim(priv, genesis, codeId, address) }));
