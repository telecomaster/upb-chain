// Uso: echo '<json con {priv, casos:[{kind, args, nonce, fee, timestamp}]}>' | node cross_check.mjs (UTF-8 por stdin)
// Imprime las TX firmadas por la billetera JS (dashboard/static/wallet-core.js).
import { buildSignedTx, kinds } from '../../dashboard/static/wallet-core.js';

import { readFileSync } from 'node:fs';
const { priv, casos } = JSON.parse(readFileSync(0, 'utf-8'));
const salida = [];
for (const c of casos) {
  const campos = kinds[c.kind](...c.args);
  salida.push(await buildSignedTx(priv, { ...campos, nonce: c.nonce, fee: c.fee, timestamp: c.timestamp }));
}
console.log(JSON.stringify(salida));
