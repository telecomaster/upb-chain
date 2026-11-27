// Uso: echo '<json>' | node kiosco_verificar_local.mjs (UTF-8 por stdin)
// Entrada: {casos:[{id, tx_id, bloque, prueba, consenso, cert}]}. Salida: lista de comprobaciones por caso,
// calculadas con kiosco.js real (verificarLocal).
import { verificarLocal, hashBloque } from '../../dashboard/static/kiosco.js';
import { readFileSync } from 'node:fs';

const { casos } = JSON.parse(readFileSync(0, 'utf-8'));
const salida = [];
for (const c of casos) {
  salida.push({
    checks: await verificarLocal({ id: c.id, txIdEsperado: c.tx_id, bloque: c.bloque,
      prueba: c.prueba, consenso: c.consenso, cert: c.cert }),
    hash: await hashBloque(c.bloque) });
}
console.log(JSON.stringify(salida));
