// Uso: echo '<json>' | node kiosco_cross_check.mjs (UTF-8 por stdin)
// Entrada: {merkle:[{leaves, proofs:[{leaf, proof}]}], campos:[{name, value, salt}]}
// Salida: raíces recalculadas, validez de cada prueba y hojas de campo, con el kiosco.js real.
import { merkleRootFromLeaves, verifyProof, fieldLeaf } from '../../dashboard/static/kiosco.js';
import { readFileSync } from 'node:fs';

const { merkle, campos } = JSON.parse(readFileSync(0, 'utf-8'));
const salida = { raices: [], pruebas: [], hojas: [] };
for (const m of merkle) {
  const raiz = await merkleRootFromLeaves(m.leaves);
  salida.raices.push(raiz);
  const oks = [];
  for (const p of m.proofs) oks.push(await verifyProof(p.leaf, p.proof, raiz));
  salida.pruebas.push(oks);
}
for (const c of campos) salida.hojas.push(await fieldLeaf(c.name, c.value, c.salt));
console.log(JSON.stringify(salida));
