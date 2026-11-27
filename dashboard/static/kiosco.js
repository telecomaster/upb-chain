// Kiosco verificador (idea 4). Módulo ES sin dependencias: las funciones puras (Merkle y
// compromiso de campos) se comprueban contra Python en tests/js/kiosco_cross_check.mjs.
// Reproduce blockchain/core/merkle.py: nodo = sha256(hex_izq + hex_der) sobre la CADENA hex,
// y si un nivel es impar se duplica el último nodo.

import { secp, sha256 as sha256Bytes } from './vendor/noble-secp256k1.bundle.js';
import { txId, signingMessage, addressFromPublicKey, canonical, fromHex } from './wallet-core.js';

const enc = new TextEncoder();
const subtle = globalThis.crypto.subtle;

function aHex(buf) {
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
}
function deHex(h) {
  if (h.length % 2 || /[^0-9a-f]/i.test(h)) throw new Error('hex inválido');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  return out;
}
export async function sha256Hex(bytes) {
  return aHex(await subtle.digest('SHA-256', bytes));
}
const sha256Texto = (t) => sha256Hex(enc.encode(t));

export async function merkleRootFromLeaves(hojas) {
  if (!hojas.length) return sha256Hex(new Uint8Array(0));
  let nivel = [...hojas];
  while (nivel.length > 1) {
    if (nivel.length % 2) nivel.push(nivel[nivel.length - 1]);
    const sig = [];
    for (let i = 0; i < nivel.length; i += 2) sig.push(await sha256Texto(nivel[i] + nivel[i + 1]));
    nivel = sig;
  }
  return nivel[0];
}

// Recalcula la raíz desde la hoja y el camino [{hash, position: 'left'|'right'}].
export async function verifyProof(hoja, prueba, raiz) {
  let actual = hoja;
  for (const paso of prueba) {
    if (paso.position === 'left') actual = await sha256Texto(paso.hash + actual);
    else if (paso.position === 'right') actual = await sha256Texto(actual + paso.hash);
    else return false;
  }
  return actual === raiz;
}

// json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
// Limitación: un float entero (1.0) se serializa "1" aquí y "1.0" en Python.
export function valorCanonico(v) {
  if (Array.isArray(v)) return '[' + v.map(valorCanonico).join(',') + ']';
  if (v !== null && typeof v === 'object') {
    return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + valorCanonico(v[k])).join(',') + '}';
  }
  return JSON.stringify(v);
}

// hoja = sha256(bytes(sal) || nombre utf-8 || valor canónico utf-8), como commitment.field_leaf.
export async function fieldLeaf(nombre, valor, salHex) {
  const partes = [deHex(salHex), enc.encode(nombre), enc.encode(valorCanonico(valor))];
  const todo = new Uint8Array(partes.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of partes) { todo.set(p, o); o += p.length; }
  return sha256Hex(todo);
}

export async function verifyField(raiz, item) {
  try {
    return await verifyProof(await fieldLeaf(item.name, item.value, item.salt), item.proof, raiz);
  } catch (e) { return false; }
}

// ── Verificación local de una credencial (idea 4) ────────────────────────────
// Todo se recalcula aquí a partir del bloque completo y el certificado: NO se confía en
// la hoja, la prueba ni el hash que informa el nodo. Cada comprobación devuelve
// {ok: true|false|null, texto}; null = no aplica / no verificable (nunca cuenta como éxito).

// json.dumps(v, sort_keys=True) con ensure_ascii=False y separadores ", " y ": " (hash del bloque).
// Limitación: un float entero (1.0) se escribe "1" aquí y "1.0" en Python (los timestamps son time.time()).
export function jsonPySinAscii(v) {
  if (Array.isArray(v)) return '[' + v.map(jsonPySinAscii).join(', ') + ']';
  if (v !== null && typeof v === 'object') {
    return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ': ' + jsonPySinAscii(v[k])).join(', ') + '}';
  }
  return JSON.stringify(v);
}

export const hojaDeTx = (tx) => sha256Texto(canonical(tx));   // sha256(json.dumps(tx, sort_keys=True))

export async function hashBloque(bloque) {
  const h = bloque.header;
  return sha256Texto(jsonPySinAscii({
    index: h.index, timestamp: h.timestamp, previous_hash: h.previous_hash,
    merkle_root: h.merkle_root, nonce: h.nonce, difficulty: h.difficulty,
    version: h.version, node_id: h.node_id, transactions: bloque.transactions }));
}

export const cumpleBits = (hashHex, bits) =>
  Number.isInteger(bits) && bits >= 0 && bits <= 256 && /^[0-9a-f]{64}$/.test(hashHex) &&
  BigInt('0x' + hashHex) < (1n << BigInt(256 - bits));

// Firma ECDSA DER (30 len 02 lr r 02 ls s) -> {r, s} BigInt. noble 2.2.3 no trae fromDER.
function derARS(der) {
  if (der[0] !== 0x30 || der[1] !== der.length - 2 || der[2] !== 0x02) throw new Error('DER inválido');
  const lr = der[3], ls = der[5 + lr];
  if (der[4 + lr] !== 0x02 || 6 + lr + ls !== der.length) throw new Error('DER inválido');
  const num = (b) => BigInt('0x' + Array.from(b, (x) => x.toString(16).padStart(2, '0')).join(''));
  return { r: num(der.slice(4, 4 + lr)), s: num(der.slice(6 + lr)) };
}

const SPKI = '3056301006072a8648ce3d020106052b8104000a034200';
export function verificarEcdsa(mensaje, firmaB64, pubHex) {
  try {
    if (!pubHex.startsWith(SPKI)) return false;
    const der = Uint8Array.from(atob(firmaB64), (c) => c.charCodeAt(0));
    return secp.verify(derARS(der), sha256Bytes(enc.encode(mensaje)),
      fromHex(pubHex.slice(SPKI.length)), { lowS: false });
  } catch (e) { return false; }
}

// Texto firmado por una réplica PBFT: JSON sin "signature" ni "block", separadores compactos.
export function payloadFirmaPbft(msg) {
  const cuerpo = {};
  for (const k of Object.keys(msg)) if (k !== 'signature' && k !== 'block') cuerpo[k] = msg[k];
  return valorCanonico(cuerpo);
}

// Certificado de commit: >= 2f+1 COMMIT firmados por réplicas DISTINTAS del conjunto que informa el
// nodo, de la misma vista, altura y hash. n sale del conjunto recibido (el conjunto se acepta del nodo).
export function verificarCertificado(cert, bloque, replicas) {
  const n = replicas.length, cuorum = 2 * Math.floor((n - 1) / 3) + 1;
  const claves = new Map(replicas.map((r) => [r.id, r.public_key]));
  const vistos = new Set();
  if (!cert || !Array.isArray(cert.commits)) return { ok: false, firmas: 0, cuorum };
  for (const m of cert.commits) {
    if (!m || m.type !== 'COMMIT' || m.view !== cert.view || m.seq !== bloque.header.index ||
        m.digest !== bloque.hash || vistos.has(m.replica) || !claves.has(m.replica) ||
        typeof m.signature !== 'string' ||
        !verificarEcdsa(payloadFirmaPbft(m), m.signature, claves.get(m.replica))) {
      return { ok: false, firmas: vistos.size, cuorum };
    }
    vistos.add(m.replica);
  }
  return { ok: vistos.size >= cuorum && cert.seq === bloque.header.index && cert.digest === bloque.hash,
    firmas: vistos.size, cuorum };
}

// consenso = /consensus; cert = /blocks/{i}/certificate (con commits) o null; prueba = /tx/{id}/proof o null.
export async function verificarLocal({ id, txIdEsperado, bloque, prueba, consenso, cert }) {
  const r = [];
  const add = (ok, texto) => r.push({ ok, texto });
  const tx = (bloque.transactions || []).find((t) => t.tx_id === txIdEsperado);
  if (!tx) { add(false, 'La transacción no está en el bloque descargado'); return r; }
  add(txId(tx) === tx.tx_id, 'El tx_id se recalcula desde el contenido de la transacción');
  const esEmision = tx.type === 'CREDENTIAL_ISSUE';
  const p = tx.payload || {};
  const idCalc = esEmision && p.degree !== undefined && p.issue_date !== undefined
    ? (await sha256Texto(String(tx.sender) + tx.recipient + p.degree + p.issue_date)).slice(0, 32) : null;
  add(esEmision && idCalc === id, 'La transacción es CREDENTIAL_ISSUE y su contenido da el ID de la credencial consultada');
  let firmaOk = false;
  try {
    firmaOk = addressFromPublicKey(tx.public_key) === tx.sender &&
      verificarEcdsa(signingMessage(tx), tx.signature, tx.public_key);
  } catch (e) { /* firmaOk queda false */ }
  add(firmaOk, 'La firma del emisor es válida y su llave pública corresponde a su dirección');
  const hojas = await Promise.all(bloque.transactions.map(hojaDeTx));
  const raiz = await merkleRootFromLeaves(hojas);
  add(raiz === bloque.header.merkle_root, 'La raíz Merkle se recalcula con todas las transacciones del bloque');
  if (prueba) {
    const mia = hojas[bloque.transactions.indexOf(tx)];
    add(prueba.leaf === mia && await verifyProof(mia, prueba.proof, bloque.header.merkle_root),
      'El camino Merkle del nodo, aplicado a la hoja recalculada, llega a la raíz del encabezado');
  }
  const h = await hashBloque(bloque);
  add(h === bloque.hash, 'El hash del bloque se recalcula desde el encabezado y las transacciones');
  if (consenso && consenso.mode === 'pbft') {
    add(null, 'Prueba de trabajo: no aplica (consenso PBFT)');
    const v = verificarCertificado(cert, bloque, consenso.replicas || []);
    add(v.ok, 'Certificado PBFT: ' + v.firmas + ' firmas ECDSA válidas de réplicas distintas (se exigen ' +
      v.cuorum + ' = 2f+1) del conjunto de réplicas que informa el nodo (no verificado de forma independiente)');
  } else {
    add(cumpleBits(bloque.hash, bloque.header.difficulty),
      'El hash cumple la dificultad declarada en el encabezado (' + bloque.header.difficulty + ' bits)');
  }
  return r;
}

export const NO_VERIFICADO = 'No verificado aquí: que este bloque pertenezca a la cadena canónica, la dificultad ' +
  'exigida por la regla de la cadena, que el emisor esté autorizado, ni la revocación (se confía en el nodo).';

export function extraerId(texto) {
  const t = String(texto).trim();
  const m = t.match(/\/verify\/([0-9a-f]{8,64})/i) || t.match(/^(?:upbchain:\/\/verify\/)?([0-9a-f]{8,64})$/i);
  return m ? m[1].toLowerCase() : null;
}

// ── Interfaz (solo en navegador) ──────────────────────────────────────────────

const COLORES = { CONFIRMED: 'ok', PENDING: 'warn', REVOKED: 'mal', EXPIRED: 'mal', NOT_FOUND: 'nd' };
let raizCampos = null;

async function getJson(url) {
  const r = await fetch(url);
  if (!r.ok && r.status !== 404) throw new Error(url + ' → ' + r.status);
  return r.ok ? r.json() : null;
}

function fila(k, v) {
  const dt = document.createElement('dt'); dt.textContent = k;
  const dd = document.createElement('dd'); dd.textContent = v;
  return [dt, dd];
}

async function verificar(id) {
  const $ = (s) => document.getElementById(s);
  $('resultado').hidden = false;
  const veredicto = $('veredicto'), detalle = $('detalle'), prueba = $('prueba');
  detalle.replaceChildren(); prueba.textContent = ''; prueba.className = 'prueba';
  $('pbft').textContent = ''; $('motivo').textContent = ''; raizCampos = null;
  veredicto.textContent = 'Verificando…'; veredicto.className = 'veredicto';
  history.replaceState(null, '', '/kiosco/' + id);
  const st = await getJson('/credentials/verify/' + encodeURIComponent(id));
  if (!st) { veredicto.textContent = 'NO ENCONTRADA'; veredicto.className = 'veredicto nd'; return; }
  veredicto.textContent = st.verdict || st.status;
  veredicto.className = 'veredicto ' + (COLORES[st.status] || 'nd');
  $('motivo').textContent = st.reason || '';
  const c = st.credential || {};
  raizCampos = c.fields_root || null;
  const filas = [['ID', id], ['Emisor', c.issuer_address], ['Tipo', c.credential_type],
    ['Título', c.degree], ['Programa', c.program], ['Fecha de emisión', c.issue_date],
    ['Vence', c.expiry_date], ['Raíz del compromiso', c.fields_root],
    ['Bloque', st.block_index], ['Confirmaciones', c.issuer_address ? st.confirmations : null]];
  for (const [k, v] of filas) if (v !== null && v !== undefined && v !== '') detalle.append(...fila(k, String(v)));
  if (!st.tx_id || st.block_index === null || st.block_index === undefined) {
    prueba.textContent = 'Sin prueba Merkle: la credencial aún no está en un bloque.'; return;
  }
  try {
    const p = await getJson('/tx/' + st.tx_id + '/proof');
    const bloque = await getJson('/blocks/' + st.block_index);
    const cons = await getJson('/consensus');
    const cert = cons && cons.mode === 'pbft' ? await getJson('/blocks/' + st.block_index + '/certificate') : null;
    const res = await verificarLocal({ id, txIdEsperado: st.tx_id, bloque, prueba: p, consenso: cons, cert });
    const fallo = res.some((x) => x.ok === false);
    prueba.textContent = fallo ? 'LA VERIFICACIÓN LOCAL FALLÓ' : 'Verificado en este dispositivo (ver detalle)';
    prueba.classList.add(fallo ? 'mal' : 'ok');
    const ul = document.createElement('ul');
    for (const x of res) {
      const li = document.createElement('li');
      li.textContent = (x.ok === true ? '✔ ' : x.ok === false ? '✘ ' : '– ') + x.texto;
      li.className = x.ok === true ? 'ok' : x.ok === false ? 'mal' : '';
      ul.append(li);
    }
    const nv = document.createElement('li'); nv.textContent = NO_VERIFICADO; ul.append(nv);
    $('pbft').replaceChildren(ul);
    // Idea 3: anclaje público (OpenTimestamps) en o después del bloque de la credencial.
    const anc = await getJson('/anchors?from_block=' + st.block_index);
    const a = anc && anc.anchors && anc.anchors[0];
    if (a) {
      const texto = a.status === 'upgraded' ? 'Anclada en Bitcoin: confirmada'
        : a.status === 'failed' ? 'falló el anclaje' : 'Anclada en Bitcoin: pendiente';
      $('motivo').textContent += (st.reason ? ' · ' : '') + texto + ' (bloque ' + a.block_index + ')';
    }
  } catch (e) { prueba.textContent = 'No se pudo comprobar la prueba: ' + e.message; prueba.classList.add('mal'); }
}

async function escanear() {
  const video = document.getElementById('video');
  const aviso = document.getElementById('aviso-cam');
  if (!('BarcodeDetector' in window) || !navigator.mediaDevices) {
    aviso.textContent = 'Este dispositivo no puede leer QR desde el navegador: escriba el ID.';
    return;
  }
  try {
    const flujo = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
    video.srcObject = flujo; video.hidden = false; await video.play();
    const det = new BarcodeDetector({ formats: ['qr_code'] });
    const ciclo = async () => {
      const codigos = await det.detect(video).catch(() => []);
      const id = codigos.length ? extraerId(codigos[0].rawValue) : null;
      if (id) { flujo.getTracks().forEach((t) => t.stop()); video.hidden = true; verificar(id); return; }
      setTimeout(ciclo, 300);
    };
    ciclo();
  } catch (e) { aviso.textContent = 'Cámara no disponible: ' + e.message; }
}

async function cargarDivulgacion(archivo) {
  const salida = document.getElementById('divulgacion-res');
  salida.replaceChildren();
  try {
    const paquete = JSON.parse(await archivo.text());
    if (!raizCampos) { salida.textContent = 'Verifique primero una credencial.'; return; }
    if (paquete.fields_root !== raizCampos) { salida.textContent = 'El paquete no corresponde a esta credencial.'; return; }
    for (const it of paquete.revealed || []) {
      const ok = await verifyField(raizCampos, it);
      const li = document.createElement('li');
      li.textContent = (ok ? '✔ ' : '✘ ') + it.name + ': ' + JSON.stringify(it.value);
      li.className = ok ? 'ok' : 'mal';
      salida.append(li);
    }
  } catch (e) { salida.textContent = 'Paquete inválido: ' + e.message; }
}

if (typeof document !== 'undefined') {
  document.getElementById('form-id').addEventListener('submit', (ev) => {
    ev.preventDefault();
    const id = extraerId(document.getElementById('id').value);
    if (id) verificar(id); else document.getElementById('aviso-cam').textContent = 'ID no válido.';
  });
  document.getElementById('btn-escanear').addEventListener('click', escanear);
  document.getElementById('archivo').addEventListener('change', (e) => e.target.files[0] && cargarDivulgacion(e.target.files[0]));
  const inicial = document.body.dataset.id;
  if (inicial) { document.getElementById('id').value = inicial; verificar(inicial); }
}
