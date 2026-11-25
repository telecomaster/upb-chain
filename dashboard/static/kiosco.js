// Kiosco verificador (idea 4). Módulo ES sin dependencias: las funciones puras (Merkle y
// compromiso de campos) se comprueban contra Python en tests/js/kiosco_cross_check.mjs.
// Reproduce blockchain/core/merkle.py: nodo = sha256(hex_izq + hex_der) sobre la CADENA hex,
// y si un nivel es impar se duplica el último nodo.

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
    const ok = !!(p && bloque && p.merkle_root === bloque.header.merkle_root &&
      await verifyProof(p.leaf, p.proof, bloque.header.merkle_root));
    prueba.textContent = ok ? 'Prueba Merkle verificada en este dispositivo' : 'LA PRUEBA MERKLE NO COINCIDE';
    prueba.classList.add(ok ? 'ok' : 'mal');
    const cons = await getJson('/consensus');
    if (cons && cons.mode === 'pbft') {
      const cert = await getJson('/blocks/' + st.block_index + '/certificate');
      $('pbft').textContent = cert
        ? 'Certificado PBFT: ' + cert.signers + ' firmantes (cuórum ' + cons.quorum + ' de ' + cons.n + ' réplicas)'
        : 'Sin certificado PBFT para este bloque';
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
