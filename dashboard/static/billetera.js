// Billetera web del estudiante (P2-1). La llave privada nunca sale del navegador.
import { buildSignedTx, kinds, randomPrivateKey, normalizePrivateKey, publicKeyHex,
  addressFromPublicKey, toHex, fromHex } from './wallet-core.js';

const $ = (id) => document.getElementById(id);
const CLAVE_ALMACEN = 'upb_wallet_v1';
const ITER = 210000;
let llave = null;      // llave privada en memoria (hex), solo mientras la página está abierta
let direccion = null;

function estado(msg, error = false) {
  $('estado').textContent = msg;
  $('estado').style.color = error ? '#a00' : '#0a5';
}

// ── Cifrado local: PBKDF2-SHA256 -> AES-GCM ───────────────────────────────────
async function derivar(clave, sal) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(clave), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: sal, iterations: ITER, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function cifrar(privHex, clave) {
  const sal = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await derivar(clave, sal), fromHex(privHex));
  return JSON.stringify({ v: 1, iter: ITER, sal: toHex(sal), iv: toHex(iv), ct: toHex(new Uint8Array(ct)) });
}
async function descifrar(texto, clave) {
  const o = JSON.parse(texto);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromHex(o.iv) },
    await derivar(clave, fromHex(o.sal)), fromHex(o.ct));
  return toHex(new Uint8Array(pt));
}
function guardar(texto) {
  try { localStorage.setItem(CLAVE_ALMACEN, texto); return true; } catch { return false; }
}
function leer() {
  try { return localStorage.getItem(CLAVE_ALMACEN); } catch { return null; }
}

// ── Sesión ────────────────────────────────────────────────────────────────────
function mostrarCuenta() {
  direccion = addressFromPublicKey(publicKeyHex(llave));
  $('direccion').textContent = direccion;
  $('sec-cuenta').classList.remove('oculto');
  $('sec-tx').classList.remove('oculto');
  actualizarCampos();
  refrescar();
}

async function obtener(ruta) {
  const r = await fetch(ruta);
  if (!r.ok) throw new Error(`${ruta}: HTTP ${r.status}`);
  return r.json();
}

async function refrescar() {
  if (!direccion) return;
  cargarCatalogo();
  try {
    const cuenta = await obtener(`/accounts/${direccion}`);
    $('saldo').textContent = cuenta.balance;
    $('nonce').textContent = cuenta.next_nonce;
  } catch (e) { estado('No se pudo leer la cuenta: ' + e.message, true); }
  try {
    const b = await obtener(`/badges/${direccion}`);
    $('insignias').replaceChildren(...b.badges.map((x) => li(`${x.name || x.badge_id}`)));
  } catch { /* opcional */ }
  try {
    const c = await obtener(`/credentials/student/${direccion}`);
    $('credenciales').replaceChildren(...c.credentials.map((x) =>
      li(`${x.degree || x.credential_id} (${x.status || ''})`)));
  } catch { /* opcional */ }
}
// Catálogo (P2-12): "Canjear" rellena el formulario con el ítem; la firma sigue siendo local.
async function cargarCatalogo() {
  try {
    const c = await obtener('/catalog');
    $('catalogo').replaceChildren(...c.items.map((x) => {
      const e = li(`${x.title} · ${x.price} puntos · quedan ${x.stock} `);
      const b = document.createElement('button');
      b.textContent = 'Canjear'; b.disabled = x.stock <= 0;
      b.onclick = () => {
        $('tipo').value = 'redeem'; actualizarCampos();
        $('destino').value = x.redeem_address; $('monto').value = x.price; $('item-id').value = x.item_id;
        $('item').value = x.title;
      };
      e.append(b);
      return e;
    }));
  } catch { /* opcional */ }
  try {
    const r = await obtener('/tokens/award-rules');
    $('reglas').replaceChildren(...r.rules.map((x) =>
      li(`Credencial ${x.credential_type}: ${x.amount} puntos (${x.rule_id})`)));
  } catch { /* opcional */ }
  try {
    const v = await obtener('/elections');
    $('elecciones').replaceChildren(...v.elections.map((x) => {
      const totales = Object.entries(x.tally).map(([o, n]) => `${o}: ${n}`).join(', ');
      const e = li(`${x.election_id} (${x.open ? 'abierta' : 'cerrada'}, bloques ${x.start_height}-${x.end_height}, ` +
        `peso: ${x.weight_rule}) ${totales} `);
      const b = document.createElement('button');
      b.textContent = 'Votar'; b.disabled = !x.open;
      b.onclick = () => { $('tipo').value = 'vote'; actualizarCampos(); $('eleccion').value = x.election_id; };
      e.append(b);
      return e;
    }));
  } catch { /* opcional */ }
}
function li(texto) { const e = document.createElement('li'); e.textContent = texto; return e; }

function actualizarCampos() {
  const t = $('tipo').value;
  const visible = { 'l-dest': t === 'transfer' || t === 'redeem' || t === 'data',
    'l-monto': t === 'transfer' || t === 'redeem', 'l-item': t === 'redeem', 'l-itemid': t === 'redeem',
    'l-eleccion': t === 'vote', 'l-opcion': t === 'vote', 'l-dato': t === 'data' };
  for (const [id, v] of Object.entries(visible)) $(id).classList.toggle('oculto', !v);
}

function claveIngresada() {
  const c = $('clave').value;
  if (c.length < 8) throw new Error('La contraseña debe tener al menos 8 caracteres.');
  return c;
}

async function protegido(fn) {
  try { await fn(); } catch (e) { estado(e.message || String(e), true); }
}

$('btn-crear').onclick = () => protegido(async () => {
  const c = claveIngresada();
  llave = randomPrivateKey();
  const ok = guardar(await cifrar(llave, c));
  mostrarCuenta();
  estado(ok ? 'Billetera creada y guardada cifrada en este navegador. Exporta una copia de tu llave.'
    : 'Billetera creada, pero este navegador no permite guardarla: exporta tu llave ahora.', !ok);
});
$('btn-abrir').onclick = () => protegido(async () => {
  const c = claveIngresada();
  const t = leer();
  if (!t) throw new Error('No hay billetera guardada en este navegador.');
  try { llave = await descifrar(t, c); } catch { throw new Error('Contraseña incorrecta o datos dañados.'); }
  mostrarCuenta();
  estado('Billetera abierta.');
});
$('btn-borrar').onclick = () => {
  if (!confirm('Se borrará la llave guardada en este navegador. Sin copia de respaldo no se puede recuperar.')) return;
  try { localStorage.removeItem(CLAVE_ALMACEN); } catch { /* sin almacenamiento */ }
  llave = null; direccion = null;
  $('sec-cuenta').classList.add('oculto'); $('sec-tx').classList.add('oculto');
  estado('Llave olvidada.');
};
$('btn-importar').onclick = () => protegido(async () => {
  const c = claveIngresada();
  llave = normalizePrivateKey($('llave-import').value);
  $('llave-import').value = '';
  guardar(await cifrar(llave, c));
  mostrarCuenta();
  estado('Llave importada y guardada cifrada.');
});
$('btn-exportar').onclick = () => {
  if (!llave) return estado('Abre o crea una billetera primero.', true);
  $('llave-export').textContent = llave;
  $('llave-export').classList.remove('oculto');
};
$('btn-refrescar').onclick = refrescar;
$('tipo').onchange = actualizarCampos;

$('btn-enviar').onclick = () => protegido(async () => {
  if (!llave) throw new Error('Abre o crea una billetera primero.');
  const cuenta = await obtener(`/accounts/${direccion}`);
  const entero = (id) => {
    const n = Number($(id).value);
    if (!Number.isSafeInteger(n)) throw new Error('El valor debe ser un entero.');
    return n;
  };
  let campos;
  switch ($('tipo').value) {
    case 'transfer': campos = kinds.transfer($('destino').value.trim(), entero('monto')); break;
    case 'redeem': campos = kinds.redeem($('destino').value.trim(), entero('monto'), $('item').value.trim(), $('item-id').value.trim()); break;
    case 'vote': campos = kinds.vote($('eleccion').value.trim(), $('opcion').value.trim()); break;
    default: campos = kinds.data($('destino').value.trim(), { dato: $('dato').value });
  }
  const tx = await buildSignedTx(llave, { ...campos, nonce: cuenta.next_nonce, fee: entero('comision') });
  const r = await fetch('/transactions', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(tx) });
  const cuerpo = await r.json().catch(() => ({}));
  $('resultado').textContent = JSON.stringify(cuerpo, null, 2);
  if (!r.ok) throw new Error(cuerpo.detail || `Error HTTP ${r.status}`);
  estado('Transacción enviada: ' + cuerpo.tx_id);
  refrescar();
});

actualizarCampos();
if (!leer()) estado('No hay billetera guardada: crea una o importa tu llave.');
