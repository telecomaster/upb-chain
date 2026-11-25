// Núcleo de la billetera (P2-1): sin DOM, corre en el navegador y en Node (test cruzado).
// Reproduce EXACTAMENTE blockchain/core/transaction.py y wallet.py:
//  - mensaje firmado = json.dumps(campos, sort_keys=True) de Python (separadores ", " y ": ",
//    ensure_ascii); tx_id = sha256 del JSON sin public_key ni signature.
//  - firma = ECDSA secp256k1 sobre SHA-256(mensaje UTF-8), codificada DER, en base64.
//  - llave pública = DER SubjectPublicKeyInfo (punto sin comprimir) en hex.
//  - dirección = "UPB" + hex(ripemd160(sha256(pub)) + checksum4)[:32] en mayúsculas.
import { secp, ripemd160, sha256 } from './vendor/noble-secp256k1.bundle.js';

const SPKI_PREFIX = '3056301006072a8648ce3d020106052b8104000a034200';

export const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
export const fromHex = (h) => {
  if (!/^([0-9a-fA-F]{2})*$/.test(h)) throw new Error('hex inválido');
  return Uint8Array.from(h.match(/../g) || [], (x) => parseInt(x, 16));
};

// json.dumps(obj, sort_keys=True) de Python: ", " y ": ", \uXXXX para no ASCII.
// Solo enteros y floats "normales"; los montos de consenso son enteros.
export function canonical(v) {
  if (v === null) return 'null';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new Error('número no finito');
    return String(v);
  }
  if (typeof v === 'string') {
    let out = '"';
    for (let i = 0; i < v.length; i++) {
      const c = v.charCodeAt(i), ch = v[i];
      if (ch === '"') out += '\\"';
      else if (ch === '\\') out += '\\\\';
      else if (ch === '\n') out += '\\n';
      else if (ch === '\r') out += '\\r';
      else if (ch === '\t') out += '\\t';
      else if (ch === '\b') out += '\\b';
      else if (ch === '\f') out += '\\f';
      else if (c < 0x20 || c > 0x7e) out += '\\u' + c.toString(16).padStart(4, '0');
      else out += ch;
    }
    return out + '"';
  }
  if (Array.isArray(v)) return '[' + v.map(canonical).join(', ') + ']';
  const keys = Object.keys(v).sort();
  return '{' + keys.map((k) => canonical(k) + ': ' + canonical(v[k])).join(', ') + '}';
}

const utf8 = (s) => new TextEncoder().encode(s);

export function publicKeyHex(privHex) {
  return SPKI_PREFIX + toHex(secp.getPublicKey(fromHex(privHex), false));
}

export function addressFromPublicKey(pubHex) {
  const raw = ripemd160(sha256(fromHex(pubHex)));
  const checksum = sha256(sha256(raw)).slice(0, 4);
  return 'UPB' + (toHex(raw) + toHex(checksum)).toUpperCase().slice(0, 32);
}

export function txId(tx) {
  return toHex(sha256(utf8(canonical({ type: tx.type, sender: tx.sender, recipient: tx.recipient,
    payload: tx.payload, timestamp: tx.timestamp, fee: tx.fee, nonce: tx.nonce }))));
}

export function signingMessage(tx) {
  return canonical({ tx_id: tx.tx_id, type: tx.type, sender: tx.sender, recipient: tx.recipient,
    payload: tx.payload, timestamp: tx.timestamp, fee: tx.fee, nonce: tx.nonce, public_key: tx.public_key });
}

function derInt(b) {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  b = b.slice(i);
  if (b[0] & 0x80) b = Uint8Array.from([0, ...b]);
  return [0x02, b.length, ...b];
}
export function compactToDer(sig64) {
  const r = derInt(sig64.slice(0, 32)), s = derInt(sig64.slice(32));
  return Uint8Array.from([0x30, r.length + s.length, ...r, ...s]);
}
const b64 = (bytes) => btoa(String.fromCharCode(...bytes));

// Construye y firma una TX. fields: {type, recipient, payload, nonce, fee?, timestamp?}.
export async function buildSignedTx(privHex, fields) {
  const pub = publicKeyHex(privHex);
  const tx = {
    type: fields.type, sender: addressFromPublicKey(pub), recipient: fields.recipient,
    payload: fields.payload, timestamp: fields.timestamp ?? Date.now() / 1000,
    fee: fields.fee ?? 0, nonce: fields.nonce, public_key: pub,
  };
  if (!Number.isSafeInteger(tx.fee) || tx.fee < 0) throw new Error('fee debe ser un entero >= 0');
  if (!Number.isSafeInteger(tx.nonce) || tx.nonce < 0) throw new Error('nonce inválido');
  tx.tx_id = txId(tx);
  const hash = sha256(utf8(signingMessage(tx)));
  const sig = await secp.signAsync(hash, fromHex(privHex));
  tx.signature = b64(compactToDer(sig.toCompactRawBytes()));
  return tx;
}

// Campos por tipo de TX (mismos que los constructores de transaction.py).
export const kinds = {
  transfer: (recipient, amount) => ({ type: 'TOKEN_TRANSFER', recipient, payload: { amount } }),
  redeem: (recipient, amount, item) =>
    ({ type: 'TOKEN_REDEEM', recipient, payload: item ? { amount, item } : { amount } }),
  vote: (election_id, choice) =>
    ({ type: 'VOTE', recipient: 'VOTING_CONTRACT', payload: { election_id, choice } }),
  // data_hash = sha256(json.dumps(data, sort_keys=True)), igual que create_data_record_transaction.
  data: (recipient, data) => ({ type: 'DATA_RECORD', recipient,
    payload: { ...data, data_hash: toHex(sha256(utf8(canonical(data)))) } }),
};

export const randomPrivateKey = () => toHex(secp.utils.randomPrivateKey());

// Acepta 64 hex (crudo) o la llave DER de wallet.py (contiene "0201010420" + 32 bytes).
export function normalizePrivateKey(text) {
  const t = text.trim().toLowerCase();
  if (/^[0-9a-f]{64}$/.test(t)) return t;
  const m = /0201010420([0-9a-f]{64})/.exec(t);
  if (m) return m[1];
  throw new Error('Llave privada no reconocida (64 hex o DER hex).');
}
