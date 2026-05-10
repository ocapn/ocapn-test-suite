/**
 * OCapN Syrup encode/decode benchmark — Node.js
 *
 * Implements the current OCapN Syrup wire format (not the old Spritely bencode
 * variant used by go-fed/syrup).  Integer encoding: N+ / N-  (not i...e).
 *
 * Comparable payloads to the Python and Zig benchmarks in this repo.
 */

// ── Encoder ──────────────────────────────────────────────────────────────────

function encodeInt(n) {
  if (n === 0n || n === 0) return Buffer.from('0+');
  const isBigInt = typeof n === 'bigint';
  const isNegative = isBigInt ? n < 0n : n < 0;
  const abs = isNegative ? (isBigInt ? -n : Math.abs(n)) : n;
  const sign = isNegative ? '-' : '+';
  return Buffer.from(String(abs) + sign);
}

function encodeBytes(b) {
  return Buffer.concat([Buffer.from(String(b.length) + ':'), b]);
}

function encodeStr(s) {
  const utf8 = Buffer.from(s, 'utf8');
  return Buffer.concat([Buffer.from(String(utf8.length) + '"'), utf8]);
}

function encodeSymbol(s) {
  const utf8 = Buffer.from(s, 'utf8');
  return Buffer.concat([Buffer.from(String(utf8.length) + "'"), utf8]);
}

function encodeBool(b) { return Buffer.from(b ? 't' : 'f'); }

function encodeFloat64(f) {
  const b = Buffer.allocUnsafe(9); b[0] = 0x44; b.writeDoubleBE(f, 1); return b;
}

function encodeList(items) {
  const parts = [Buffer.from('[')];
  for (const item of items) parts.push(encode(item));
  parts.push(Buffer.from(']'));
  return Buffer.concat(parts);
}

function encodeDict(obj) {
  const parts = [Buffer.from('{')];
  const keys = Object.keys(obj).map((k) => ({ key: k, encoded: encodeStr(k) }));
  keys.sort((a, b) => Buffer.compare(a.encoded, b.encoded));
  for (const { key, encoded } of keys) {
    parts.push(encoded);
    parts.push(encode(obj[key]));
  }
  parts.push(Buffer.from('}'));
  return Buffer.concat(parts);
}

function encodeRecord(label, args) {
  const parts = [Buffer.from('<'), encodeSymbol(label)];
  for (const a of args) parts.push(encode(a));
  parts.push(Buffer.from('>'));
  return Buffer.concat(parts);
}

function encode(v) {
  if (v instanceof SyrupRecord) return encodeRecord(v.label, v.args);
  if (v instanceof SyrupSymbol) return encodeSymbol(v.name);
  if (Buffer.isBuffer(v)) return encodeBytes(v);
  if (typeof v === 'boolean') return encodeBool(v);
  if (typeof v === 'bigint') return encodeInt(v);
  if (typeof v === 'number') {
    if (Number.isInteger(v)) return encodeInt(v);
    return encodeFloat64(v);
  }
  if (typeof v === 'string') return encodeStr(v);
  if (Array.isArray(v)) return encodeList(v);
  if (v !== null && typeof v === 'object') return encodeDict(v);
  throw new Error('unsupported type: ' + typeof v);
}

class SyrupSymbol { constructor(name) { this.name = name; } }
class SyrupRecord { constructor(label, args) { this.label = label; this.args = args; } }

// ── Decoder ──────────────────────────────────────────────────────────────────

function decode(buf, pos = { i: 0 }) {
  const b = buf[pos.i];
  // integer: digits followed by + or -
  if (b >= 0x30 && b <= 0x39) {
    let numStr = '';
    while (buf[pos.i] >= 0x30 && buf[pos.i] <= 0x39) numStr += String.fromCharCode(buf[pos.i++]);
    const tag = String.fromCharCode(buf[pos.i++]);
    if (tag === '+') return BigInt(numStr);
    if (tag === '-') return -BigInt(numStr);
    // Otherwise it's a length-prefixed type
    const len = parseInt(numStr, 10);
    const payload = buf.slice(pos.i, pos.i + len);
    pos.i += len;
    if (tag === ':') return payload;
    if (tag === '"') return payload.toString('utf8');
    if (tag === "'") return new SyrupSymbol(payload.toString('utf8'));
    throw new Error('unknown tag: ' + tag);
  }
  pos.i++;
  if (b === 0x74 /* t */) return true;
  if (b === 0x66 /* f */) return false;
  if (b === 0x44 /* D */) { const f = buf.readDoubleBE(pos.i); pos.i += 8; return f; }
  if (b === 0x46 /* F */) { const f = buf.readFloatBE(pos.i); pos.i += 4; return f; }
  if (b === 0x30 /* 0 */) { pos.i++; return 0n; } // "0+" already handled above
  if (b === 0x5b /* [ */) {
    const items = [];
    while (buf[pos.i] !== 0x5d) items.push(decode(buf, pos));
    pos.i++; return items;
  }
  if (b === 0x7b /* { */) {
    const obj = {};
    while (buf[pos.i] !== 0x7d) {
      const k = decode(buf, pos);
      if (typeof k !== 'string') throw new Error('dict key must be string');
      obj[k] = decode(buf, pos);
    }
    pos.i++; return obj;
  }
  if (b === 0x23 /* # */) {
    const s = new Set();
    while (buf[pos.i] !== 0x24) s.add(decode(buf, pos));
    pos.i++; return s;
  }
  if (b === 0x3c /* < */) {
    const label = decode(buf, pos);
    const args = [];
    while (buf[pos.i] !== 0x3e) args.push(decode(buf, pos));
    pos.i++;
    return new SyrupRecord(label instanceof SyrupSymbol ? label.name : label, args);
  }
  throw new Error('unexpected byte: 0x' + b.toString(16));
}

// ── Benchmark harness ────────────────────────────────────────────────────────

function bench(label, iters, fn) {
  // warmup
  for (let i = 0; i < Math.min(iters / 10, 1000); i++) fn();
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < iters; i++) fn();
  const elapsed = process.hrtime.bigint() - t0;
  const nsPerOp = elapsed / BigInt(iters);
  const opsPerSec = nsPerOp > 0n ? 1_000_000_000n / nsPerOp : 0n;
  console.log(`${label.padEnd(36)} ${String(nsPerOp).padStart(8)} ns/op  (${opsPerSec} ops/sec)`);
}

const N = 100_000;

console.log('=== Node.js OCapN Syrup Benchmark (N=' + N + ') ===\n');

// Encode
bench('Encode int (42)',            N, () => encode(42));
bench('Encode bool (true)',         N, () => encode(true));
bench('Encode float64 (3.14)',      N, () => encode(3.14));
bench('Encode bytes (11 b)',        N, () => encode(Buffer.from('hello world')));
bench('Encode string (11 b)',       N, () => encode('hello world'));
bench('Encode symbol (op:deliver)', N, () => encode(new SyrupSymbol('op:deliver')));
bench('Encode record (3 args)',     N, () => encode(new SyrupRecord('op:deliver', [1, new SyrupSymbol('answer'), 'hello'])));
bench('Encode list (100 ints)',     10_000, () => {
  const items = [];
  for (let i = 0; i < 100; i++) items.push(i);
  encode(items);
});

// Decode — pre-encode payloads
const encInt    = encode(42);
const encBool   = encode(true);
const encFloat  = encode(3.14);
const encBytes  = encode(Buffer.from('hello world'));
const encStr    = encode('hello world');
const encSym    = encode(new SyrupSymbol('op:deliver'));
const encRec    = encode(new SyrupRecord('op:deliver', [1, new SyrupSymbol('answer'), 'hello']));
const encList100 = (() => { const a=[]; for(let i=0;i<100;i++) a.push(i); return encode(a); })();

console.log();
bench('Decode int (42)',            N, () => decode(encInt));
bench('Decode bool (true)',         N, () => decode(encBool));
bench('Decode float64 (3.14)',      N, () => decode(encFloat));
bench('Decode bytes (11 b)',        N, () => decode(encBytes));
bench('Decode string (11 b)',       N, () => decode(encStr));
bench('Decode symbol (op:deliver)', N, () => decode(encSym));
bench('Decode record (3 args)',     N, () => decode(encRec));
bench('Decode list (100 ints)',     10_000, () => decode(encList100));

console.log('\n=== Benchmark complete ===');
