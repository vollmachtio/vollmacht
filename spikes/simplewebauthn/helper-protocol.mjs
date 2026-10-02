// Private IPC profile. This validates envelopes, not WebAuthn evidence.
export const MAX_BODY = 65_536;
const fail = () => { throw new Error('invalid_envelope'); };

// JSON.parse alone discards duplicate keys and normalizes numeric lexemes.
// Parse only the specified object/string/unsigned-integer/boolean profile;
// delegate string escape decoding to JSON.parse, never eval.
export function strictJSON(bytes) {
  if (bytes.length < 1 || bytes.length > MAX_BODY) fail();
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  let at = 0;
  const whitespace = () => { while (/[\x20\t\r\n]/.test(text[at] ?? '') && at < text.length) at++; };
  const string = () => {
    const start = at;
    if (text[at++] !== '"') fail();
    while (at < text.length) {
      const char = text[at++];
      if (char === '\\') { at++; continue; }
      if (char === '"') {
        const value = JSON.parse(text.slice(start, at));
        if (!/^[\x00-\x7f]*$/.test(value)) fail();
        return value;
      }
    }
    fail();
  };
  const value = depth => {
    whitespace();
    if (text[at] === '"') return string();
    if (text[at] === '{') {
      if (depth >= 8) fail();
      at++;
      const object = Object.create(null);
      whitespace();
      if (text[at] === '}') { at++; return object; }
      for (;;) {
        whitespace();
        const key = string();
        if (Object.hasOwn(object, key)) fail();
        whitespace();
        if (text[at++] !== ':') fail();
        object[key] = value(depth + 1);
        whitespace();
        const end = text[at++];
        if (end === '}') return object;
        if (end !== ',') fail();
      }
    }
    for (const token of ['true', 'false']) {
      if (text.startsWith(token, at)) { at += token.length; return token === 'true'; }
    }
    const number = /^(0|[1-9][0-9]*)/.exec(text.slice(at));
    if (!number) fail();
    at += number[0].length;
    const n = Number(number[0]);
    if (!Number.isSafeInteger(n)) fail();
    return n;
  };
  const result = value(0);
  whitespace();
  if (at !== text.length) fail();
  return result;
}

function fields(object, keys) {
  if (!object || typeof object !== 'object' || Array.isArray(object)
      || Object.keys(object).length !== keys.length || keys.some(k => !Object.hasOwn(object, k))) fail();
}
function binary(value, min, max) {
  if (typeof value !== 'string' || value.length > Math.ceil(max * 4 / 3) || !/^[A-Za-z0-9_-]*$/.test(value)) fail();
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length < min || bytes.length > max || bytes.toString('base64url') !== value) fail();
}
const uint = n => { if (!Number.isInteger(n) || n < 0 || n > 0xffff_ffff) fail(); };
const boolean = b => { if (typeof b !== 'boolean') fail(); };

export function parseRequest(bytes) {
  const r = strictJSON(bytes);
  fields(r, ['version','kind','request_id','challenge','rp_id','origin','credential','assertion']);
  if (r.version !== 1 || r.kind !== 'verify_assertion' || typeof r.request_id !== 'string'
      || r.request_id.length !== 32 || !/^[a-f0-9]{32}$/.test(r.request_id)
      || r.rp_id !== 'localhost' || r.origin !== 'http://localhost:8374') fail();
  binary(r.challenge, 32, 32);
  const c = r.credential;
  fields(c, ['id','public_key','counter','user_handle','backup_eligible']);
  binary(c.id, 1, 1024); binary(c.public_key, 1, 4096); binary(c.user_handle, 1, 64);
  uint(c.counter); boolean(c.backup_eligible);
  const a = r.assertion;
  fields(a, ['id','raw_id','type','client_data_json','authenticator_data','signature','user_handle']);
  if (a.type !== 'public-key') fail();
  binary(a.id, 1, 1024); binary(a.raw_id, 1, 1024); binary(a.client_data_json, 1, 12288);
  binary(a.authenticator_data, 37, 8192); binary(a.signature, 1, 1024); binary(a.user_handle, 0, 64);
  return r;
}

export function frame(body) {
  if (!Buffer.isBuffer(body) || body.length < 1 || body.length > MAX_BODY) fail();
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(body.length);
  return Buffer.concat([prefix, body]);
}

// Read exactly one frame and require EOF before any verification/response.
export async function readFrame(stream) {
  const prefix = Buffer.alloc(4);
  let used = 0, length, body, filled = 0;
  for await (let chunk of stream) {
    if (used < 4) {
      const n = Math.min(4 - used, chunk.length);
      chunk.copy(prefix, used, 0, n); used += n; chunk = chunk.subarray(n);
      if (used < 4) continue;
      length = prefix.readUInt32BE();
      if (length < 1 || length > MAX_BODY) fail();
      body = Buffer.alloc(length);
    }
    if (filled + chunk.length > length) fail();
    chunk.copy(body, filled); filled += chunk.length;
  }
  if (!body || filled !== length) fail();
  return body;
}
