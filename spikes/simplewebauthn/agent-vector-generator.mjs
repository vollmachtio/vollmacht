// Public test fixture generator only: stdout, no file writes or operational keys.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';

if (process.argv.length !== 2 || process.version !== 'v24.21.0') {
  throw new Error('Use pinned Node 24.21.0 with no arguments');
}
const load = name => JSON.parse(readFileSync(new URL(`../canonicalization/fixtures/${name}`, import.meta.url)));
const envelopeVector = load('candidate-envelope-vector.json');
const expected = load('candidate-expected.json');
const mandate = envelopeVector.envelope.payload;

// Fixture-only ASCII/integer oracle, deliberately not a general JCS implementation.
function canonical(value) {
  if (typeof value === 'string' && /^[\x20-\x7e]*$/.test(value)) return JSON.stringify(value);
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0)) return JSON.stringify(value);
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const keys = Object.keys(value).sort();
    if (!keys.every(key => /^[A-Za-z_][A-Za-z0-9_]*$/.test(key))) throw new Error('Unsupported fixture key');
    return `{${keys.map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  throw new Error('Unsupported fixture value');
}
const hash = bytes => createHash('sha256').update(bytes).digest();
const digest = (domain, bytes) => hash(Buffer.concat([Buffer.from(domain + '\0'), Buffer.from(bytes)]));
assert.equal(canonical(mandate), expected.canonical_payload);
assert.equal(canonical(mandate.operation), expected.canonical_operation);
assert.equal(canonical(envelopeVector.envelope), envelopeVector.canonical_envelope);
const mandateDigest = digest('vollmacht:mandate:v1', canonical(mandate));
const operationDigest = digest('vollmacht:operation:v1', canonical(mandate.operation));
const envelopeDigest = digest('vollmacht:envelope:v1', canonical(envelopeVector.envelope));
assert.equal(mandateDigest.toString('hex'), expected.mandate_digest_hex);
assert.equal(mandateDigest.toString('base64url'), expected.mandate_challenge);
assert.equal(operationDigest.toString('hex'), expected.operation_digest_hex);
assert.equal(envelopeDigest.toString('hex'), envelopeVector.envelope_digest_hex);

// Scalar 1 is PUBLIC TEST MATERIAL, never a secret or an operational identity.
// It preserves the generator-point thumbprint already bound by the payload.
const agentJwk = { kty: 'EC', crv: 'P-256',
  x: 'axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY',
  y: 'T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU' };
const scalar = Buffer.alloc(32);
scalar[31] = 1;
const privateKey = createPrivateKey({ format: 'jwk', key: { ...agentJwk, d: scalar.toString('base64url') } });
assert.deepEqual(createPublicKey(privateKey).export({ format: 'jwk' }), agentJwk);
const thumbprint = hash(Buffer.from(canonical(agentJwk))).toString('base64url');
assert.equal(thumbprint, mandate.agent_jkt);
const wrongAgent = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' });
const pending = {
  mandate_digest: mandateDigest.toString('base64url'),
  operation_digest: operationDigest.toString('base64url'),
  envelope_digest: envelopeDigest.toString('base64url'),
  audience: mandate.audience,
  challenge: Buffer.alloc(32, 12).toString('base64url'),
  issued_at: mandate.issued_at + 60,
  expires_at: mandate.issued_at + 90,
};
assert.equal(pending.expires_at - pending.issued_at, 30);
assert(pending.expires_at <= mandate.expires_at);
const header = { alg: 'ES256', typ: 'vollmacht-execution+jws', kid: thumbprint };
const canonicalHeader = canonical(header);
function artifact(payload) {
  const bytes = canonical(payload);
  const input = `${Buffer.from(canonicalHeader).toString('base64url')}.${Buffer.from(bytes).toString('base64url')}`;
  const signature = sign('sha256', Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  assert.equal(signature.length, 64);
  assert(verify('sha256', Buffer.from(input), { key: createPublicKey(privateKey), dsaEncoding: 'ieee-p1363' }, signature));
  return { payload, canonical_payload: bytes, proof_jws: `${input}.${signature.toString('base64url')}` };
}
const payload = { version: 1, ...pending };
const variants = [
  ['wrong-audience', 'audience', '44444444444444444444444444444444'],
  ['wrong-challenge', 'challenge', Buffer.alloc(32, 13).toString('base64url')],
  ['wrong-envelope-digest', 'envelope_digest', Buffer.alloc(32, 14).toString('base64url')],
].map(([id, field, value]) => ({ id, ...artifact({ ...payload, [field]: value }) }));
const vector = {
  profile: 'candidate-agent-proof-v1',
  trusted: { agent_jwk: agentJwk, wrong_agent_jwk: wrongAgent, pending, mandate_expires_at: mandate.expires_at },
  protected_header: header, canonical_header: canonicalHeader,
  ...artifact(payload), variants,
};
// Only public keys and proof artifacts are emitted; scalar 1 is intentionally public.
process.stdout.write(JSON.stringify(vector, null, 2) + '\n');
