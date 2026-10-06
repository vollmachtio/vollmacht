// Offline test fixture generator only. Writes public vectors to stdout, never files.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { isoCBOR } from '@simplewebauthn/server/helpers';

if (process.argv.length !== 2 || process.version !== 'v24.21.0') {
  throw new Error('Use pinned Node 24.21.0 with no arguments');
}
const payload = JSON.parse(readFileSync(new URL('../canonicalization/fixtures/candidate-payload.json', import.meta.url)));
const expected = JSON.parse(readFileSync(new URL('../canonicalization/fixtures/candidate-expected.json', import.meta.url)));

// Independent oracle for this ASCII/integer/object fixture only, not general JCS.
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
const keyPair = () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
function cose(publicKey) {
  const { x, y } = publicKey.export({ format: 'jwk' });
  return Buffer.from(isoCBOR.encode(new Map([
    [1, 2], [3, -7], [-1, 1],
    [-2, new Uint8Array(Buffer.from(x, 'base64url'))],
    [-3, new Uint8Array(Buffer.from(y, 'base64url'))],
  ]))).toString('base64url');
}

assert.equal(payload.credential_id, 'AQIDBA');
assert.equal(canonical(payload), expected.canonical_payload);
const challenge = digest('vollmacht:mandate:v1', canonical(payload)).toString('base64url');
assert.equal(challenge, expected.mandate_challenge);

const credential = keyPair(), issuer = keyPair();
const wrongCredential = keyPair(), wrongIssuer = keyPair();
const origin = 'http://localhost:8374', rpID = 'localhost';
const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin, crossOrigin: false }, null, 2));
const authData = Buffer.alloc(37);
hash(Buffer.from(rpID)).copy(authData);
authData[32] = 5; // Synthetic UP and UV, not evidence of a person.
authData.writeUInt32BE(1, 33);
const assertionSignature = sign('sha256', Buffer.concat([authData, hash(clientData)]), credential.privateKey);
const envelope = {
  version: 1, payload,
  evidence: {
    kind: 'webauthn.get', credential_id: payload.credential_id,
    client_data_json: clientData.toString('base64url'),
    authenticator_data: authData.toString('base64url'),
    signature: assertionSignature.toString('base64url'), user_handle: '',
  },
};
const protectedHeader = { alg: 'ES256', typ: 'vollmacht-mandate+jws', kid: payload.issuer_id };
const canonicalHeader = canonical(protectedHeader);
function issuerArtifact(canonicalEnvelope) {
  const input = `${Buffer.from(canonicalHeader).toString('base64url')}.${Buffer.from(canonicalEnvelope).toString('base64url')}`;
  const signature = sign('sha256', Buffer.from(input), { key: issuer.privateKey, dsaEncoding: 'ieee-p1363' });
  assert.equal(signature.length, 64);
  return `${input}.${signature.toString('base64url')}`;
}
const canonicalEnvelope = canonical(envelope);
const rebound = structuredClone(envelope);
rebound.payload.operation.resource.pull_request_number = 43;
const reboundCanonical = canonical(rebound);
const vector = {
  profile: 'candidate-envelope-v1',
  trusted: {
    issuer_jwk: issuer.publicKey.export({ format: 'jwk' }),
    wrong_issuer_jwk: wrongIssuer.publicKey.export({ format: 'jwk' }),
    credential: { id: payload.credential_id, public_key: cose(credential.publicKey), counter: 0, user_handle: 'AA', backup_eligible: false },
    wrong_credential_public_key: cose(wrongCredential.publicKey), rp_id: rpID, origin,
  },
  envelope, canonical_envelope: canonicalEnvelope,
  envelope_digest_hex: digest('vollmacht:envelope:v1', canonicalEnvelope).toString('hex'),
  protected_header: protectedHeader, canonical_header: canonicalHeader,
  issuer_jws: issuerArtifact(canonicalEnvelope),
  rebound_envelope: rebound, rebound_canonical_envelope: reboundCanonical,
  rebound_issuer_jws: issuerArtifact(reboundCanonical),
};
// Private keys are never exported or written; a rerun produces a new public vector.
process.stdout.write(JSON.stringify(vector, null, 2) + '\n');
