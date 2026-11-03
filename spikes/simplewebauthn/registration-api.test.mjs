// Public-API assessment only, not production registration or enrollment policy.
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { generateRegistrationOptions } from '@simplewebauthn/server';
import { decodeCredentialPublicKey, isoCBOR } from '@simplewebauthn/server/helpers';
import { authenticator } from './fixture.mjs';

const challenge = Uint8Array.from({ length: 32 }, (_, i) => i);
const userID = Uint8Array.from({ length: 32 }, (_, i) => 255 - i);
const b64 = value => Buffer.from(value).toString('base64url');

function options(overrides = {}) {
  return {
    rpName: 'Vollmacht', rpID: 'localhost', userName: 'local-principal',
    userDisplayName: 'Vollmacht local principal', challenge: challenge.slice(), userID: userID.slice(),
    timeout: 120_000, attestationType: 'none', excludeCredentials: [],
    authenticatorSelection: {
      authenticatorAttachment: 'platform', residentKey: 'preferred', userVerification: 'required',
    },
    supportedAlgorithmIDs: [-7], ...overrides,
  };
}

test('explicit creation options preserve bytes and pin the complete observed option shape', async () => {
  const input = options();
  const result = await generateRegistrationOptions(input);
  assert.deepEqual(result, {
    challenge: b64(challenge), rp: { name: 'Vollmacht', id: 'localhost' },
    user: { id: b64(userID), name: 'local-principal', displayName: 'Vollmacht local principal' },
    pubKeyCredParams: [{ alg: -7, type: 'public-key' }], timeout: 120_000,
    attestation: 'none', excludeCredentials: [],
    authenticatorSelection: {
      authenticatorAttachment: 'platform', residentKey: 'preferred', userVerification: 'required',
      requireResidentKey: false,
    },
    extensions: { credProps: true }, hints: [],
  });
  assert.deepEqual(input.challenge, challenge);
  assert.deepEqual(input.userID, userID);
  // The library mutates this options object; create it afresh per ceremony.
  assert.equal(input.authenticatorSelection.requireResidentKey, false);
});

test('a string challenge is UTF-8 encoded rather than decoded from base64url', async () => {
  const encoded = b64(challenge);
  const result = await generateRegistrationOptions(options({ challenge: encoded }));
  assert.equal(result.challenge, b64(Buffer.from(encoded, 'utf8')));
  assert.notEqual(result.challenge, encoded);
  await assert.rejects(generateRegistrationOptions(options({ userID: b64(userID) })));
});

test('explicit timeout and exclusions are propagated, not an authoritative deadline or registry', async () => {
  const id = b64(Buffer.alloc(32, 42));
  const result = await generateRegistrationOptions(options({
    timeout: 7_321, excludeCredentials: [{ id, transports: ['internal'] }],
  }));
  assert.equal(result.timeout, 7_321);
  assert.deepEqual(result.excludeCredentials, [{ id, transports: ['internal'], type: 'public-key' }]);
  assert.equal(result.challenge, b64(challenge));
  assert.equal(result.user.id, b64(userID));
  assert.deepEqual(result.pubKeyCredParams, [{ alg: -7, type: 'public-key' }]);
});

// Test-only composition of public APIs. This is not wired into registration.
async function importCandidate(bytes, observed) {
  const key = decodeCredentialPublicKey(bytes);
  if (!(key instanceof Map) || key.get(1) !== 2 || key.get(3) !== -7 || key.get(-1) !== 1
      || !(key.get(-2) instanceof Uint8Array) || key.get(-2).length !== 32
      || !(key.get(-3) instanceof Uint8Array) || key.get(-3).length !== 32) {
    throw new Error('candidate_key_shape');
  }
  observed.imports += 1;
  return webcrypto.subtle.importKey('jwk', {
    kty: 'EC', crv: 'P-256', x: b64(key.get(-2)), y: b64(key.get(-3)),
  }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
}

const encode = key => Uint8Array.from(isoCBOR.encode(key));

test('a synthetic verified-shape EC2 key imports through maintained public WebCrypto', async () => {
  const bytes = authenticator().credential.publicKey;
  const observed = { imports: 0 };
  const key = await importCandidate(bytes, observed);
  assert.equal(observed.imports, 1);
  assert.equal(key.type, 'public');
  assert.equal(key.extractable, false);
  assert.deepEqual(key.usages, ['verify']);
  assert.deepEqual(key.algorithm, { name: 'ECDSA', namedCurve: 'P-256' });
});

test('malformed COSE, wrong labels and malformed coordinates reject before import', async () => {
  const original = decodeCredentialPublicKey(authenticator().credential.publicKey);
  const invalid = [new Uint8Array(), Uint8Array.of(0xff), encode([])];
  for (const [label, value] of [
    [1, 1], [3, -35], [-1, 2], [-2, new Uint8Array(31)], [-3, new Uint8Array(33)],
    [-2, 'not-bytes'],
  ]) {
    const key = new Map(original);
    key.set(label, value);
    invalid.push(encode(key));
  }
  const missing = new Map(original);
  missing.delete(-3);
  invalid.push(encode(missing));
  for (const bytes of invalid) {
    const observed = { imports: 0 };
    await assert.rejects(importCandidate(bytes, observed));
    assert.equal(observed.imports, 0);
  }
});

test('correct labels and coordinate lengths do not make invalid points acceptable', async () => {
  const original = decodeCredentialPublicKey(authenticator().credential.publicKey);
  const zero = new Map(original);
  zero.set(-2, new Uint8Array(32));
  zero.set(-3, new Uint8Array(32));
  const outsideField = new Map(original);
  outsideField.set(-2, new Uint8Array(32).fill(255));
  for (const key of [zero, outsideField]) {
    const observed = { imports: 0 };
    await assert.rejects(importCandidate(encode(key), observed), { name: 'DataError' });
    assert.equal(observed.imports, 1); // Rejected by WebCrypto, not our shape predicate.
  }
});
