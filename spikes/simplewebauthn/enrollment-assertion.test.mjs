// Synthetic signed evidence only. No enrollment, real credential or admin capability.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { decodeCredentialPublicKey } from '@simplewebauthn/server/helpers';
import { authenticator } from './fixture.mjs';
import { parseRequest } from './helper-protocol.mjs';
import { verifyRequest } from './helper.mjs';

const vector = JSON.parse(readFileSync(new URL('../canonicalization/fixtures/candidate-enrollment-vector.json', import.meta.url)));
const domain = 'vollmacht:admin:enroll-agent:v1\0';
const hash = bytes => createHash('sha256').update(bytes).digest();
const challengeFor = (bytes, prefix = domain) => hash(Buffer.concat([Buffer.from(prefix), Buffer.from(bytes)])).toString('base64url');
const challenge = challengeFor(vector.canonical_proposal);
const cloneRequest = request => parseRequest(Buffer.from(JSON.stringify(request)));
assert.equal(vector.profile, 'candidate-agent-enrollment-v1');
assert.deepEqual(JSON.parse(vector.canonical_proposal), vector.proposal);
assert.equal(Buffer.from(domain).toString('hex'), vector.domain_hex);
assert.equal(challenge, vector.authorization_digest);
assert.equal(Buffer.from(challenge, 'base64url').toString('hex'), vector.authorization_digest_hex);

function fixture(signedChallenge = challenge, options = {}) {
  const auth = authenticator();
  const assertion = auth.assert(signedChallenge, { pretty: true, counter: 1, ...options });
  // A synthetic registry assigns A's credential ID to this fresh software key.
  // IDs are association metadata, not signed authenticator-data fields. This is
  // explicitly trusted test setup, not registration or an enrollment shortcut.
  const id = vector.proposal.credential_id;
  const request = parseRequest(Buffer.from(JSON.stringify({
    version: 1, kind: 'verify_assertion', request_id: 'abababababababababababababababab',
    challenge, rp_id: 'localhost', origin: 'http://localhost:8374',
    credential: { id, public_key: Buffer.from(auth.credential.publicKey).toString('base64url'),
      counter: 0, user_handle: 'AA', backup_eligible: false },
    assertion: { id, raw_id: id, type: 'public-key',
      client_data_json: assertion.response.clientDataJSON,
      authenticator_data: assertion.response.authenticatorData,
      signature: assertion.response.signature, user_handle: '' },
  })));
  const cose = decodeCredentialPublicKey(auth.credential.publicKey);
  const publicKey = createPublicKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256',
    x: Buffer.from(cose.get(-2)).toString('base64url'), y: Buffer.from(cose.get(-3)).toString('base64url') } });
  return { request, publicKey };
}

function signatureValid({ request, publicKey }) {
  const a = request.assertion;
  return verify('sha256', Buffer.concat([
    Buffer.from(a.authenticator_data, 'base64url'), hash(Buffer.from(a.client_data_json, 'base64url')),
  ]), publicKey, Buffer.from(a.signature, 'base64url'));
}

test('synthetic assertion signs the exact reviewed enrollment proposal digest', async () => {
  const f = fixture();
  const before = cloneRequest(f.request);
  assert.equal(signatureValid(f), true);
  const result = await verifyRequest(f.request);
  assert.equal(result.outcome, 'verified');
  assert.equal(result.challenge, vector.authorization_digest);
  assert.equal(result.new_counter, 1);
  assert.equal(result.backup_eligible, false);
  assert.equal(result.backed_up, false);
  assert.deepEqual(f.request, before);
});

test('correctly signed wrong challenge, domain, type, origin, RP and absent UP or UV fail trusted expectations', async () => {
  const cases = [
    ['challenge', Buffer.alloc(32, 42).toString('base64url'), {}],
    ['mandate-domain', challengeFor(vector.canonical_proposal, 'vollmacht:mandate:v1\0'), {}],
    ['ceremony-type', challenge, { type: 'webauthn.create' }],
    ['origin', challenge, { origin: 'https://attacker.invalid' }],
    ['RP', challenge, { rpID: 'attacker.invalid' }],
    ['UV', challenge, { flags: 1 }],
    ['UP', challenge, { flags: 4 }],
  ];
  for (const [name, signedChallenge, options] of cases) {
    const f = fixture(signedChallenge, options);
    assert.equal(signatureValid(f), true, name);
    const result = await verifyRequest(f.request);
    assert.equal(result.outcome, 'rejected', name);
    assert.equal(result.code, 'verification_rejected', name);
  }
});

test('credential association and a different credential key reject intact original evidence', async () => {
  const f = fixture();
  for (const field of ['id', 'raw_id', 'user_handle']) {
    const request = cloneRequest(f.request);
    request.assertion[field] = 'BQYHCA';
    assert.equal(signatureValid({ ...f, request }), true, field);
    assert.equal((await verifyRequest(request)).outcome, 'rejected', field);
  }
  const request = cloneRequest(f.request);
  request.credential.public_key = Buffer.from(authenticator().credential.publicKey).toString('base64url');
  assert.equal(signatureValid({ ...f, request }), true);
  assert.equal((await verifyRequest(request)).outcome, 'rejected');
});

test('original signed evidence cannot authorize changed proposal identities, candidate or revisions', async () => {
  const f = fixture();
  const wrong = vector.trusted.wrong_candidate_jwk;
  // Exact RFC 7638 member order also preserves this nested object's JCS order.
  const candidate = { crv: wrong.crv, kty: wrong.kty, x: wrong.x, y: wrong.y };
  assert.deepEqual(createPublicKey({ key: candidate, format: 'jwk' }).export({ format: 'jwk' }), candidate);
  assert.notDeepEqual(candidate, vector.proposal.agent_key);
  const candidateJkt = hash(Buffer.from(JSON.stringify(candidate))).toString('base64url');
  assert.notEqual(candidateJkt, vector.proposal.agent_jkt);
  for (const [field, value] of [
    ['registry_revision', vector.proposal.registry_revision + 1],
    ['credential_revision', vector.proposal.credential_revision + 1],
    ['policy_revision', vector.proposal.policy_revision + 1],
    ['principal_id', '44444444444444444444444444444444'],
    ['audience', '44444444444444444444444444444444'],
    ['credential_id', 'BQYHCA'],
    ['nonce', Buffer.alloc(32, 43).toString('base64url')],
    ['agent_jkt', candidateJkt],
    ['agent_key', candidate],
  ]) {
    // Existing reviewed canonical order is retained. Replacement key order is
    // fixed above; all other replacements are scalars. Single-field key changes
    // can leave key/thumbprint inconsistent: this tests binding, not a parser.
    // This is not a general canonicalizer or an untrusted proposal parser.
    const altered = JSON.parse(vector.canonical_proposal);
    altered[field] = value;
    const request = cloneRequest(f.request);
    request.challenge = challengeFor(JSON.stringify(altered));
    assert.notEqual(request.challenge, challenge, field);
    assert.deepEqual(request.assertion, f.request.assertion);
    assert.equal(signatureValid({ ...f, request }), true, field);
    assert.equal((await verifyRequest(request)).outcome, 'rejected', field);
  }
  assert.equal((await verifyRequest(f.request)).outcome, 'verified');
});

test('missing domain separator or a mandate domain cannot reuse enrollment evidence', async () => {
  const f = fixture();
  for (const prefix of ['vollmacht:admin:enroll-agent:v1', 'vollmacht:admin:enroll-agent:v1\0\0', 'vollmacht:mandate:v1\0']) {
    const request = cloneRequest(f.request);
    request.challenge = challengeFor(vector.canonical_proposal, prefix);
    assert.notEqual(request.challenge, challenge);
    assert.equal((await verifyRequest(request)).outcome, 'rejected');
  }
});

test('semantically equivalent client-data reserialization breaks its original signature', async () => {
  const f = fixture();
  const changed = cloneRequest(f.request);
  const client = JSON.parse(Buffer.from(changed.assertion.client_data_json, 'base64url'));
  changed.assertion.client_data_json = Buffer.from(JSON.stringify(client)).toString('base64url');
  assert.notEqual(changed.assertion.client_data_json, f.request.assertion.client_data_json);
  assert.equal(signatureValid({ ...f, request: changed }), false);
  assert.equal((await verifyRequest(changed)).outcome, 'rejected');
  assert.equal((await verifyRequest(f.request)).outcome, 'verified');
});

test('verification against unchanged original counter context does not consume administrative authority', async () => {
  const f = fixture();
  const original = cloneRequest(f.request);
  assert.equal((await verifyRequest(f.request)).outcome, 'verified');
  assert.equal((await verifyRequest(f.request)).outcome, 'verified');
  assert.deepEqual(f.request, original);
  // Expected behavior: this stateless helper is not a replay or enrollment store.
});
