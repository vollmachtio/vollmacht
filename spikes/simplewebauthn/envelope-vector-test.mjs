// Public synthetic vectors only. This is not an artifact parser or trust registry.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { parseRequest } from './helper-protocol.mjs';
import { verifyRequest } from './helper.mjs';

const read = name => JSON.parse(readFileSync(new URL(`../canonicalization/fixtures/${name}`, import.meta.url), 'utf8'));
const vector = read('candidate-envelope-vector.json');
const expected = read('candidate-expected.json');
const payload = read('candidate-payload.json');
assert.equal(vector.profile, 'candidate-envelope-v1');
const hash = (domain, bytes) => createHash('sha256').update(domain).update(bytes).digest();
const mandateDomain = 'vollmacht:mandate:v1\0';
const trustedKey = createPublicKey({ key: vector.trusted.issuer_jwk, format: 'jwk' });

function issuerValid(compact, key = trustedKey) {
  const parts = compact.split('.');
  assert.equal(parts.length, 3);
  const signature = Buffer.from(parts[2], 'base64url');
  assert.equal(signature.length, 64);
  assert.equal(signature.toString('base64url'), parts[2]);
  return verify('sha256', Buffer.from(`${parts[0]}.${parts[1]}`), { key, dsaEncoding: 'ieee-p1363' }, signature);
}

function request(envelope, challenge = expected.mandate_challenge) {
  const evidence = envelope.evidence;
  return parseRequest(Buffer.from(JSON.stringify({
    version: 1, kind: 'verify_assertion', request_id: '0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c', challenge,
    rp_id: vector.trusted.rp_id, origin: vector.trusted.origin,
    credential: vector.trusted.credential,
    assertion: {
      id: evidence.credential_id, raw_id: evidence.credential_id, type: 'public-key',
      client_data_json: evidence.client_data_json, authenticator_data: evidence.authenticator_data,
      signature: evidence.signature, user_handle: evidence.user_handle,
    },
  })));
}

test('committed issuer artifact covers exact canonical envelope and known payload', () => {
  assert.deepEqual(vector.envelope.payload, payload);
  assert.equal(vector.envelope.version, 1);
  assert.equal(vector.envelope.evidence.kind, 'webauthn.get');
  assert.equal(vector.envelope.evidence.credential_id, payload.credential_id);
  assert.equal(vector.trusted.credential.id, payload.credential_id);
  assert.deepEqual(JSON.parse(expected.canonical_payload), payload);
  assert.deepEqual(JSON.parse(vector.canonical_envelope), vector.envelope);
  assert.deepEqual(JSON.parse(vector.canonical_header), vector.protected_header);
  const parts = vector.issuer_jws.split('.');
  assert.equal(parts[0], Buffer.from(vector.canonical_header).toString('base64url'));
  assert.equal(parts[1], Buffer.from(vector.canonical_envelope).toString('base64url'));
  assert.equal(vector.protected_header.alg, 'ES256');
  assert.equal(vector.protected_header.typ, 'vollmacht-mandate+jws');
  assert.equal(vector.protected_header.kid, payload.issuer_id);
  assert.equal(issuerValid(vector.issuer_jws), true);
  assert.equal(hash('vollmacht:envelope:v1\0', vector.canonical_envelope).toString('hex'), vector.envelope_digest_hex);
  assert.equal(hash(mandateDomain, expected.canonical_payload).toString('base64url'), expected.mandate_challenge);
});

test('retained original assertion verifies through the real helper with separate trusted context', async () => {
  const result = await verifyRequest(request(vector.envelope));
  assert.equal(result.outcome, 'verified');
  assert.equal(result.new_counter, 1);
  assert.equal(result.backup_eligible, false);
});

test('wrong issuer key and altered envelope bytes fail issuer verification', () => {
  const wrong = createPublicKey({ key: vector.trusted.wrong_issuer_jwk, format: 'jwk' });
  assert.equal(issuerValid(vector.issuer_jws, wrong), false);
  const parts = vector.issuer_jws.split('.');
  parts[1] = Buffer.from(vector.rebound_canonical_envelope).toString('base64url');
  assert.equal(issuerValid(parts.join('.')), false);
});

test('issuer-resigned changed operation cannot reuse the original human evidence', async () => {
  // The existing literal oracle fixes member order; change only this one value.
  const changedPayload = JSON.parse(expected.canonical_payload);
  changedPayload.operation.resource.pull_request_number += 1;
  assert.deepEqual(vector.rebound_envelope.payload, changedPayload);
  assert.deepEqual(vector.rebound_envelope.evidence, vector.envelope.evidence);
  assert.deepEqual(JSON.parse(vector.rebound_canonical_envelope), vector.rebound_envelope);
  const parts = vector.rebound_issuer_jws.split('.');
  assert.equal(parts[0], Buffer.from(vector.canonical_header).toString('base64url'));
  assert.equal(parts[1], Buffer.from(vector.rebound_canonical_envelope).toString('base64url'));
  assert.equal(issuerValid(vector.rebound_issuer_jws), true);
  const changedChallenge = hash(mandateDomain, JSON.stringify(changedPayload)).toString('base64url');
  assert.notEqual(changedChallenge, expected.mandate_challenge);
  assert.equal((await verifyRequest(request(vector.rebound_envelope, changedChallenge))).outcome, 'rejected');
});

test('wrong credential and wrong domain cannot validate the original assertion', async () => {
  const wrong = request(vector.envelope);
  wrong.credential.public_key = vector.trusted.wrong_credential_public_key;
  assert.equal((await verifyRequest(wrong)).outcome, 'rejected');
  for (const domain of ['vollmacht:mandate:v1', 'vollmacht:operation:v1\0']) {
    const challenge = hash(domain, expected.canonical_payload).toString('base64url');
    assert.equal((await verifyRequest(request(vector.envelope, challenge))).outcome, 'rejected');
  }
});

test('equivalent client-data reserialization invalidates the retained signature', async () => {
  const changed = request(vector.envelope);
  const original = changed.assertion.client_data_json;
  const compact = JSON.stringify(JSON.parse(Buffer.from(original, 'base64url').toString('utf8')));
  changed.assertion.client_data_json = Buffer.from(compact).toString('base64url');
  assert.notEqual(changed.assertion.client_data_json, original);
  assert.equal((await verifyRequest(changed)).outcome, 'rejected');
  assert.equal((await verifyRequest(request(vector.envelope))).outcome, 'verified');
});
