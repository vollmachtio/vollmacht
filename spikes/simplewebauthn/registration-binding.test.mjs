// Library characterization only. Synthetic flags are not human verification.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { verifyRegistrationResponse, verifyAuthenticationResponse } from '@simplewebauthn/server';
import { decodeCredentialPublicKey, decodeAttestationObject } from '@simplewebauthn/server/helpers';
import { authenticator } from './fixture.mjs';
import { ORIGIN, RP_ID } from './probe.mjs';

const registrationChallenge = Buffer.alloc(32, 31).toString('base64url');
const activationChallenge = Buffer.alloc(32, 32).toString('base64url');

function registration(device) {
  const response = device.register(registrationChallenge);
  response.clientExtensionResults = response.extensions;
  delete response.extensions;
  return response;
}

function register(response) {
  return verifyRegistrationResponse({ response, expectedChallenge: registrationChallenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID, requireUserPresence: true,
    requireUserVerification: true, supportedAlgorithmIDs: [-7] });
}

function activate(response, credential) {
  return verifyAuthenticationResponse({ response, credential, expectedChallenge: activationChallenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID, requireUserVerification: true });
}

function signatureValid(response, credential) {
  const cose = decodeCredentialPublicKey(credential.publicKey);
  const key = createPublicKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256',
    x: Buffer.from(cose.get(-2)).toString('base64url'), y: Buffer.from(cose.get(-3)).toString('base64url') } });
  const r = response.response;
  const clientHash = createHash('sha256').update(Buffer.from(r.clientDataJSON, 'base64url')).digest();
  return verify('sha256', Buffer.concat([Buffer.from(r.authenticatorData, 'base64url'), clientHash]),
    key, Buffer.from(r.signature, 'base64url'));
}

test('matching registration IDs return the authenticator-data credential and none attestation', async () => {
  const device = authenticator();
  const response = registration(device);
  const attestation = decodeAttestationObject(Buffer.from(response.response.attestationObject, 'base64url'));
  assert.equal(attestation.get('fmt'), 'none');
  assert.equal(attestation.get('attStmt').size, 0);
  const result = await register(response);
  assert.equal(result.verified, true);
  assert.equal(result.registrationInfo.fmt, 'none');
  assert.equal(response.id, response.rawId);
  assert.equal(result.registrationInfo.credential.id, response.id);
  assert.equal(result.registrationInfo.credential.id, device.credential.id);
  assert.deepEqual(Buffer.from(result.registrationInfo.credential.publicKey), Buffer.from(device.credential.publicKey));
});

test('registration rejects disagreement between browser id and rawId', async () => {
  const response = registration(authenticator());
  response.rawId = Buffer.alloc(32, 33).toString('base64url');
  assert.notEqual(response.id, response.rawId);
  await assert.rejects(register(response), /Credential ID/);
});

test('current library accepts matching browser IDs that disagree with extracted authenticator ID', async () => {
  const device = authenticator();
  const response = registration(device);
  const originalAttestation = response.response.attestationObject;
  response.id = response.rawId = Buffer.alloc(32, 34).toString('base64url');
  assert.notEqual(response.id, device.credential.id);
  const result = await register(response);
  assert.equal(result.verified, true); // Characterization, not recommended policy.
  assert.equal(response.response.attestationObject, originalAttestation);
  assert.equal(result.registrationInfo.credential.id, device.credential.id);
  assert.notEqual(response.id, result.registrationInfo.credential.id);
  assert.notEqual(response.rawId, result.registrationInfo.credential.id);
  // P06 proposes rejecting this mismatch. This test does not add that enforcement.
});

test('fresh correct-key activation verifies after none-attestation registration', async () => {
  const device = authenticator();
  const result = await register(registration(device));
  assert.equal(result.verified, true);
  assert.notEqual(activationChallenge, registrationChallenge);
  const response = device.assert(activationChallenge, { counter: 1 });
  assert.equal(signatureValid(response, result.registrationInfo.credential), true);
  const verified = await activate(response, result.registrationInfo.credential);
  assert.equal(verified.verified, true);
  assert.equal(verified.authenticationInfo.userVerified, true);
  assert.equal(verified.authenticationInfo.newCounter, 1);
});

test('valid signature by another key cannot activate the returned candidate credential', async () => {
  const candidate = authenticator();
  const result = await register(registration(candidate));
  assert.equal(result.verified, true);
  const other = authenticator();
  const response = other.assert(activationChallenge, { counter: 1 });
  // Claim the candidate ID while retaining a genuine signature from another key.
  response.id = response.rawId = result.registrationInfo.credential.id;
  assert.equal(signatureValid(response, other.credential), true);
  assert.equal(signatureValid(response, result.registrationInfo.credential), false);
  const verified = await activate(response, result.registrationInfo.credential);
  assert.equal(verified.verified, false);
});
