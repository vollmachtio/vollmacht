import assert from 'node:assert/strict';
import { test } from 'node:test';
import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import { Ceremony, challengeFor, ORIGIN, RP_ID } from './probe.mjs';
import { authenticator } from './fixture.mjs';

// Fixed bytes only. Schema and JCS implementation remain a separate P06/P07 gate.
const payload = Buffer.from('{"action":"merge","head":"abc","pr":42,"repo":"disposable"}');
const other = Buffer.from('{"action":"merge","head":"abc","pr":43,"repo":"disposable"}');

async function setup(clock) {
  const device = authenticator();
  const ceremony = new Ceremony(payload, device.credential, clock);
  const options = await ceremony.options();
  return { device, ceremony, options, response: device.assert(options.challenge) };
}

test('public API carries exact digest and raw client bytes survive verification', async () => {
  const { device, ceremony, options } = await setup();
  assert.equal(Buffer.from(options.challenge, 'base64url').length, 32);
  assert.equal(options.challenge, challengeFor(payload, ceremony.nonce()).toString('base64url'));
  assert.equal(options.userVerification, 'required');
  const result = await ceremony.finish(device.assert(options.challenge, { pretty: true }), payload);
  assert.equal(result.verified, true);
  assert.equal(result.authenticationInfo.userVerified, true);
});

test('fresh nonce produces distinct challenges for identical operation', async () => {
  const { device, options } = await setup();
  const second = await new Ceremony(payload, device.credential).options();
  assert.notEqual(options.challenge, second.challenge);
});

test('payload and nonce mutations each change the digest', () => {
  const nonce = Buffer.alloc(32, 1);
  const first = challengeFor(payload, nonce);
  // Independently calculated with Python hashlib, not the function under test.
  assert.equal(first.toString('hex'), '889bf0c37cfa045a07e4d277ed6aed47523d916f80281f84ed64f18ce06cc67c');
  assert.notDeepEqual(first, challengeFor(other, nonce));
  nonce[0] ^= 1;
  assert.notDeepEqual(first, challengeFor(payload, nonce));
  assert.throws(() => challengeFor(payload, Buffer.alloc(31)), /invalid_nonce/);
  assert.throws(() => challengeFor(Buffer.alloc(8193), nonce), /invalid_payload/);
});

test('changed execution bytes fail and consume the ceremony', async () => {
  const { ceremony, response } = await setup();
  await assert.rejects(ceremony.finish(response, other), /operation_mismatch/);
  await assert.rejects(ceremony.finish(response, payload), /consumed/);
});

for (const [label, overrides] of [
  ['wrong origin port', { origin: 'http://localhost:9999' }],
  ['wrong RP hash', { rpID: 'wrong.example' }],
  ['missing UV', { flags: 1 }],
  ['missing UP', { flags: 4 }],
  ['wrong ceremony type', { type: 'webauthn.create' }],
  ['cross-origin ceremony', { crossOrigin: true }],
]) {
  test(`validly signed ${label} is rejected`, async () => {
    const { device, ceremony, options } = await setup();
    await assert.rejects(ceremony.finish(device.assert(options.challenge, overrides), payload));
    await assert.rejects(ceremony.finish(device.assert(options.challenge), payload), /consumed/);
  });
}

test('validly signed different challenge is rejected', async () => {
  const { device, ceremony, options } = await setup();
  const bytes = Buffer.from(options.challenge, 'base64url');
  bytes[0] ^= 1;
  await assert.rejects(ceremony.finish(device.assert(bytes.toString('base64url')), payload));
});

test('wrong credential and forged signature fail', async () => {
  const a = await setup();
  await assert.rejects(a.ceremony.finish(authenticator().assert(a.options.challenge), payload));
  const b = await setup();
  const bytes = Buffer.from(b.response.response.signature, 'base64url');
  bytes[bytes.length - 1] ^= 1;
  b.response.response.signature = bytes.toString('base64url');
  await assert.rejects(b.ceremony.finish(b.response, payload));
});

test('same signing key cannot claim a different credential ID', async () => {
  const { ceremony, response } = await setup();
  response.id = response.rawId = Buffer.alloc(32, 9).toString('base64url');
  await assert.rejects(ceremony.finish(response, payload), /credential_mismatch/);
});

test('another key signing the right challenge cannot impersonate the enrolled ID', async () => {
  const { ceremony, options, device } = await setup();
  const response = authenticator().assert(options.challenge);
  response.id = response.rawId = device.credential.id;
  await assert.rejects(ceremony.finish(response, payload), /invalid_assertion/);
});

test('another ceremony cannot reuse an assertion from the same credential', async () => {
  const { device, response } = await setup();
  const second = new Ceremony(payload, device.credential);
  await assert.rejects(second.finish(response, payload));
});

test('malformed and oversized client data consume the ceremony', async () => {
  for (const encoded of [Buffer.from('{').toString('base64url'), 'a'.repeat(16_385)]) {
    const { ceremony, response } = await setup();
    response.response.clientDataJSON = encoded;
    await assert.rejects(ceremony.finish(response, payload));
    await assert.rejects(ceremony.finish(response, payload), /consumed/);
  }
});

test('signature covers original clientDataJSON bytes', async () => {
  const { ceremony, response } = await setup();
  const data = JSON.parse(Buffer.from(response.response.clientDataJSON, 'base64url'));
  response.response.clientDataJSON = Buffer.from(JSON.stringify(data, null, 2)).toString('base64url');
  await assert.rejects(ceremony.finish(response, payload));
});

test('replay races have exactly one successful completion', async () => {
  const { ceremony, response } = await setup();
  const results = await Promise.allSettled([
    ceremony.finish(response, payload), ceremony.finish(response, payload),
  ]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
  await assert.rejects(ceremony.finish(response, payload), /consumed/);
});

test('server deadline rejects exactly at expiry; just before succeeds', async () => {
  for (const elapsed of [119_999, 120_000]) {
    let now = 0;
    const { ceremony, response } = await setup(() => now);
    now = elapsed;
    if (elapsed === 120_000) await assert.rejects(ceremony.finish(response, payload), /expired/);
    else assert.equal((await ceremony.finish(response, payload)).verified, true);
  }
});

test('caller mutations cannot rewrite captured payload or trusted credential', async () => {
  const device = authenticator();
  const input = Buffer.from(payload);
  const ceremony = new Ceremony(input, device.credential);
  const options = await ceremony.options();
  const response = device.assert(options.challenge);
  input.fill(0);
  device.credential.publicKey.fill(0);
  assert.equal((await ceremony.finish(response, payload)).verified, true);
});

test('library verification alone is not a replay store with zero counters', async () => {
  const { device, response, options } = await setup();
  const args = {
    response, credential: device.credential, expectedChallenge: options.challenge,
    expectedOrigin: ORIGIN, expectedRPID: RP_ID, requireUserVerification: true,
  };
  assert.equal((await verifyAuthenticationResponse(args)).verified, true);
  assert.equal((await verifyAuthenticationResponse(args)).verified, true);
});
