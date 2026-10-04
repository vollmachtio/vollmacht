// Characterization only. Verified malformed fixtures are NOT an acceptance policy.
import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './helper-fixture.mjs';
import { parseRequest } from './helper-protocol.mjs';
import { verifyRequest } from './helper.mjs';

const challenge = Buffer.alloc(32, 9).toString('base64url');
const requestId = '09090909090909090909090909090909';
const fields = { type: 'webauthn.get', challenge, origin: 'http://localhost:8374', crossOrigin: false };
const raw = entries => Buffer.from(`{${entries.join(',')}}`);
const entry = (key, value) => `${JSON.stringify(key)}:${JSON.stringify(value)}`;
const entries = Object.entries(fields).map(([key, value]) => entry(key, value));
function request(bytes) {
  return parseRequest(Buffer.from(JSON.stringify(fixture(challenge, requestId, { rawClientData: bytes }).request)));
}
async function outcome(bytes) {
  return (await verifyRequest(request(bytes))).outcome;
}

test('raw-byte fixture extension rejects wrong types and oversized input', () => {
  for (const rawClientData of ['{}', new Uint8Array(1), Buffer.alloc(12_289)]) {
    assert.throws(() => fixture(challenge, requestId, { rawClientData }), /invalid_test_client_data/);
  }
});

test('signed duplicate security fields follow last value, including escaped names', async () => {
  for (const [key, wrong] of Object.entries({
    type: 'webauthn.create', challenge: Buffer.alloc(32, 8).toString('base64url'),
    origin: 'https://wrong.example', crossOrigin: true,
  })) {
    const others = Object.entries(fields).filter(([name]) => name !== key).map(([name, value]) => entry(name, value));
    assert.equal(await outcome(raw([...others, entry(key, wrong), entry(key, fields[key])])), 'verified', `${key}: last allowed value wins`);
    assert.equal(await outcome(raw([...others, entry(key, fields[key]), entry(key, wrong)])), 'rejected', `${key}: last wrong value wins`);
  }
  const withoutChallenge = entries.filter(value => !value.startsWith('"challenge":'));
  const escapedName = '"\\u0063hallenge"';
  assert.equal(await outcome(raw([...withoutChallenge, entry('challenge', 'wrong'), `${escapedName}:${JSON.stringify(challenge)}`])), 'verified');
  assert.equal(await outcome(raw([...withoutChallenge, entry('challenge', challenge), `${escapedName}:"wrong"`])), 'rejected');
});

test('signed extension fields and cross-origin shapes have distinct outcomes', async () => {
  assert.equal(await outcome(raw([...entries, '"futureField":{"value":1}'])), 'verified');
  for (const value of [null, '', 'false', 0, 1, {}, []]) {
    assert.equal(await outcome(raw([...entries.filter(item => !item.startsWith('"crossOrigin":')), entry('crossOrigin', value)])), 'rejected');
  }
  assert.equal(await outcome(raw(entries.filter(item => !item.startsWith('"crossOrigin":')))), 'verified');
  for (const value of ['http://localhost:8374', null, false]) {
    assert.equal(await outcome(raw([...entries, entry('topOrigin', value)])), 'rejected');
  }
});

test('signed malformed text characterizes decoding, not production permission', async () => {
  const invalidUTF8 = Buffer.concat([raw(entries).subarray(0, -1), Buffer.from(',"unknown":"'), Buffer.from([0xff]), Buffer.from('"}')]);
  assert.equal(await outcome(invalidUTF8), 'verified');
  assert.equal(await outcome(raw([...entries, '"unknown":"\\ud800"'])), 'verified');
  assert.equal(await outcome(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), raw(entries)])), 'verified');
  assert.equal(await outcome(Buffer.from('{')), 'rejected');
  assert.equal(await outcome(Buffer.concat([raw(entries), Buffer.from(' trailing')])), 'rejected');
});

test('valid byte variations verify only with their original signatures', async () => {
  const pretty = Buffer.from(JSON.stringify(fields, null, 2));
  const reordered = raw([...entries].reverse());
  const escaped = raw(entries.map(value => value.startsWith('"origin":') ? '"origin":"http:\\/\\/localhost:8374"' : value));
  for (const bytes of [pretty, reordered, escaped]) {
    const original = request(bytes);
    assert.equal((await verifyRequest(original)).outcome, 'verified');
    const altered = structuredClone(original);
    altered.assertion.client_data_json = Buffer.from(JSON.stringify(fields)).toString('base64url');
    assert.notEqual(altered.assertion.client_data_json, original.assertion.client_data_json);
    assert.equal((await verifyRequest(altered)).outcome, 'rejected');
    assert.equal((await verifyRequest(original)).outcome, 'verified');
  }
});
