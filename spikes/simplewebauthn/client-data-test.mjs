// Signed regression fixtures: the helper now rejects the previously permissive cases.
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

test('signed duplicate security fields reject regardless of order or escaped names', async () => {
  for (const [key, wrong] of Object.entries({
    type: 'webauthn.create', challenge: Buffer.alloc(32, 8).toString('base64url'),
    origin: 'https://wrong.example', crossOrigin: true,
  })) {
    const others = Object.entries(fields).filter(([name]) => name !== key).map(([name, value]) => entry(name, value));
    assert.equal(await outcome(raw([...others, entry(key, wrong), entry(key, fields[key])])), 'rejected', `${key}: last allowed value cannot hide ambiguity`);
    assert.equal(await outcome(raw([...others, entry(key, fields[key]), entry(key, wrong)])), 'rejected', `${key}: reverse order also rejects`);
  }
  const withoutChallenge = entries.filter(value => !value.startsWith('"challenge":'));
  const escapedName = '"\\u0063hallenge"';
  assert.equal(await outcome(raw([...withoutChallenge, entry('challenge', 'wrong'), `${escapedName}:${JSON.stringify(challenge)}`])), 'rejected');
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

test('signed malformed text rejects before permissive library decoding', async () => {
  const invalidUTF8 = Buffer.concat([raw(entries).subarray(0, -1), Buffer.from(',"unknown":"'), Buffer.from([0xff]), Buffer.from('"}')]);
  assert.equal(await outcome(invalidUTF8), 'rejected');
  assert.equal(await outcome(raw([...entries, '"unknown":"\\ud800"'])), 'rejected');
  assert.equal(await outcome(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), raw(entries)])), 'rejected');
  assert.equal(await outcome(Buffer.from('{')), 'rejected');
  assert.equal(await outcome(Buffer.concat([raw(entries), Buffer.from(' trailing')])), 'rejected');
});

test('correctly signed unknown extensions cannot bypass syntax checks', async () => {
  for (const extension of [
    '"unknown":{"name":1,"\\u006eame":2}',
    '"unknown":[{"name":1,"name":2}]',
    '"unknown":1e400',
    '"unknown":' + '['.repeat(16) + '0' + ']'.repeat(16),
  ]) assert.equal(await outcome(raw([...entries, extension])), 'rejected');
  assert.equal(await outcome(raw([...entries, '"unknown":' + '['.repeat(15) + '0' + ']'.repeat(15)])), 'verified');
});

test('valid byte variations verify only with their original signatures', async () => {
  const pretty = Buffer.from(JSON.stringify(fields, null, 2));
  const reordered = raw([...entries].reverse());
  const escaped = raw(entries.map(value => value.startsWith('"origin":') ? '"origin":"http:\\/\\/localhost:8374"' : value));
  const unicode = Buffer.from(JSON.stringify({ ...fields, extension: { '日本語': ['😀', null, true, -1, 1.25] } }, null, 2));
  for (const bytes of [pretty, reordered, escaped, unicode]) {
    const original = request(bytes);
    assert.equal((await verifyRequest(original)).outcome, 'verified');
    const altered = structuredClone(original);
    altered.assertion.client_data_json = Buffer.from(JSON.stringify(fields)).toString('base64url');
    assert.notEqual(altered.assertion.client_data_json, original.assertion.client_data_json);
    assert.equal((await verifyRequest(altered)).outcome, 'rejected');
    assert.equal((await verifyRequest(original)).outcome, 'verified');
  }
});
