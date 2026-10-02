// Synthetic evidence only. Rust creates the expected binding; Node fixtures sign it.
import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './helper-fixture.mjs';
import { makeRunner } from './helper-runner.mjs';

const driver = process.env.VOLLMACHT_TEST_DRIVER;
const launcher = process.env.VOLLMACHT_TEST_LAUNCHER;
const roundTrip = makeRunner(driver, launcher);

for (const [name, options, mutate] of [
  ['valid assertion', {}, () => {}],
  ['original whitespace retained', { pretty: true, counter: 1 }, () => {}],
  ['synced eligible, not backed up', { flags: 13 }, r => { r.credential.backup_eligible = true; }],
  ['synced eligible, backed up', { flags: 29 }, r => { r.credential.backup_eligible = true; }],
]) test(name, async () => assert.equal(await roundTrip(options, mutate), 'verified'));

for (const [name, options] of [
  ['wrong origin', { origin: 'https://example.com' }],
  ['wrong RP', { rpID: 'example.com' }],
  ['missing UP', { flags: 4 }], ['missing UV', { flags: 1 }],
  ['wrong ceremony type', { type: 'webauthn.create' }],
  ['cross origin', { crossOrigin: true }],
  ['top origin', { topOrigin: 'http://localhost:8374' }],
  ['changed backup eligibility', { flags: 13 }], ['invalid backup state', { flags: 21 }],
]) test(name, async () => assert.equal(await roundTrip(options), 'rejected'));

for (const [name, mutate] of [
  ['wrong credential ID', r => { r.assertion.id = 'AA'; }],
  ['wrong raw ID', r => { r.assertion.raw_id = 'AA'; }],
  ['wrong user handle', r => { r.assertion.user_handle = 'AQ'; }],
  ['counter rollback', r => { r.credential.counter = 1; }],
  ['different key', r => { r.credential.public_key = fixture(r.challenge, r.request_id).request.credential.public_key; }],
  ['damaged signature', r => { r.assertion.signature = Buffer.alloc(70).toString('base64url'); }],
  ['reserialized signed client data', r => {
    const data = JSON.parse(Buffer.from(r.assertion.client_data_json, 'base64url'));
    r.assertion.client_data_json = Buffer.from(JSON.stringify(data, null, 2)).toString('base64url');
  }],
  ['signed evidence for another challenge', (r, auth) => {
    const other = auth.assert(Buffer.alloc(32, 3).toString('base64url')).response;
    r.assertion.client_data_json = other.clientDataJSON; r.assertion.signature = other.signature;
  }],
]) test(name, async () => assert.equal(await roundTrip({}, mutate), 'rejected'));

for (const field of ['challenge', 'request_id']) test(`Rust owns ${field}`, async () => {
  assert.equal(await roundTrip({}, r => {
    r[field] = field === 'challenge' ? Buffer.alloc(32).toString('base64url') : '0'.repeat(32);
  }), 'binding_rejected');
});
