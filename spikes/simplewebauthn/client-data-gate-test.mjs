// Test-harness sequencing only. Neither production helper nor browser is gated.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { promisify } from 'node:util';
import { fixture } from './helper-fixture.mjs';
import { parseRequest } from './helper-protocol.mjs';
import { verifyRequest } from './helper.mjs';

const execute = promisify(execFile);
const driver = process.env.VOLLMACHT_CLIENT_DATA_GATE;
if (!driver || !isAbsolute(driver)) throw new Error('Set VOLLMACHT_CLIENT_DATA_GATE to an absolute test-driver path');
const corpus = JSON.parse(readFileSync(new URL('./client-data-vectors.json', import.meta.url), 'utf8'));
assert.equal(corpus.profile, 'candidate-client-data-syntax-v1');
assert.equal(corpus.vectors.length, 24);

async function gate(bytes) {
  // Trusted single-process test executable, not a hostile-helper supervisor.
  // execFile bounds output/time and invokes directly without a shell.
  const options = { encoding: 'buffer', timeout: 3_000, maxBuffer: 12_288, killSignal: 'SIGKILL', env: {} };
  const pending = execute(driver, [], options);
  const child = pending.child;
  child.stdin.on('error', () => {}); // Rejection can close stdin before a large fixture finishes.
  child.stdin.end(bytes); // EOF is part of the driver contract.
  try {
    const result = await pending;
    assert.equal(result.stderr.length, 0, 'successful gate emits no diagnostics');
    assert.deepEqual(result.stdout, bytes, 'gate must preserve exact signed bytes');
    return { accepted: true, bytes: result.stdout };
  } catch (error) {
    if (error.code !== 1 || error.killed || error.signal) throw new Error('gate driver failed outside its rejection contract');
    assert.equal(error.stdout.length, 0, 'rejected evidence must not reach stdout');
    assert.equal(error.stderr.toString('utf8'), 'client_data_rejected\n');
    return { accepted: false };
  }
}

const ids = new Set();
for (const vector of corpus.vectors) {
  assert.equal(typeof vector.id, 'string');
  assert(vector.id && !ids.has(vector.id));
  ids.add(vector.id);
  assert(['accept', 'reject'].includes(vector.expected_gate));
  const bytes = Buffer.from(vector.raw_base64url, 'base64url');
  assert.equal(bytes.toString('base64url'), vector.raw_base64url);
  test(`unsigned Rust gate corpus: ${vector.id}`, async () => {
    assert.equal((await gate(bytes)).accepted, vector.expected_gate === 'accept');
  });
}

test('Rust process accepts the byte bound and rejects an oversized input without evidence output', async () => {
  const exact = Buffer.from(`{"x":"${'a'.repeat(12_288 - 8)}"}`);
  assert.equal(exact.length, 12_288);
  assert.equal((await gate(exact)).accepted, true);
  assert.equal((await gate(Buffer.concat([exact, Buffer.from(' ') ]))).accepted, false);
});

const challenge = Buffer.alloc(32, 11).toString('base64url');
const requestId = '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b';
const fields = { type: 'webauthn.get', challenge, origin: 'http://localhost:8374', crossOrigin: false };
function signed(bytes) {
  return parseRequest(Buffer.from(JSON.stringify(fixture(challenge, requestId, { rawClientData: bytes }).request)));
}

async function gatedVerification(request, verify) {
  const result = await gate(Buffer.from(request.assertion.client_data_json, 'base64url'));
  if (!result.accepted) return 'syntax_rejected';
  const preserved = structuredClone(request);
  preserved.assertion.client_data_json = result.bytes.toString('base64url');
  return (await verify(preserved)).outcome;
}

test('test-harness gate preserves signed Unicode and ordinary unknown JSON types', async () => {
  const bytes = Buffer.from(JSON.stringify({ ...fields, future: { '日本語': ['😀', null, true, -1, 1.25, {}] } }, null, 2));
  const request = signed(bytes);
  let calls = 0;
  assert.equal(await gatedVerification(request, async preserved => {
    calls++;
    assert.equal(preserved.assertion.client_data_json, bytes.toString('base64url'));
    return verifyRequest(preserved);
  }), 'verified');
  assert.equal(calls, 1);

  const changed = structuredClone(request);
  const compact = Buffer.from(JSON.stringify(JSON.parse(bytes.toString('utf8'))));
  assert.notDeepEqual(compact, bytes);
  changed.assertion.client_data_json = compact.toString('base64url');
  assert.equal(await gatedVerification(changed, verifyRequest), 'rejected');
  assert.equal(await gatedVerification(request, verifyRequest), 'verified');
});

test('test-harness gate rejects correctly signed ambiguity before invoking helper', async () => {
  const original = Buffer.from(JSON.stringify(fields));
  const duplicate = Buffer.from(`{"challenge":"wrong",${original.toString('utf8').slice(1)}`);
  const invalidUTF8 = Buffer.concat([original.subarray(0, -1), Buffer.from(',"future":"'), Buffer.from([0xff]), Buffer.from('"}')]);
  for (const bytes of [duplicate, invalidUTF8]) {
    const request = signed(bytes);
    // Existing helper remains permissive; this is not a signature forgery.
    assert.equal((await verifyRequest(request)).outcome, 'verified');
    let called = false;
    assert.equal(await gatedVerification(request, async value => {
      called = true;
      return verifyRequest(value);
    }), 'syntax_rejected');
    assert.equal(called, false);
  }
});

test('structural acceptance still requires independent WebAuthn semantic verification', async () => {
  const wrongOrigin = signed(Buffer.from(JSON.stringify({ ...fields, origin: 'https://wrong.example' })));
  assert.equal(await gatedVerification(wrongOrigin, verifyRequest), 'rejected');
});
