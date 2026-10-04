// Assessment only: stateless cryptographic rechecks, not execution authorization.
import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './helper-fixture.mjs';
import { verifyRequest } from './helper.mjs';
import { parseRequest } from './helper-protocol.mjs';

const challenge = Buffer.alloc(32, 7).toString('base64url');
const requestId = '07070707070707070707070707070707';
const parsed = request => parseRequest(Buffer.from(JSON.stringify(request)));

test('retained original counter context permits repeat evidence checks without mutation', async () => {
  const original = parsed(fixture(challenge, requestId, { counter: 5, pretty: true }).request);
  const before = parsed(original);
  for (let attempt = 0; attempt < 3; attempt++) {
    const result = await verifyRequest(original);
    assert.equal(result.outcome, 'verified');
    assert.equal(result.new_counter, 5);
    assert.deepEqual(original, before);
  }
  assert.equal(original.credential.counter, 0);
});

test('updated counter context rejects old evidence while original context stays challenge-bound', async () => {
  const original = parsed(fixture(challenge, requestId, { counter: 5 }).request);
  const issued = await verifyRequest(original);
  assert.equal(issued.outcome, 'verified');
  const advanced = structuredClone(original);
  advanced.credential.counter = issued.new_counter;
  assert.equal((await verifyRequest(parsed(advanced))).outcome, 'rejected');
  assert.equal((await verifyRequest(original)).outcome, 'verified');

  const differentOperation = structuredClone(original);
  differentOperation.challenge = Buffer.alloc(32, 8).toString('base64url');
  assert.equal((await verifyRequest(parsed(differentOperation))).outcome, 'rejected');
});

test('zero counters cannot establish replay consumption', async () => {
  const original = parsed(fixture(challenge, requestId, { counter: 0 }).request);
  for (let attempt = 0; attempt < 2; attempt++) {
    const result = await verifyRequest(original);
    assert.equal(result.outcome, 'verified');
    assert.equal(result.new_counter, 0);
  }
  // Current credential status and reservation state are outside this helper's API.
  // Adding an apparent status field must not make it trusted verification input.
  const unrecognized = structuredClone(original);
  unrecognized.credential.enabled = false;
  assert.throws(() => parsed(unrecognized));
});
