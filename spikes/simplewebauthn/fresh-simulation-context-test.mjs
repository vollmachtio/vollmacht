// TEST ONLY: exercise synthetic bridge framing, not human authorization.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const bridge = fileURLToPath(new URL('./fresh-simulation-context.mjs', import.meta.url));
const challenge = Buffer.alloc(32, 7).toString('base64url');
const valid = `${JSON.stringify({ challenge })}\n`;

function run(input, leaveOpen = false) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [bridge], { env: {}, stdio: ['pipe', 'pipe', 'pipe'] });
    const stdout = [], stderr = [];
    let outputBytes = 0, failure;
    const stop = message => {
      failure ??= new Error(message);
      child.kill('SIGKILL');
    };
    // Await close even after timeout or output overflow, so the child is reaped
    // and its pipes are drained before this promise settles.
    const timer = setTimeout(() => stop('bridge exceeded test deadline'), 8_000);
    child.on('error', error => { failure ??= error; });
    child.stdin.on('error', error => {
      if (error.code !== 'EPIPE') stop('bridge stdin failed');
    });
    for (const [stream, chunks] of [[child.stdout, stdout], [child.stderr, stderr]]) {
      stream.on('data', bytes => {
        outputBytes += bytes.length;
        if (outputBytes > 16_384) stop('bridge exceeded output bound');
        else chunks.push(bytes);
      });
    }
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      child.stdin.destroy();
      if (failure) reject(failure);
      else resolve({ code, signal, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') });
    });
    if (leaveOpen) child.stdin.write(input);
    else child.stdin.end(input);
  });
}

function publicContext(result, expectedLines) {
  assert.equal(result.signal, null);
  assert(result.stdout.endsWith('\n'));
  const lines = result.stdout.trimEnd().split('\n');
  assert.equal(lines.length, expectedLines);
  const first = JSON.parse(lines[0]);
  assert.deepEqual(Object.keys(first), ['credential']);
  assert.deepEqual(Object.keys(first.credential).sort(), ['backup_eligible', 'counter', 'id', 'public_key', 'user_handle']);
  assert.equal(first.credential.counter, 0);
  assert.equal(first.credential.backup_eligible, false);
  assert.equal(first.credential.user_handle, 'AA');
  assert.equal(Buffer.from(first.credential.id, 'base64url').length, 32);
  assert(Buffer.from(first.credential.public_key, 'base64url').length > 0);
  return { credential: first.credential, lines };
}

test('fresh bridge binds a canonical challenge and returns only public context and assertion', async () => {
  const result = await run(valid);
  assert.equal(result.code, 0);
  assert.equal(result.stderr, '');
  const { credential, lines } = publicContext(result, 2);
  const second = JSON.parse(lines[1]);
  assert.deepEqual(Object.keys(second), ['assertion']);
  const assertion = second.assertion;
  assert.deepEqual(Object.keys(assertion).sort(), ['authenticator_data', 'client_data_json', 'id', 'raw_id', 'signature', 'type', 'user_handle']);
  assert.equal(assertion.id, credential.id);
  assert.equal(assertion.raw_id, credential.id);
  assert.equal(assertion.type, 'public-key');
  assert.equal(assertion.user_handle, '');
  const client = JSON.parse(Buffer.from(assertion.client_data_json, 'base64url'));
  assert.equal(client.challenge, challenge);
  assert.equal(client.type, 'webauthn.get');
  assert.equal(client.origin, 'http://localhost:8374');
  assert.equal(client.crossOrigin, false);
  assert.equal(Buffer.from(assertion.authenticator_data, 'base64url').length, 37);
  assert(Buffer.from(assertion.signature, 'base64url').length > 0);
  const another = await run(valid);
  assert.equal(another.code, 0);
  const fresh = publicContext(another, 2).credential;
  assert.notEqual(fresh.id, credential.id);
  assert.notEqual(fresh.public_key, credential.public_key);
});

test('malformed or ambiguous input never yields an assertion', async () => {
  const alias = `${challenge.slice(0, -1)}d`; // Same decoded tail, nonzero unused bits.
  assert.deepEqual(Buffer.from(alias, 'base64url'), Buffer.from(challenge, 'base64url'));
  for (const input of [
    '', '{\n', valid.trimEnd(), valid.replace('\n', '\r\n'), valid + valid,
    valid + ' ', JSON.stringify({ challenge, extra: 1 }) + '\n',
    `{"challenge":"${challenge}","challenge":"${challenge}"}\n`,
    `{"challenge":"${challenge}","\\u0063hallenge":"${challenge}"}\n`,
    JSON.stringify({ challenge: challenge + '=' }) + '\n',
    JSON.stringify({ challenge: alias }) + '\n',
    JSON.stringify({ challenge: 'AA' }) + '\n',
    JSON.stringify({ challenge: null }) + '\n',
    ' '.repeat(257), Buffer.from([0xff, 10]),
  ]) {
    const result = await run(input);
    assert.equal(result.code, 1);
    assert.equal(result.stderr, 'fresh_simulation_rejected\n');
    publicContext(result, 1);
  }
});

test('a complete challenge without EOF times out without signing and is reaped', async () => {
  const result = await run(valid, true);
  assert.equal(result.code, 1);
  assert.equal(result.stderr, 'fresh_simulation_rejected\n');
  publicContext(result, 1);
});
