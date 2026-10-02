// Test tooling only: fixture enrollment is trusted, never an agent input API.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fixture } from './helper-fixture.mjs';

const helper = fileURLToPath(new URL('./helper.mjs', import.meta.url));

export function makeRunner(driver, launcher) {
  if (!driver || !launcher || !isAbsolute(driver) || !isAbsolute(launcher)) {
    throw new Error('Set absolute driver and launcher paths');
  }
  const challenges = new Set();
  return async function roundTrip(options = {}, mutate = () => {}) {
    return new Promise((resolve, reject) => {
      const child = spawn(driver, [process.execPath, launcher, helper], { env: {}, timeout: 10_000 });
      let output = '', answered = false, fault;
      const fail = error => { fault ??= error; child.kill('SIGKILL'); };
      child.stderr.resume();
      child.stdin.on('error', () => {});
      child.on('error', fail);
      child.stdout.on('data', bytes => {
        output += bytes.toString('utf8');
        if (output.length > 8192) { fail(new Error('driver output overflow')); return; }
        if (!answered && output.includes('\n')) {
          answered = true;
          try {
            const binding = JSON.parse(output.split('\n')[0]);
            assert.equal(binding.request_id.length, 32);
            assert.match(binding.request_id, /^[a-f0-9]{32}$/);
            assert.equal(Buffer.from(binding.challenge, 'base64url').length, 32);
            assert(!challenges.has(binding.challenge), 'Rust must generate a fresh binding');
            challenges.add(binding.challenge);
            const sample = fixture(binding.challenge, binding.request_id, options);
            mutate(sample.request, sample.auth);
            child.stdin.end(JSON.stringify(sample.request));
          } catch (error) { fail(error); }
        }
      });
      child.on('close', (code, signal) => {
        if (fault) { reject(fault); return; }
        if (signal) { reject(new Error('driver terminated')); return; }
        try {
          const lines = output.trim().split('\n');
          assert(answered, 'driver must provide its expected binding');
          if (code !== 0) {
            assert.equal(code, 1); assert.equal(lines.length, 1);
            resolve('binding_rejected'); return;
          }
          assert.equal(lines.length, 2);
          const result = JSON.parse(lines[1]);
          assert.equal(result.replay_denied, true, 'same coordinator must not be reused');
          resolve(result.outcome);
        } catch (error) { reject(error); }
      });
    });
  };
}
