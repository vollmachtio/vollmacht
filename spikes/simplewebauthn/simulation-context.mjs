// TEST ONLY: fixed public fixture context, not enrollment or a live registry.
// Rust derives challenge and assertion from its independently checked envelope.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { isoCBOR } from '@simplewebauthn/server/helpers';

assert.equal(process.argv.length, 2, 'no adapter arguments');
const fixture = JSON.parse(readFileSync(new URL(
  '../canonicalization/fixtures/candidate-profile-vector.json', import.meta.url,
), 'utf8'));
const key = fixture.trusted.credential_jwk;
assert.deepEqual(Object.keys(key).sort(), ['crv', 'kty', 'x', 'y']);
assert.equal(key.kty, 'EC');
assert.equal(key.crv, 'P-256');
const coordinate = value => {
  assert.equal(typeof value, 'string');
  const bytes = Buffer.from(value, 'base64url');
  assert.equal(bytes.length, 32);
  assert.equal(bytes.toString('base64url'), value);
  return new Uint8Array(bytes);
};
const cose = isoCBOR.encode(new Map([
  [1, 2], [3, -7], [-1, 1], [-2, coordinate(key.x)], [-3, coordinate(key.y)],
]));
assert.equal(fixture.approval.credential_id, 'AQIDBA');
const context = {
  id: fixture.approval.credential_id,
  public_key: Buffer.from(cose).toString('base64url'),
  counter: 0,
  user_handle: 'AA',
  backup_eligible: false,
};
process.stdout.write(JSON.stringify(context));
