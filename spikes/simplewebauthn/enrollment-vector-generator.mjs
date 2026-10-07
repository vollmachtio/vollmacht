// Synthetic candidate enrollment only. No files, admin capabilities or live keys.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';

if (process.argv.length !== 2 || process.version !== 'v24.21.0') {
  throw new Error('Use pinned Node 24.21.0 with no arguments');
}
const previous = JSON.parse(readFileSync(new URL('../canonicalization/fixtures/candidate-agent-vector.json', import.meta.url)));
// Restricted oracle for these ASCII strings, unsigned integers and objects only.
function canonical(value) {
  if (typeof value === 'string' && /^[\x20-\x7e]*$/.test(value)) return JSON.stringify(value);
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0)) return JSON.stringify(value);
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const keys = Object.keys(value).sort();
    assert(keys.every(key => /^[A-Za-z_][A-Za-z0-9_]*$/.test(key)));
    return `{${keys.map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  throw new Error('Unsupported fixture value');
}
const hash = bytes => createHash('sha256').update(bytes).digest();
const key = previous.trusted.agent_jwk;
assert.deepEqual(Object.keys(key).sort(), ['crv', 'kty', 'x', 'y']);
// The P-256 generator's scalar 1 is intentionally PUBLIC TEST MATERIAL.
const scalar = Buffer.alloc(32);
scalar[31] = 1;
const privateKey = createPrivateKey({ format: 'jwk', key: { ...key, d: scalar.toString('base64url') } });
const publicKey = createPublicKey(privateKey);
assert.deepEqual(publicKey.export({ format: 'jwk' }), key);
const thumbprint = hash(Buffer.from(canonical(key))).toString('base64url');
assert.equal(thumbprint, previous.protected_header.kid);
const proposal = {
  version: 1, operation: 'enroll_agent', operation_id: '66666666666666666666666666666666',
  installation_id: '77777777777777777777777777777777', audience: '22222222222222222222222222222222',
  principal_id: '33333333333333333333333333333333', credential_id: 'AQIDBA',
  registry_revision: 7, credential_revision: 3, policy_revision: 1,
  agent_key: key, agent_jkt: thumbprint, ceremony_id: '88888888888888888888888888888888',
  nonce: Buffer.alloc(32, 21).toString('base64url'), issued_at: 1800000000, expires_at: 1800000120,
};
const domain = Buffer.from('vollmacht:admin:enroll-agent:v1\0');
const canonicalProposal = canonical(proposal);
const authorizationDigest = hash(Buffer.concat([domain, Buffer.from(canonicalProposal)]));
const payload = {
  version: 1, operation: 'enroll_agent', operation_id: proposal.operation_id,
  installation_id: proposal.installation_id, audience: proposal.audience,
  principal_id: proposal.principal_id, agent_jkt: thumbprint,
  authorization_digest: authorizationDigest.toString('base64url'),
  ceremony_id: '99999999999999999999999999999999',
  challenge: Buffer.alloc(32, 22).toString('base64url'), issued_at: 1800000060, expires_at: 1800000090,
};
const header = { alg: 'ES256', typ: 'vollmacht-agent-enrollment+jws', kid: thumbprint };
function artifact(body, protectedHeader = header) {
  const canonicalHeader = canonical(protectedHeader), canonicalPayload = canonical(body);
  const input = `${Buffer.from(canonicalHeader).toString('base64url')}.${Buffer.from(canonicalPayload).toString('base64url')}`;
  const signature = sign('sha256', Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  assert.equal(signature.length, 64);
  assert(verify('sha256', Buffer.from(input), { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature));
  return { protected_header: protectedHeader, canonical_header: canonicalHeader,
    payload: body, canonical_payload: canonicalPayload, proof_jws: `${input}.${signature.toString('base64url')}` };
}
const variants = [
  ['wrong-audience', 'audience', '44444444444444444444444444444444'],
  ['wrong-stage', 'ceremony_id', proposal.ceremony_id],
  ['wrong-authorization-digest', 'authorization_digest', Buffer.alloc(32, 23).toString('base64url')],
  ['wrong-candidate', 'agent_jkt', hash(Buffer.from(canonical(previous.trusted.wrong_agent_jwk))).toString('base64url')],
].map(([id, field, value]) => ({ id, ...artifact({ ...payload, [field]: value }) }));
variants.push({ id: 'execution-type', ...artifact(payload, { ...header, typ: 'vollmacht-execution+jws' }) });
process.stdout.write(JSON.stringify({
  profile: 'candidate-agent-enrollment-v1',
  trusted: { candidate_jwk: key, wrong_candidate_jwk: previous.trusted.wrong_agent_jwk, pending: payload },
  proposal, canonical_proposal: canonicalProposal, domain_hex: domain.toString('hex'),
  authorization_digest_hex: authorizationDigest.toString('hex'),
  authorization_digest: authorizationDigest.toString('base64url'),
  ...artifact(payload), variants,
}, null, 2) + '\n');
