// Synthetic revised-profile fixture only. No operational keys or file writes.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';

if (process.argv.length !== 2 || process.version !== 'v24.21.0') throw new Error('Use pinned Node 24.21.0 with no arguments');
const load = name => JSON.parse(readFileSync(new URL(`../canonicalization/fixtures/${name}`, import.meta.url)));
const PROFILE = 'vollmacht-local-es256-v1';
// Restricted independent oracle, not a production/general JCS implementation.
function canonical(value) {
  if (typeof value === 'string' && /^[\x20-\x7e]*$/.test(value)) return JSON.stringify(value);
  if (Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0)) return JSON.stringify(value);
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const keys = Object.keys(value).sort();
    assert(keys.every(k => /^[A-Za-z_][A-Za-z0-9_]*$/.test(k)));
    return `{${keys.map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  }
  throw new Error('Unsupported fixture value');
}
const hash = bytes => createHash('sha256').update(bytes).digest();
const digest = (domain, value) => hash(Buffer.concat([Buffer.from(domain + '\0'), Buffer.from(canonical(value))])).toString('base64url');
const pair = () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const agent = pair(), issuer = pair(), credential = pair(), wrong = pair();
const jwk = key => key.publicKey.export({ format: 'jwk' });
const agentJwk = jwk(agent), agentJkt = hash(Buffer.from(canonical(agentJwk))).toString('base64url');
function assertion(challenge) {
  const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'http://localhost:8374', crossOrigin: false }));
  const auth = Buffer.alloc(37);
  hash(Buffer.from('localhost')).copy(auth);
  auth[32] = 5; // Synthetic UP/UV flags, not proof of a human or biometric.
  auth.writeUInt32BE(1, 33);
  const signature = sign('sha256', Buffer.concat([auth, hash(client)]), credential.privateKey);
  return { kind: 'webauthn.get', credential_id: 'AQIDBA', client_data_json: client.toString('base64url'), authenticator_data: auth.toString('base64url'), signature: signature.toString('base64url'), user_handle: '' };
}
function artifact(payload, typ, kid, key) {
  const header = { typ, alg: 'ES256', kid };
  const headerBytes = JSON.stringify(header), payloadBytes = canonical(payload);
  const input = `${Buffer.from(headerBytes).toString('base64url')}.${Buffer.from(payloadBytes).toString('base64url')}`;
  const signature = sign('sha256', Buffer.from(input), { key: key.privateKey, dsaEncoding: 'ieee-p1363' });
  assert.equal(signature.length, 64);
  assert(verify('sha256', Buffer.from(input), { key: key.publicKey, dsaEncoding: 'ieee-p1363' }, signature));
  return { payload, header_bytes: headerBytes, canonical_payload: payloadBytes, jws: `${input}.${signature.toString('base64url')}` };
}
const approval = { ...load('candidate-payload.json'), crypto_profile: PROFILE, agent_jkt: agentJkt };
const approvalChallenge = digest('vollmacht:mandate:v1', approval);
const envelope = { version: 1, payload: approval, evidence: assertion(approvalChallenge) };
const execution = { ...load('candidate-agent-vector.json').payload, crypto_profile: PROFILE,
  mandate_digest: approvalChallenge, operation_digest: digest('vollmacht:operation:v1', approval.operation), envelope_digest: digest('vollmacht:envelope:v1', envelope) };
const previous = load('candidate-enrollment-vector.json');
const proposal = { ...previous.proposal, crypto_profile: PROFILE, agent_key: agentJwk, agent_jkt: agentJkt };
const enrollmentChallenge = digest('vollmacht:admin:enroll-agent:v1', proposal);
const possession = { ...previous.payload, crypto_profile: PROFILE, agent_jkt: agentJkt, authorization_digest: enrollmentChallenge };
const variants = ['missing', 'unknown', 'downgrade'].map(id => {
  const changed = structuredClone(execution);
  if (id === 'missing') delete changed.crypto_profile;
  else changed.crypto_profile = id === 'unknown' ? 'unknown-profile' : 'vollmacht-local-es256-v0';
  return { id, ...artifact(changed, 'vollmacht-execution+jws', agentJkt, agent) };
});
process.stdout.write(JSON.stringify({
  fixture: 'candidate-crypto-profile-v1',
  trusted: { installation_profile: PROFILE, pending_profile: PROFILE, agent_jwk: agentJwk, issuer_jwk: jwk(issuer), credential_jwk: jwk(credential), wrong_jwk: jwk(wrong) },
  approval, canonical_approval: canonical(approval), approval_challenge: approvalChallenge,
  issuer: artifact(envelope, 'vollmacht-mandate+jws', approval.issuer_id, issuer),
  execution: artifact(execution, 'vollmacht-execution+jws', agentJkt, agent),
  proposal, canonical_proposal: canonical(proposal), enrollment_challenge: enrollmentChallenge,
  enrollment_assertion: assertion(enrollmentChallenge),
  possession: artifact(possession, 'vollmacht-agent-enrollment+jws', agentJkt, agent), variants,
}, null, 2) + '\n');
