// Trusted private verifier, not an authorization server. One request per process.
import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import { decodeClientDataJSON, decodeCredentialPublicKey } from '@simplewebauthn/server/helpers';
import { pathToFileURL } from 'node:url';
import { parseRequest, readFrame, frame } from './helper-protocol.mjs';

export async function verifyRequest(r) {
  const base = { version: 1, kind: 'verification_result', request_id: r.request_id, challenge: r.challenge };
  try {
    const c = r.credential, a = r.assertion;
    if (a.id !== c.id || a.raw_id !== c.id || (a.user_handle && a.user_handle !== c.user_handle)) throw new Error();
    const publicKey = new Uint8Array(Buffer.from(c.public_key, 'base64url'));
    const key = decodeCredentialPublicKey(publicKey);
    // Public library decoder, restricted to enrolled ES256 P-256 keys.
    if (!(key instanceof Map) || key.get(1) !== 2 || key.get(3) !== -7 || key.get(-1) !== 1
        || !(key.get(-2) instanceof Uint8Array) || key.get(-2).length !== 32
        || !(key.get(-3) instanceof Uint8Array) || key.get(-3).length !== 32) throw new Error();
    const client = decodeClientDataJSON(a.client_data_json);
    if ((client.crossOrigin !== undefined && client.crossOrigin !== false) || client.topOrigin !== undefined) throw new Error();
    const result = await verifyAuthenticationResponse({
      response: { id: a.id, rawId: a.raw_id, type: a.type, clientExtensionResults: {},
        response: { clientDataJSON: a.client_data_json, authenticatorData: a.authenticator_data,
          signature: a.signature, userHandle: a.user_handle || null } },
      expectedChallenge: r.challenge, expectedOrigin: r.origin, expectedRPID: r.rp_id,
      credential: { id: c.id, publicKey, counter: c.counter }, requireUserVerification: true,
    });
    const info = result.authenticationInfo;
    const eligible = info.credentialDeviceType === 'multiDevice';
    if (!result.verified || !info.userVerified || eligible !== c.backup_eligible) throw new Error();
    return { ...base, outcome: 'verified', new_counter: info.newCounter,
      backup_eligible: eligible, backed_up: info.credentialBackedUp };
  } catch {
    return { ...base, outcome: 'rejected', code: 'verification_rejected' };
  }
}

async function main() {
  // No extra arguments or alternate modes on the runtime entry point.
  if (process.argv.length !== 2) { process.exitCode = 1; return; }
  try {
    const request = parseRequest(await readFrame(process.stdin));
    const response = await verifyRequest(request);
    const output = frame(Buffer.from(JSON.stringify(response)));
    await new Promise((resolve, reject) => process.stdout.write(output, error => error ? reject(error) : resolve()));
  } catch {
    process.exitCode = 1; // No unvalidated correlation IDs or library diagnostics.
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
