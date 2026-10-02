// Test-only adapter: software-generated keys are trusted fixtures, never enrollment.
import { authenticator } from './fixture.mjs';

export function fixture(challenge, request_id, options = {}) {
  const auth = authenticator();
  const assertion = auth.assert(challenge, options);
  const request = {
    version:1, kind:'verify_assertion', request_id, challenge,
    rp_id:'localhost', origin:'http://localhost:8374',
    credential:{ id:auth.credential.id, public_key:Buffer.from(auth.credential.publicKey).toString('base64url'),
      counter:0, user_handle:'AA', backup_eligible:false },
    assertion:{ id:assertion.id, raw_id:assertion.rawId, type:assertion.type,
      client_data_json:assertion.response.clientDataJSON, authenticator_data:assertion.response.authenticatorData,
      signature:assertion.response.signature, user_handle:'' },
  };
  return { request, auth };
}
