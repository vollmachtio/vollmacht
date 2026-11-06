// TEST ONLY: synthetic UP/UV and ephemeral software credential, not a person,
// passkey, enrollment service or product protocol. No private key is exported.
// Emit public context, accept one bounded challenge line plus EOF, then emit
// the original synthetic assertion. Rust derives the challenge independently.
import { authenticator } from './fixture.mjs';
import { strictJSON } from './helper-protocol.mjs';

const rejected = () => { throw new Error('fresh_simulation_rejected'); };

async function main() {
  if (process.argv.length !== 2) rejected();
  const auth = authenticator();
  const write = value => new Promise((resolve, reject) => {
    process.stdout.write(`${JSON.stringify(value)}\n`, error => error ? reject(error) : resolve());
  });
  // This fixed context deliberately has no production provenance claim.
  await write({ credential: {
    id: auth.credential.id,
    public_key: Buffer.from(auth.credential.publicKey).toString('base64url'),
    counter: 0,
    user_handle: 'AA',
    backup_eligible: false,
  } });
  const chunks = [];
  let size = 0;
  const timer = setTimeout(() => process.stdin.destroy(new Error('fresh_simulation_rejected')), 5_000);
  try {
    for await (const chunk of process.stdin) {
      size += chunk.length;
      if (size > 256) rejected();
      chunks.push(chunk);
    }
  } finally {
    clearTimeout(timer);
  }
  const bytes = Buffer.concat(chunks);
  // Require one LF-terminated line and EOF before signing. CRLF, multiple
  // lines, duplicate fields and trailing requests are outside this test wire.
  if (bytes.length < 2 || bytes.at(-1) !== 10 || bytes.subarray(0, -1).includes(10)
      || bytes.includes(13)) rejected();
  const request = strictJSON(bytes.subarray(0, -1));
  if (!request || typeof request !== 'object' || Object.keys(request).length !== 1
      || typeof request.challenge !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(request.challenge)) rejected();
  const challenge = Buffer.from(request.challenge, 'base64url');
  if (challenge.length !== 32 || challenge.toString('base64url') !== request.challenge) rejected();
  const assertion = auth.assert(request.challenge);
  await write({ assertion: {
    id: assertion.id,
    raw_id: assertion.rawId,
    type: assertion.type,
    client_data_json: assertion.response.clientDataJSON,
    authenticator_data: assertion.response.authenticatorData,
    signature: assertion.response.signature,
    user_handle: '',
  } });
}

try {
  await main();
} catch {
  process.stderr.write('fresh_simulation_rejected\n');
  process.exitCode = 1;
}
