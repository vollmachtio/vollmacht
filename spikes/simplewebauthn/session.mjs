// In-memory browser experiment. Never issues authority or calls GitHub.
import { randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { generateRegistrationOptions, verifyRegistrationResponse } from '@simplewebauthn/server';
import { decodeClientDataJSON } from '@simplewebauthn/server/helpers';
import { Ceremony, ORIGIN, RP_ID } from './probe.mjs';

export const OPERATION = '{"action":"simulate_merge","head":"0000000000000000000000000000000000000000","pr":42,"repo":"vollmacht-disposable/example"}';
const TTL = 120_000;
const fail = code => { throw new Error(code); };

export class Session {
  #clock;
  #user = randomBytes(32);
  #credential;
  #deviceType;
  #pending;
  #busy = false;

  constructor(clock = () => performance.now()) { this.#clock = clock; }

  async execute(command) {
    if (!command || typeof command !== 'object' || Array.isArray(command)) fail('bad_command');
    const { operation, id, credential } = command;
    const start = operation === 'register' || operation === 'authenticate';
    const finish = operation === 'finish_registration' || operation === 'finish_authentication';
    if (!start && !finish && operation !== 'cancel') fail('bad_command');
    const fields = start ? ['operation'] : finish ? ['operation', 'id', 'credential'] : ['operation', 'id'];
    if (Object.keys(command).length !== fields.length || fields.some(k => !Object.hasOwn(command, k))) fail('bad_command');
    if (!start && (typeof id !== 'string' || !/^[a-f0-9]{32}$/.test(id))) fail('bad_command');
    if (this.#busy) fail('ceremony_pending');
    if (this.#pending && this.#clock() >= this.#pending.deadline) this.#pending = undefined;
    if (start && this.#pending) fail('ceremony_pending');
    if (!start && this.#pending?.id !== id) fail('missing_or_expired_ceremony');
    this.#busy = true;
    try {
      if (start) {
        if (operation === 'register' && this.#credential) fail('already_registered');
        if (operation === 'authenticate' && !this.#credential) fail('not_registered');
        const pending = { id: randomBytes(16).toString('hex'), operation, deadline: this.#clock() + TTL };
        if (operation === 'register') {
          pending.options = await generateRegistrationOptions({
            rpName: 'Vollmacht binding experiment', rpID: RP_ID,
            userID: this.#user, userName: 'vollmacht-binding-spike',
            attestationType: 'none', supportedAlgorithmIDs: [-7], timeout: TTL,
            authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' },
          });
        } else {
          pending.ceremony = new Ceremony(Buffer.from(OPERATION), this.#credential, this.#clock);
          pending.options = await pending.ceremony.options();
        }
        this.#pending = pending;
        return { id: pending.id, options: { publicKey: structuredClone(pending.options) } };
      }
      const pending = this.#pending;
      this.#pending = undefined; // matching finish/cancel consumes even on failure
      if (operation === 'cancel') return { cancelled: true };
      if (operation !== (pending.operation === 'register' ? 'finish_registration' : 'finish_authentication')) fail('bad_ceremony');
      const response = structuredClone(credential);
      if (!response || typeof response !== 'object') fail('invalid_credential');
      // The reused browser script calls this field extensions (Rust probe format).
      response.clientExtensionResults = response.extensions;
      delete response.extensions;
      const encoded = response.response?.clientDataJSON;
      if (typeof encoded !== 'string' || encoded.length > 16_384) fail('invalid_client_data');
      const client = decodeClientDataJSON(encoded);
      if ((client.crossOrigin !== undefined && client.crossOrigin !== false) || client.topOrigin !== undefined) fail('cross_origin');
      if (operation === 'finish_registration') {
        const result = await verifyRegistrationResponse({
          response, expectedChallenge: pending.options.challenge,
          expectedOrigin: ORIGIN, expectedRPID: RP_ID,
          requireUserPresence: true, requireUserVerification: true, supportedAlgorithmIDs: [-7],
        });
        if (!result.verified || this.#clock() >= pending.deadline) fail('invalid_or_expired');
        this.#credential = result.registrationInfo.credential;
        this.#deviceType = result.registrationInfo.credentialDeviceType;
        return { registered: true };
      }
      const handle = response.response?.userHandle;
      if (handle != null && handle !== this.#user.toString('base64url')) fail('wrong_user');
      const result = await pending.ceremony.finish(response, Buffer.from(OPERATION));
      if (this.#clock() >= pending.deadline || result.authenticationInfo.credentialDeviceType !== this.#deviceType) fail('invalid_or_expired');
      this.#credential.counter = result.authenticationInfo.newCounter;
      return { verified: true, simulated: true };
    } finally { this.#busy = false; }
  }
}
