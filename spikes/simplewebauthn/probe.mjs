// Isolated feasibility experiment. Not an authorization API or canonicalizer.
import { createHash, randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { decodeClientDataJSON } from '@simplewebauthn/server/helpers';

export const ORIGIN = 'http://localhost:8374';
export const RP_ID = 'localhost';
const DOMAIN = Buffer.from('vollmacht:experimental:webauthn-binding:v1\0');
const TTL_MS = 120_000;

// Fixed domain and fixed-width nonce make this concatenation unambiguous.
// The input is opaque bytes, NOT arbitrary JSON that this module canonicalizes.
export function challengeFor(payload, nonce) {
  if (!(payload instanceof Uint8Array) || payload.length === 0 || payload.length > 8192) {
    throw new Error('invalid_payload');
  }
  if (!(nonce instanceof Uint8Array) || nonce.length !== 32) {
    throw new Error('invalid_nonce');
  }
  return createHash('sha256').update(DOMAIN).update(nonce).update(payload).digest();
}

export class Ceremony {
  #payload;
  #credential;
  #challenge;
  #nonce;
  #deadline;
  #clock;
  #consumed = false;

  constructor(payload, credential, clock = () => performance.now()) {
    this.#nonce = randomBytes(32);
    this.#challenge = challengeFor(payload, this.#nonce);
    this.#payload = Buffer.from(payload);
    // This is a TRUSTED pre-enrolled test credential, never supplied by a client.
    this.#credential = structuredClone(credential);
    this.#clock = clock;
    this.#deadline = clock() + TTL_MS;
  }

  nonce() {
    return Buffer.from(this.#nonce);
  }

  async options() {
    return generateAuthenticationOptions({
      rpID: RP_ID,
      challenge: new Uint8Array(this.#challenge),
      allowCredentials: [{ id: this.#credential.id }],
      userVerification: 'required',
      timeout: TTL_MS,
    });
  }

  async finish(response, operationBytes) {
    if (this.#consumed) throw new Error('consumed');
    // Consume before any await, including failed submissions. In-memory only.
    this.#consumed = true;
    if (this.#clock() >= this.#deadline) throw new Error('expired');
    if (!(operationBytes instanceof Uint8Array) || !this.#payload.equals(operationBytes)) {
      throw new Error('operation_mismatch');
    }
    // Snapshot before library awaits; the caller must already bound its transport.
    response = structuredClone(response);
    if (response?.id !== this.#credential.id || response?.rawId !== this.#credential.id) {
      throw new Error('credential_mismatch');
    }
    const encoded = response.response?.clientDataJSON;
    if (typeof encoded !== 'string' || encoded.length > 16_384) {
      throw new Error('invalid_client_data');
    }
    // v14 permits crossOrigin=true without topOrigin for Safari compatibility.
    // Our local ceremony permits no iframe context, regardless of browser.
    const client = decodeClientDataJSON(encoded);
    if ((client.crossOrigin !== undefined && client.crossOrigin !== false)
        || client.topOrigin !== undefined) {
      throw new Error('cross_origin');
    }
    const result = await verifyAuthenticationResponse({
      response,
      expectedChallenge: this.#challenge.toString('base64url'),
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: this.#credential,
      requireUserVerification: true,
    });
    if (!result.verified) throw new Error('invalid_assertion');
    return result;
  }
}
