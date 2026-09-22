// TEST ONLY: synthetic UV/UP flags; no person, browser or platform authenticator.
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { ORIGIN, RP_ID } from './probe.mjs';
import { isoCBOR } from '@simplewebauthn/server/helpers';

export function authenticator() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  // Fixed test COSE EC2 map: {1:2, 3:-7, -1:1, -2:x, -3:y}.
  // This encodes only a test public key, not a general-purpose CBOR implementation.
  const publicKeyCOSE = Buffer.concat([
    Buffer.from('a5010203262001215820', 'hex'), Buffer.from(jwk.x, 'base64url'),
    Buffer.from('225820', 'hex'), Buffer.from(jwk.y, 'base64url'),
  ]);
  const id = randomBytes(32).toString('base64url');
  return {
    credential: { id, publicKey: new Uint8Array(publicKeyCOSE), counter: 0 },
    register(challenge, { flags = 69, origin = ORIGIN, rpID = RP_ID, crossOrigin = false } = {}) {
      const data = Buffer.alloc(55);
      createHash('sha256').update(rpID).digest().copy(data);
      data[32] = flags;
      data.writeUInt16BE(32, 53);
      const attestation = isoCBOR.encode(new Map([
        ['fmt', 'none'], ['attStmt', new Map()],
        ['authData', new Uint8Array(Buffer.concat([data, Buffer.from(id, 'base64url'), publicKeyCOSE]))],
      ]));
      return {
        id, rawId: id, type: 'public-key', extensions: {},
        response: {
          clientDataJSON: Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge, origin, crossOrigin })).toString('base64url'),
          attestationObject: Buffer.from(attestation).toString('base64url'), transports: ['internal'],
        },
      };
    },
    assert(challenge, overrides = {}) {
      const {
        origin = ORIGIN, rpID = RP_ID, flags = 5, type = 'webauthn.get',
        crossOrigin = false, pretty = false, counter = 0,
      } = overrides;
      const clientData = Buffer.from(JSON.stringify(
        { type, challenge, origin, crossOrigin }, null, pretty ? 2 : undefined,
      ));
      const authData = Buffer.alloc(37);
      createHash('sha256').update(rpID).digest().copy(authData);
      authData[32] = flags;
      authData.writeUInt32BE(counter, 33);
      const signed = Buffer.concat([authData, createHash('sha256').update(clientData).digest()]);
      return {
        id, rawId: id, type: 'public-key', clientExtensionResults: {},
        response: {
          clientDataJSON: clientData.toString('base64url'),
          authenticatorData: authData.toString('base64url'),
          signature: sign('sha256', signed, privateKey).toString('base64url'),
        },
      };
    },
  };
}
