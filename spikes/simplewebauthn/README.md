# P03c: SimpleWebAuthn challenge-binding feasibility

Experimental, test-only probe. No HTTP server, real enrollment, passkey creation, Touch ID prompt, GitHub access or issuer signing. The Rust browser probe is unchanged. This does not implement Human Mandates or complete P03.

## Question and result

Can a maintained library's public API generate and verify a WebAuthn assertion whose challenge commits to exact operation bytes, without rewriting private state or bypassing challenge checks?

Yes in this software experiment: SimpleWebAuthn 14.0.2 accepts a byte-array challenge and verifies the identical base64url value using `expectedChallenge`. The [upstream guide](https://simplewebauthn.dev/docs/advanced/server/custom-challenges) explicitly discusses application data within challenges. Our experiment uses exact comparison, not a permissive challenge callback. This establishes API feasibility, not a complete review of the library or formal approval of this construction.

The test construction is SHA-256 over a fixed experimental domain, a fresh server-generated 32-byte nonce, and operation bytes. The nonce is fixed-width and the domain is fixed, so these concatenation boundaries are unambiguous. The nonce is returned by copy for independent digest reconstruction; it is not secret. A fixed vector was independently checked with Python hashlib.

Payload bytes are deliberately opaque. The test JSON is a fixture, not a canonicalizer or approved schema. P06 must settle the precise nonce placement, domain, canonicalization and evidence format. A hash without fresh trusted randomness is not acceptable. Approval UI correctness, trusted enrollment and credential revocation are separate requirements.

## Run

Use Node 26.5.1, the runtime pinned for this experiment, then:

```sh
cd spikes/simplewebauthn
npm ci
npm test
npm audit
```

The local `.npmrc` disables dependency lifecycle scripts. `package-lock.json` pins transitive versions and integrity hashes. No global installation or TypeScript compiler is required; the probe uses native ESM JavaScript and Node's test runner. The package is private and has no executable service entry point.

## Evidence and obligations

Twenty-one tests cover exact challenge transmission/reconstruction, fresh nonces, operation and nonce mutation, signed wrong challenge/origin/RP/type, missing UP/UV, cross-origin rejection, credential identity substitution, wrong key with the enrolled ID, signature corruption, original client-data bytes, malformed/oversized client data, ceremony swaps, concurrent replay, deadline boundary, captured-input mutation and verification without a replay store.

Test keys and ES256 assertions are generated using Node crypto, independently of the library's protocol verification. A small fixed COSE encoding exists only for synthetic public-key fixtures. UP and UV are simulated flags. Registration, hardware behavior and browser compatibility with this library have not been tested.

Two integration boundaries matter:

- SimpleWebAuthn 14.0.2 tolerates `crossOrigin=true` when `topOrigin` is absent for browser compatibility. The first probe run caught this. Vollmacht's local-only policy rejects cross-origin or top-origin metadata explicitly using the public decoder; the signature is still checked over the original bytes.
- The caller supplies the trusted credential. The wrapper checks both response IDs against that credential before verification. It also consumes in-memory state before any await, including failures. Repeated direct library verification of a zero-counter assertion succeeds: signature verification is not a replay database.

The wrapper is not ready to expose as a service. It lacks a bounded transport, strict JSON/duplicate-key policy, enrollment and user-handle association, persistent credential/counter/backup-state lifecycle, revocation, durable execution reservation and crash recovery. Its 8 KiB operation and 16 KiB encoded client-data limits are experiment bounds, not a complete message-size policy. It returns no execution authority and performs no action.

## Dependency and packaging assessment

At installation on 2026-09-21, the lock resolved 25 dependency packages; npm reported zero known vulnerabilities. The installed dependency directory measured about 6.9 MiB locally, excluding Node. Audit output is time-sensitive and is not security certification. CI runs a fresh audit and the synthetic tests on Linux and macOS.

`npm test` also checks lockfile source URLs, SHA-512 integrity, absence of declared install scripts/links, and the reviewed license set (MIT, Apache-2.0, BSD-3-Clause, 0BSD), with five negative controls. These are metadata checks, not a package-content audit. Dependabot tracks this isolated npm graph separately from Cargo.

The upstream [runtime documentation](https://simplewebauthn.dev/docs/packages/server) lists Node 22+ and Deno 2.4+. Package metadata declares Node >=20; we use the documented floor rather than interpreting metadata as a production support promise. Only Node 26.5.1 was tested locally. Importing v14 on that runtime prints experimental Web Crypto/ML-DSA capability warnings even though this probe uses ES256. We do not suppress them or claim PQC support.

A production helper would introduce a second runtime, npm supply-chain maintenance, signed/notarized packaging questions and a Rust/helper protocol boundary. Helper responses cannot be trusted merely because they contain `verified: true`; request, operation and evidence must stay bound across that boundary, with clear process trust and failure behavior. None of that integration is authorized by this experiment.

## Recommendation and next gate

Proceed to a separately reviewed browser experiment with SimpleWebAuthn before choosing it for v0. Reuse the existing loopback threat model, not the synthetic credential bootstrap. Require real Chrome/Safari registration and mandate-bound assertions, cancellation/timeout recovery, wrong-operation rejection and replay rejection. Then compare a narrow helper against its packaging costs in P06. Do not downgrade to issuer-only approval or migrate the Rust core on the basis of this result alone.
