# P03c: SimpleWebAuthn challenge-binding feasibility

Experimental probe. P03c's synthetic test path performs no hardware operations. P03d adds an opt-in local browser server for real passkey enrollment and operation-binding assessment; see [browser instructions](BROWSER.md). Neither path accesses GitHub or signs issuer envelopes. The Rust browser probe is unchanged. This does not implement Human Mandates or complete P03.

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

The local `.npmrc` disables dependency lifecycle scripts. `package-lock.json` pins transitive versions and integrity hashes. No global installation or TypeScript compiler is required; the probe uses native ESM JavaScript and Node's test runner. The package is private. `npm test` uses synthetic credentials and temporary loopback sockets, never a browser or hardware prompt. Only `npm run browser` starts the interactive service.

## Evidence and obligations

Twenty-one tests cover exact challenge transmission/reconstruction, fresh nonces, operation and nonce mutation, signed wrong challenge/origin/RP/type, missing UP/UV, cross-origin rejection, credential identity substitution, wrong key with the enrolled ID, signature corruption, original client-data bytes, malformed/oversized client data, ceremony swaps, concurrent replay, deadline boundary, captured-input mutation and verification without a replay store.

Test keys and ES256 assertions are generated using Node crypto, independently of the library's protocol verification. A small fixed COSE encoding exists only for synthetic public-key fixtures. UP and UV are simulated flags. P03d adds synthetic none-attestation registration and session/HTTP tests. User-reported Chrome/Safari Touch ID and recovery results, Chrome replay rejection, and remaining evidence gaps are recorded in the [browser matrix](BROWSER.md).

Two integration boundaries matter:

- SimpleWebAuthn 14.0.2 tolerates `crossOrigin=true` when `topOrigin` is absent for browser compatibility. The first probe run caught this. Vollmacht's local-only policy rejects cross-origin or top-origin metadata explicitly using the public decoder; the signature is still checked over the original bytes.
- The caller supplies the trusted credential. The wrapper checks both response IDs against that credential before verification. It also consumes in-memory state before any await, including failures. Repeated direct library verification of a zero-counter assertion succeeds: signature verification is not a replay database.

The P03c wrapper alone is not a service. The opt-in P03d session/HTTP layer adds bounded transport, a narrow JSON command encoding, single enrollment and user-handle association. Persistent credential lifecycle, revocation, durable execution reservation and crash recovery remain absent. Its 8 KiB operation and 16 KiB encoded client-data limits are experiment bounds. Neither layer returns execution authority or performs an action.

## Dependency and packaging assessment

At installation on 2026-09-21, the lock resolved 25 dependency packages; npm reported zero known vulnerabilities. The installed dependency directory measured about 6.9 MiB locally, excluding Node. Audit output is time-sensitive and is not security certification. CI runs a fresh audit and the synthetic tests on Linux and macOS.

`npm test` also checks lockfile source URLs, SHA-512 integrity, absence of declared install scripts/links, and the reviewed license set (MIT, Apache-2.0, BSD-3-Clause, 0BSD), with five negative controls. These are metadata checks, not a package-content audit. Dependabot tracks this isolated npm graph separately from Cargo.

The upstream [runtime documentation](https://simplewebauthn.dev/docs/packages/server) lists Node 22+ and Deno 2.4+. Package metadata declares Node >=20; we use the documented floor rather than interpreting metadata as a production support promise. Only Node 26.5.1 was tested locally. Importing v14 on that runtime prints experimental Web Crypto/ML-DSA capability warnings even though this probe uses ES256. We do not suppress them or claim PQC support.

A production helper would introduce a second runtime, npm supply-chain maintenance, signed/notarized packaging questions and a Rust/helper protocol boundary. Helper responses cannot be trusted merely because they contain `verified: true`; request, operation and evidence must stay bound across that boundary, with clear process trust and failure behavior. None of that integration is authorized by this experiment.

## Recommendation and next gate

The completed user-reported P03d functional matrix supports continuing the [helper trust-boundary and packaging assessment](../../docs/helper-assessment.md), not production adoption. Environment versions and cleanup were confirmed on 2026-09-29; observation limits remain documented in the matrix. Compare a narrow helper against its packaging costs in P06. Do not downgrade to issuer-only approval or migrate the Rust core on the basis of this result alone.

## P03e.3 private assertion helper

`helper.mjs` is a separate one-shot, private-pipe entry point. It does not run the browser server or create a challenge. Rust supplies the expected challenge and trusted credential snapshot; the helper verifies original assertion bytes with the existing pinned SimpleWebAuthn dependency. It restricts keys to ES256/P-256, requires UP and UV, checks both credential IDs and any supplied user handle, rejects cross-origin/top-origin data and changed backup eligibility, and reports only fixed result codes. Rust retains final deadline, registry revision, counter and single-use checks. An absent user handle is allowed for a non-discoverable assertion; a supplied handle must match.

`helper-protocol.mjs` implements the experimental assertion envelope, not WebAuthn cryptography. It rejects duplicate keys before normalization, noncanonical binary encodings, unknown fields, invalid integer lexemes, excess depth and size, and anything except one complete frame followed by EOF. This deliberate JSON subset mirrors the Rust schema. Malformed requests exit without reflecting unvalidated identifiers; invalid evidence in a valid request returns a correlated rejection. The Rust supervisor bounds process lifetime and both output streams.

Run the integrated synthetic path from the repository root after `npm ci` in this directory:

```sh
cargo build -p vollmacht-helper-launcher --bin vollmacht-helper-launcher --example real-helper --locked
VOLLMACHT_TEST_DRIVER="$PWD/target/debug/examples/real-helper" \
VOLLMACHT_TEST_LAUNCHER="$PWD/target/debug/vollmacht-helper-launcher" \
npm --prefix spikes/simplewebauthn run test:helper-e2e
```

The `real-helper` example is exclusively a test driver, not a CLI or enrollment API. It generates fresh randomness and hashes the experimental domain, nonce and fixed simulated operation in Rust. The Node test fixture independently signs the resulting challenge with a software key, sends fixture enrollment/evidence to Rust, and Rust invokes Node through the hardened launcher with private pipes and an empty environment. The driver rejects attempts to overwrite its challenge or request ID. Tests cover valid signatures, synced-credential flags, original-byte preservation, wrong expectations and tampered evidence, plus repeat attempts on the same coordinator. Synthetic UP/UV bits are not evidence of a human or platform authenticator.

The fixture input intentionally supplies its own trusted public key: do not expose the driver to agents or treat it as authorized enrollment. Restart/fresh-coordinator replay protection, durable enrollment/revocation, binding to a real agent or execution, packaging integrity and a production mandate schema remain absent. No issuer keys or GitHub tokens enter this experiment. A malicious helper can still lie about verification; process separation does not remove it from the trusted computing base. See [assessment](../../docs/helper-assessment.md) and [protocol](../helper-protocol/README.md).
