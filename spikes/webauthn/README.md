# WebAuthn compatibility and browser probe (P03a/P03b)

This isolated experiment tests the library boundary and provides an opt-in localhost browser server. It does not mint a mandate or perform GitHub operations. No physical authenticator result is claimed until the manual matrix below is completed. The production CLI is unchanged.

Run from the repository root:

```sh
cargo test -p vollmacht-webauthn-probe
python3 scripts/dependencies.py install
```

The tests deliberately use upstream SoftPasskey with simulated user verification. This is a development-only dependency. It cannot serve as evidence of a human approval. The production CLI has no dependency on this spike.

## Findings

The pinned webauthn-rs 0.5.5 passkey API verifies ordinary random-challenge ceremonies. Tests isolate rejection of a correctly signed altered challenge, a correctly signed wrong-port origin, a client-side UV downgrade, an unknown credential, and a corrupt signature. Separate tests show that an assertion cannot be swapped into a different ceremony and that repeatedly verifying the same borrowed state succeeds. The latter is an application obligation: the browser service must consume its own ceremony state atomically, including failures and cancellation.

Source inspection of start_passkey_authentication and its core challenge builder found no supported caller-supplied challenge parameter in 0.5.5. The inspected 0.6.1-dev high-level API has the same constraint. The executable alternate-challenge test demonstrates why changing only the client options is not a solution. No private state is rewritten or serialized and no verification step is bypassed.

This does not establish that all Rust WebAuthn libraries lack custom challenges. It leaves the planned mandate-hash challenge unresolved. Keep that gate separate from ordinary browser passkey feasibility. Associating a library-generated challenge with a stored operation is not equivalent to independently verifiable cryptographic binding of that operation into the challenge.

Sources inspected on 2026-09-20:

- [Stable API and source](https://docs.rs/webauthn-rs/0.5.5/webauthn_rs/struct.Webauthn.html)
- [Core challenge generation](https://docs.rs/webauthn-rs-core/0.5.5/src/webauthn_rs_core/core.rs.html)
- [Development API](https://docs.rs/webauthn-rs/0.6.1-dev/webauthn_rs/struct.Webauthn.html)

## Next gate (P03b)

Before approving the mandate design, evaluate a supported custom-challenge API in another maintained verifier or document a reviewed protocol change. Do not turn the random-challenge probe into a claimed implementation of Human Mandates.

The browser spike independently tests platform authentication on localhost. It adds loopback-only binding, exact origin/Host validation, an ephemeral protected enrollment session, required UV, body limits, CSRF protection, expiration, and atomic state consumption. Automated tests cover registration failure, a correctly signed wrong RP ID, missing UP in otherwise valid none-attestation registration, and concurrent replay. A none-attestation success control distinguishes missing UP from a broken attestation signature.

Physical Safari/Chrome registration, assertion, cancellation, expiration, and replay checks remain pending. The user completes the OS prompt. Record observed UV and Touch ID separately; report no universal proof of humanity or device identity. Passkeys may remain in the platform provider after the in-memory server stops; document manual removal of the specifically named test credential.

## Run the browser experiment

Install the prerequisites in [development](../../docs/development.md), then run:

```sh
cargo run -p vollmacht-webauthn-probe
```

1. Open `http://localhost:8374` in Safari or Chrome. Use this exact hostname and port, not 127.0.0.1. Nothing opens automatically.
2. Paste the session token printed in your terminal into the page. Do not share the token or record the terminal. It authorizes registration and authentication for this process.
3. Select **Register test passkey**, then complete the platform prompt. Enrollment requests a platform authenticator; this client hint is not hardware attestation.
4. Select **Verify passkey**, then complete the prompt. Success means the verifier accepted required WebAuthn user verification, not specifically Touch ID.
5. Stop with Ctrl-C. Remove only the `vollmacht-local-spike` passkey for `localhost` from the provider used in the prompt (for example Apple Passwords). Restarting the probe does not remove stored passkeys.

Each process supports one in-memory enrollment. Refreshing forgets the page's token, not the server enrollment: re-enter the token and use Verify. Restart to test enrollment again, and clean up each test credential. A port collision fails startup; no alternative origin is selected. Never expose this server through a tunnel or reverse proxy.

### Boundary and limitations

- Binds only `127.0.0.1:8374`; checks exact Host, API Origin, content type and a 256-bit OS-random bearer token. No CORS or cookies. Duplicate security headers, query strings, foreign fetch metadata and mismatched absolute authorities fail closed.
- The token is intentionally printed once for local bootstrap and retained in memory. It is not a durable identity, protected credential registry, or defense against local malware, malicious extensions, terminal capture, or a hostile process impersonating this localhost service.
- A mutex serializes verification and state consumption. Only one pending ceremony exists. Matching, structurally valid submissions consume it before verification, even on failure or wrong kind. Stale IDs cannot consume newer state. Malformed JSON is rejected before matching and leaves state pending until cancellation or expiry.
- The monotonic 120-second deadline is checked inside that mutex. Cancel is available during the platform prompt, not after submission begins. If a request or cleanup response is lost, wait for expiry. A lost finish response is ambiguous: registration may already have succeeded; try Verify before restarting. No operation is retried automatically.
- Request bodies are limited to 64 KiB with a five-second handler/body timeout after headers. This is not comprehensive connection-level denial-of-service protection. Only one ceremony is retained, but an attacker on the machine can exhaust sockets or stop the process.
- Public static assets contain no token, external scripts or analytics. Responses set no-store, no-referrer, nosniff and restrictive CSP. Browser assertions and credentials are not logged or written to disk. Memory is not locked or guaranteed to be zeroized, and OS swap/crash dumps remain possible.
- WebAuthn private keys stay with the selected provider; they may be synced. Synthetic tests remove the client platform hint because SoftPasskey does not support it; the server still requires UV. SoftPasskey is a development-only dependency, never an option in the running server.
- The library generates random challenges. This is not the planned canonical mandate-derived challenge and does not settle the protocol design gate.

### Manual evidence matrix

Use a fresh process per browser. Do not put tokens, assertion bytes or personal account names in results. Browser-script tests use stubs and do not replace this matrix.

| Check | Safari | Chrome |
| :--- | :--- | :--- |
| Exact browser/macOS version | Pending | Pending |
| Registration accepted; provider and prompt type noted | Pending | Pending |
| Authentication reports verified UV | Pending | Pending |
| Whether Touch ID was actually used, versus device password or another method | Pending | Pending |
| Cancel platform prompt; next ceremony succeeds | Pending | Pending |
| Wait beyond 120 seconds; old response rejected; new ceremony succeeds | Pending | Pending |
| Resubmit a completed request in local developer tools; receive 409 | Pending | Pending |
| Stop/restart forgets enrollment; targeted provider cleanup completed | Pending | Pending |

Automated coverage includes 10 library compatibility tests, 8 lifecycle tests, 6 HTTP tests, and 4 browser-script tests, plus the existing CLI tests. The HTTP replay test runs two concurrent completions against the real router and requires exactly one success. Node tests execute the shipped script and check binary conversion, token isolation, cancellation cleanup and the submission-stage cancellation regression.

## Dependency assessment

WebAuthn dependencies are pinned to 0.5.5. The experimental server uses webauthn-rs and webauthn-rs-proto; webauthn-authenticator-rs remains test-only. Default features are disabled for the server and authenticator crates; only softpasskey is explicitly enabled for the latter. Its upstream feature graph also enables softtoken, crypto, and CTAP2 support. No authenticator network/device transports are explicitly enabled.

The browser server adds pinned Axum 0.8.9 (HTTP/JSON routing), Tokio 1.53.1 (runtime, loopback socket, shutdown and timeouts), serde/serde_json (transport parsing), getrandom (OS randomness), and subtle (constant-time bearer comparison). Tower and serde_cbor_2 are explicit test dependencies for router requests and none-attestation fixtures. Axum default features are disabled. Review the resolved lockfile and cargo-deny result rather than treating pins as a security guarantee. Sources checked on 2026-09-20: [Axum API](https://docs.rs/axum/0.8.9/axum/), [Tokio API](https://docs.rs/tokio/1.53.1/tokio/).

These upstream crates use MPL-2.0. Keep their source and notices intact; this does not change Vollmacht's Apache-2.0 license. The allowlist in deny.toml covers dependency licenses, including MPL-2.0, rather than relicensing dependencies.

Axum's pinned matchit 0.8.4 dependency declares MIT AND BSD-3-Clause; subtle 2.6.1 declares BSD-3-Clause. Their upstream license files were inspected; version-scoped exceptions admit BSD-3-Clause for these two crates only. Preserve the relevant copyright, license and disclaimer notices in distribution. No advisory exception was added.

The resolved graph includes OpenSSL FFI and build scripts despite the workspace's unsafe-code prohibition. Workspace lints do not apply to dependencies. OpenSSL headers and pkg-config must be available: Homebrew openssl@3/pkgconf on macOS, libssl-dev/pkg-config on Ubuntu. System OpenSSL maintenance is separate from RustSec scanning.

cargo-deny 0.20.2 checks the locked graph, known advisories, license allowlist, wildcard requirements, and dependency sources in CI. No advisory ignores are configured. Duplicate transitive versions are warnings to be reviewed, not automatically suppressed. Advisory data changes over time; passing today is not a security guarantee. Use only synthetic test data until the dependency and protocol decisions are reviewed.
