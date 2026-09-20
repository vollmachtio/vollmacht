# WebAuthn compatibility probe (P03a)

This is the first part of P03. It tests the library boundary before adding a local browser server. It does not register a real passkey, open a listener, mint a mandate, or perform GitHub operations. No physical authenticator or browser result is claimed.

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

The browser spike can independently test platform authentication on localhost: loopback-only binding, exact origin/Host validation, an ephemeral protected enrollment session, required UV, request limits, CSRF protection, expiration, and atomic state consumption. It must add registration failure, wrong RP ID and UP checks, and concurrent replay tests. Correctly signed synthetic failures should isolate semantic checks instead of only breaking signatures.

Physical Safari/Chrome registration, assertion, cancellation, expiration, and replay checks remain pending. The user completes the OS prompt. Record observed UV and Touch ID separately; report no universal proof of humanity or device identity. Passkeys may remain in the platform provider after the in-memory server stops; document manual removal of the specifically named test credential.

## Dependency assessment

Direct test dependencies are pinned to webauthn-rs, webauthn-rs-proto, and webauthn-authenticator-rs 0.5.5. Default features are disabled for the server and authenticator crates; only softpasskey is explicitly enabled. Its upstream feature graph also enables softtoken, crypto, and CTAP2 support. These are test dependencies, not a deployment decision. No network/device transports are explicitly enabled.

These upstream crates use MPL-2.0. Keep their source and notices intact; this does not change Vollmacht's Apache-2.0 license. The allowlist in deny.toml covers dependency licenses, including MPL-2.0, rather than relicensing dependencies.

The resolved graph includes OpenSSL FFI and build scripts despite the workspace's unsafe-code prohibition. Workspace lints do not apply to dependencies. OpenSSL headers and pkg-config must be available: Homebrew openssl@3/pkgconf on macOS, libssl-dev/pkg-config on Ubuntu. System OpenSSL maintenance is separate from RustSec scanning.

cargo-deny 0.20.2 checks the locked graph, known advisories, license allowlist, wildcard requirements, and dependency sources in CI. No advisory ignores are configured. Duplicate transitive versions are warnings to be reviewed, not automatically suppressed. Advisory data changes over time; passing today is not a security guarantee. Use only synthetic test data until the dependency and protocol decisions are reviewed.
