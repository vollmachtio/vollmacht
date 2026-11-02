# Bounded jsonwebtoken compatibility assessment

Assessment only, not a production library selection. The exact dev dependency is jsonwebtoken 11.1.0 with default features disabled. No built-in crypto backend or PEM feature is enabled; the existing OpenSSL software-key pattern supplies the test signer. No native API, Keychain item or production key is involved.

## Result

The public encoder supports a custom signer, but does not preserve the candidate canonical protected-header bytes. For the existing experimental three-field header it serializes `typ`, `alg`, `kid`, whereas the candidate canonical bytes use `alg`, `kid`, `typ`. Both are valid JSON/JWS ordering choices; this is a Vollmacht profile compatibility limitation, not an upstream cryptographic vulnerability.

The passing negative demonstration checks literal observed header bytes, their inequality with the literal canonical header, exact callback signing input, preserved one-field payload bytes, a raw 64-byte signature, public-key-only verification, and altered-message rejection. A bounded follow-up also parses the existing independently generated `candidate-envelope-vector.json` canonical envelope string and confirms the public encoder preserves those exact nested payload bytes. Its header still differs from the candidate canonical header. This single ASCII/integer fixture is not full JCS conformance or a production schema/parser assessment. In particular, it does not show that encoding an arbitrarily ordered map performs canonicalization.

Verification uses OpenSSL outside the candidate JWT verifier: it is independent of jsonwebtoken serialization, not independent of the OpenSSL cryptographic provider. This does not assess `JwtVerifier` or the production profile gate. The exact-header prerequisite remains unmet; passing these demonstrations does not mean all required compatibility checks passed.

An exact test-only opaque handle selects one ephemeral software key. Unknown, empty and suffix-extended handles and ES384 are rejected before signing. This routing policy belongs to the test provider, not the library. The factory receives the algorithm and handle but not the header's `kid`: the test changes `kid` and demonstrates that the same key still signs successfully. Header identity and trusted handle must therefore be bound by the application; this is not automatic library enforcement. The `EncodingKey::from_ec_der` container holds handle bytes only on this path; these bytes are intentionally not DER. No native key routing or key confinement is established. The generated key is unrelated to the fixture's trusted issuer key, so re-signing its payload proves byte compatibility, not fixture issuer authority or evidence validity.

The provider is process-global and cannot be installed twice. One integration-test binary contains one assessment test, so its static state does not affect other integration-test executables. Unused verifier/JWK provider interfaces deliberately remain unsupported and are not production-ready defaults.

## Decision boundary

Do not select this public encoder for a profile requiring these exact canonical protected-header bytes. There is no custom JOSE assembler, duplicate parser, extra-header workaround, raw-payload workaround or header-order relaxation here. Production parsing, enrollment, trusted key resolution, duplicate rejection and authorization remain outside this assessment. A valid signature alone is not approval or authorization.

The next decision is whether to retain the existing josekit candidate with its documented maintenance tradeoffs or explicitly revise the header profile. This experiment makes neither choice. Adding further libraries or widening the experiment is not an implied next step.

## Sources and validation

The exact [v11.1.0 encoder](https://github.com/Keats/jsonwebtoken/blob/v11.1.0/src/encoding.rs), [header](https://github.com/Keats/jsonwebtoken/blob/v11.1.0/src/header.rs) and [custom-provider API](https://github.com/Keats/jsonwebtoken/blob/v11.1.0/src/crypto/mod.rs) were inspected before implementation. Release tag commit: `4c0ae752e9acc108c8e2c4c8ed8128dc66014210`. The tagged manifest declares Rust 1.88 and passively maintained status; our pinned toolchain is 1.98.1.

Run the existing `python3 scripts/check-jose.py` and `python3 scripts/dependencies.py`. No existing test or audit command is removed or bypassed. The extra lockfile entries include target-specific dependencies even when they are not compiled on macOS; default-features-disabled does not mean an empty dependency graph. Passing tests and an advisory scan are not a security certification.
