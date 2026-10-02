# P06 JOSE compatibility review

Scope: isolated josekit 0.10.3 custom ES256 signer experiment and explicit CI/audit integration. No production issuer, verifier, schema or native key provider.

Independent reviewer: `adversarial_p02`, separate from author `durable_key_contract` and root integration author. No blockers for this assessment. Independently ran formatting, strict Clippy and all seven tests, including final malformed-signature additions. Reviewed fixed manifest paths, committed lockfile, dev-dependency inclusion and root-policy audit integration.

Tests verify original signing-input bytes, one SHA-256 operation, raw64 conversion and verification through a direct OpenSSL path rather than josekit. Both paths use OpenSSL; this is not an independent cryptographic implementation. Signed negative demonstrations show that generic JWS validity does not reject every header forbidden by the proposed application profile. Unknown algorithms/critical extensions, wrong keys, modified payload/signature and selected malformed signature lengths/scalars are rejected.

Root final verification: full workspace checks and all three locked dependency audits passed. Reviewer did not independently rerun advisory databases. Existing duplicate-version and unused-policy warnings are retained; no advisory is ignored. Hosted exact-head CI remains required before merge.

Reviewed final test SHA-256: `db81c2a5c11d4dc778e7a42c47eb9d50e119f02561d9324fd347c7d368908e59`. Review covers the final runner and documentation delta too.

Tracked before production selection: strict bounded duplicate-aware parsing, exact profile enforcement, leading-zero DER and complete scalar/malleability vectors, native signer integration and library-maintenance decision. Source review identified recursive equality for boxed algorithm objects; the inspected compact path uses algorithm-name comparisons instead and the spike does not invoke that API. This is a concrete upstream maintenance concern, not a claimed remotely exploitable flaw on the tested path. The library is not selected for production by this PR.
