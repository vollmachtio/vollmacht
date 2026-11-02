# Revised candidate crypto-profile vectors

Assessment only. `fixtures/candidate-profile-vector.json` is a separate proposed-profile fixture, not acceptance of P06a or a production validator. Historical fixtures remain unchanged and are not implicitly accepted by this profile.

The required literal `crypto_profile: "vollmacht-local-es256-v1"` appears in approval, execution proof, enrollment proposal A and possession proof B. It does not appear as a duplicate envelope or protected-header field. Schema version 1 and existing domain strings remain unchanged for this prerelease revision. Fixed compact protected-header bytes use `typ`, `alg`, `kid` order; payload bytes use JCS. This is not a library-selection decision.

The stdout-only `../simplewebauthn/profile-vector-generator.mjs` requires Node 24.21.0 and uses a restricted ASCII/integer oracle independently of Rust serialization. Fresh synthetic keys and maintained Node signing APIs produce approval and enrollment assertions, issuer envelope, execution proof and possession proof. Re-running changes random keys/signatures. No private keys are emitted. The synthetic UP/UV flags are not evidence of a person, Touch ID or hardware protection. Fixed timestamps are not live approvals.

The revised approval challenge covers the profile-bearing payload. The envelope covers that payload and its fresh assertion; execution links the new mandate, operation and envelope digests. Enrollment A has its own recomputed authorization digest and fresh assertion; B binds that digest and the same profile. Trusted profile values in fixture metadata represent test context, not an authenticated registry.

Rust tests independently compare canonical bytes and hashes, verify Node-produced JWSs with public keys and verify the raw synthetic assertion signing inputs. They demonstrate missing, unknown and downgrade-profile disagreements at each of the four locations, and validly signed execution variants still disagree with expected context. These are explicit fixture/context assertions, not implemented server rejection, registry policy, enrollment, replay protection or schema enforcement. A cryptographically valid artifact is not authorization. Full profile parsing, cross-context validation and fail-closed production dispatch remain separate implementation tasks.

Existing `scripts/check-canonicalization.py` and `scripts/check-jose.py` include the new Rust integration tests. Source accounting lists the generator and tests as unmeasured; no coverage claim follows from execution.
