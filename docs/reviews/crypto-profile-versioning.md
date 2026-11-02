# Cryptographic profile versioning adversarial review

Date: 2026-11-01. Reviewer: independent agent `/root/adversarial_roadmap_november`, separate from the document and vector authors. Scope: the staged, unstaged and new files listed below against HEAD `d118791da5c50611a368ec036ecd0e0fc1ec6df8`. The personal `VollmachtSigningProbe` project is excluded and untouched. This review does not accept P06a, adopt a production library or qualify a deployment.

## Reviewed source identity

| Source | SHA-256 |
| :--- | :--- |
| `docs/architecture/crypto-profiles.md` | `60b8d7409bca42e51e576f8f84cbbf32117352762f26522cf08522c2195d358a` |
| `docs/architecture/deterministic-headers.md` | `ae882f6a4e1209811100ecc6a2461f1e965c9fdfae51636bf3619b1bc1ee1b47` |
| `docs/architecture/mandate-contract.md` | `8f9e755c01b930aa408c6f7e8036baa5f3aae8db3fb9c842a3401756b84ec63f` |
| `docs/architecture/agent-enrollment-profile.md` | `5450b2043178a061254a6e9071c61e8d37ea417d7d978eb170303aaab412b810` |
| `coverage/sources.json` | `87d5136553997240141b165628ef2d177087abf3045eb7ae987e311ccf0ba79f` |
| `spikes/canonicalization/PROFILE.md` | `2e2ed4d6913b3af170251dc3c8583baec37d2eec651b6041176073248b9e5e08` |
| `spikes/canonicalization/fixtures/candidate-profile-vector.json` | `b5660d224a1dd6f07366bf002f91a317141bbba5256c16dc531b7c984b191215` |
| `spikes/canonicalization/tests/candidate_profile.rs` | `7ee3de49fcb14e95bd543043b23a63c7fb85252ba39a3810c7005df0254f8777` |
| `spikes/jose/tests/candidate_profile.rs` | `46cda3df5289e7c63730a51b008c53c0d919b35548cb85034bb3d5fec06bee7e` |
| `spikes/simplewebauthn/profile-vector-generator.mjs` | `9b4cbea458e95308d49f87443e5bb2423db36eb033bf43fc674023841d586172` |

## Findings and disposition

No actionable findings or unresolved blockers identified in the final integrated scope. No source fix was requested by this reviewer. The coordinator requested an additional direct unsigned profile-mutation case; this reviewer checked that final delta and reran the JOSE suite after it was present.

## Contract review

- The required exact suite identifier is independent of the object schema version, but cannot override schema sizes or meanings. Unknown, missing, disabled or mismatched profiles reject without aliasing, inferred defaults, algorithm trials or fallback.
- Profile binding covers approval payload, execution proof, enrollment proposal A and possession proof B. The issuer envelope authenticates its nested approval profile without creating a second competing field. The operation digest alone remains non-authorizing.
- Trusted installation policy, role-specific registry metadata and pending state determine the expected profile. Header type/algorithm/key ID, public key and provider handle are bound separately; submitted profile strings cannot select or update a trust root.
- Current policy permission and revision checks remain necessary when re-verifying retained evidence against its original profile/context. Counters are not updated again. Migration and concurrent profile acceptance remain future reviewed work, not implemented commands.
- The sole current suite stays classical. The documents correctly deny that replacing only the issuer signature establishes post-quantum security for classical passkeys or agent proofs.
- The lifetime agent-slot paragraph is consistent with the provider proposal: disable cannot allow a new-key enrollment to serve as unsupported rotation.

## Fixture and test review

The stdout-only Node generator uses fresh synthetic keys and maintained signing APIs, emits public JWKs only and preserves existing historical fixtures. Its restricted ASCII/integer ordering oracle is independent of Rust JCS serialization; it is not presented as a general-purpose canonicalizer.

Rust independently compares all four profile-bearing canonical objects, exact deterministic headers, public agent thumbprint and domain-separated digests. The approval assertion challenge is recomputed from the revised payload; the issuer envelope carries that assertion; execution links the revised mandate and envelope. Enrollment A has its separate revised authorization digest and raw assertion; B binds that digest and the matching profile.

JOSE tests verify the three Node-produced signatures with the expected public keys, reject wrong keys and signature mutation, and reject a changed profile-bearing body while retaining the original header and signature. The latter changes the nested approval profile for the issuer artifact and the top-level profile for execution and possession. Synthetic WebAuthn signing inputs are independently verified as authenticator data plus the hash of original client-data bytes, with expected challenge, RP hash and flags checked.

Missing, unknown and downgrade cases at four object locations are explicit canonical-byte/context comparisons. Validly re-signed execution variants still have a profile disagreement with test context. These are not a server validator or evidence that production rejects such inputs. Synthetic UP/UV flags do not establish human or hardware verification. The documents state these limits and leave strict schema enforcement, disabled-profile policy, provider dispatch behavior and complete acceptance cases pending.

The inventory adds two tests and one fixture generator, all unmeasured. No source exclusion, threshold reduction, historical-fixture replacement or new production dependency is introduced.

## Independent validation

- `python3 scripts/check-canonicalization.py`: formatting and all-target Clippy passed; all 27 integration tests passed.
- `python3 scripts/check-jose.py`: formatting and all-target Clippy passed; all 22 integration tests passed, including a rerun after the direct unsigned profile-tamper cases.
- `python3 scripts/coverage_inventory.py`: 107 sources accounted for; 90 unmeasured, 16 raw Swift fake-test and one attribution-only source.
- Coverage inventory unit suite: all nine tests passed.
- Fresh generator execution under Node 24.21.0 produced parseable stdout with the four required profile locations and public-only JWK fields. Output was checked in memory and was not written over the committed fixture.
- Git whitespace diff check passed.

No authored source was edited by this reviewer; only this report was written. No native probe, Keychain, signing identity, VM or external write was performed. Passing fixture suites do not freeze the contract, prove complete profile enforcement or establish a hardware result. Exact integrated-head CI and review of material changes after these hashes remain required before merge.
