# Durable issuer-key contract (P04b.1)

Status: software contract tested, native persistence not implemented. No Keychain items, identities, certificates, entitlements or signing configuration are changed by these tests. The ephemeral CLI remains unchanged. This is not completion of P04b or evidence of Apple access isolation.

## Lifecycle

`durable.rs` separates explicit `create` from `open`. Trusted configuration supplies a 32-character lowercase hexadecimal identifier; the library adds the fixed `io.vollmacht.experimental.issuer.v1.` namespace. Syntax validation does not establish randomness or authority. Never accept this identifier or enrollment metadata from an agent authorization request.

Creation delegates exclusive creation to a trusted backend, exports that exact handle's public key, validates the SEC1 P-256 point using OpenSSL, and returns a handle bound to enrollment metadata. The backend must ensure exclusive creation, including concurrent processes; a preliminary search is insufficient. This is a required backend guarantee, not something the portable wrapper implements or Apple automatically guarantees for arbitrary labels.

Opening requires trusted enrollment metadata containing the identifier and exact public key. It accepts exactly one matching handle and validates its public key against the enrolled bytes. It never creates, replaces or rotates keys. Missing, ambiguous, locked, denied, cancelled, unsupported and unavailable results remain failures. Counterparts compare public key bytes, not signature encodings or an Apple application-label hash.

Creation and enrollment persistence are not one transaction. If creation succeeds but export, validation or later registry storage fails, a key may remain orphaned. Do not automatically delete it or repeat creation. Future recovery must reconcile a narrowly identified item under explicit operator control. There is intentionally no deletion API, signing API, durable registry, production retry policy or key rotation in this slice.

The fake backend is deterministic and snapshots stored state into a new instance to model restart. It is not a filesystem crash test, concurrency implementation or proof of Keychain behavior. Twelve tests cover exact identifiers, curve validation, create/open separation, restart binding, unrelated identities, missing/ambiguous/duplicate results, access errors without fallback, orphan retention and valid-key substitution.

## Fixed native profile and API gate

The future adapter must request EC P-256, Secure Enclave, permanent Data Protection Keychain storage, AccessibleWhenUnlockedThisDeviceOnly and PrivateKeyUsage. Do not request synchronized issuer keys or fall back to file Keychain/software keys. WebAuthn remains the human approval mechanism; issuer-key operations do not gain a biometric requirement implicitly.

Source inspection of pinned security-framework 3.7.0 found:

- `GenerateKeyOptions` exposes location, token, protection, size and label, but no application-tag or access-group setters. Specifying a location sets permanent attributes; that alone does not establish unique identity or isolation.
- `Location::DataProtectionKeychain` is feature gated by `OSX_10_15`. This package currently disables default features, so the existing ephemeral configuration does not enable that variant.
- `SecKey::generate(CFDictionary)` is a public safe wrapper accepting custom attributes. The builder limitation is not absence of all Rust APIs. A later slice must review dictionary construction/constants and safe-wrapper support, or propose a maintained helper. No new unsafe exception is approved here.
- `ItemSearchOptions` supports access group, private-key class, application label, Data Protection-only searches and explicit match limits. Its default limit is one, unsuitable for ambiguity detection. Application label is not application tag.

Select a supported exact application-tag or persistent-reference strategy and prove exclusive creation before adding the native backend. Do not substitute a display label. Keep trusted access-group configuration outside agent input. An opened handle prevents a second identifier lookup during public-key export, but does not establish protection attributes by itself; the native adapter remains trusted and must enforce the profile. Signing-time lock/access failures and handle lifetime require native tests.

## Signed identity and manual test matrix

All rows are pending. Use a dedicated test identifier and record macOS, hardware, binary digest, signing identity class, entitlement values, provisioning profile details and numeric OS outcomes. Do not publish private keys or certificate secrets. Observe outcomes; do not infer isolation from a single successful call.

| Scenario | Required evidence |
| :--- | :--- |
| Unsigned/ad-hoc development binary | Record supported/denied result; never interpret debug success as release identity isolation |
| Properly provisioned signed probe | Explicit create, stop process, open in new process, same public key, fixed-message signature verifies |
| Same identity rebuilt/updated | Existing item remains accessible with the same public key; no replacement |
| Different application or unauthorized access group | Lookup/sign denied or item invisible; unrelated identity cannot use the key |
| Missing or invalid entitlement/profile | Failure without alternate storage or weaker configuration |
| Two simultaneous creates for one identifier | Exactly one enrolled identity; loser fails; no hidden duplicate or overwritten registry |
| Duplicate matches or changed expected public key | Fail closed; never select first match or silently repin |
| Locked session, then unlocked session | Record lookup and signing behavior separately; no automatic prompting/fallback assumption |
| User cancellation, if any platform interaction occurs | Fail without retry loop; cancellation is not approval |
| Crash after creation before enrollment persistence | Orphan remains discoverable only through explicit scoped recovery; normal open does not trust it |
| Missing item after previously successful enrollment | Fail; normal startup must not regenerate identity |
| Explicit test cleanup | Separately approved deletion of the exact test item, after identity verification; unrelated items unchanged |

The release packaging identity and access-group entitlement are not chosen yet. Actual signing/provisioning and hardware checks require user participation. Apple access groups constrain entitled programs, not arbitrary trusted code inside an authorized process. Same-user malware, compromised signer code and an agent that can invoke an unrestricted signing interface remain threats. Non-exportable hardware keys do not fix those authorization failures.

## Sources

Checked 2026-10-01. Apple documentation distinguishes the Data Protection Keychain from the file-based implementation and derives access groups from code-signing entitlements. Appropriate provisioning must authorize restricted entitlement claims; exact release packaging remains a gate, not an assumption.

- [Apple TN3137: Mac keychain implementations](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)
- [Apple: Keychain access groups](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps)
- [Apple: distribution-signed macOS code](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac)
- [Apple: protecting keys with Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [Pinned key wrapper](https://docs.rs/crate/security-framework/3.7.0/source/src/key.rs)
- [Pinned item wrapper](https://docs.rs/crate/security-framework/3.7.0/source/src/item.rs)

Apple search-index excerpts were available during this review; full documentation pages requested JavaScript and their Markdown endpoints were not readable through the browser fetcher. API details above were verified against the installed pinned wrapper source. The native integration must recheck current Apple documentation and entitlement requirements before implementation.
