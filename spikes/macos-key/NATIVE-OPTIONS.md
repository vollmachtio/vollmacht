# Native persistence options

Status: a narrow Swift compile/test assessment is authorized; production architecture is not selected. Checked 2026-10-01. This assessment does not implement a backend or authorize Keychain changes, signing, entitlements or new Rust unsafe code. The [durable contract](DURABLE.md) remains a software-only experiment.

## Verified constraints

Apple defines key-item uniqueness using a composite that includes both application tag and application label, plus access group, key class/type/size and synchronization attributes. Therefore, a tag alone cannot enforce exclusive creation of a newly generated key. [Apple: key item class](https://developer.apple.com/documentation/security/ksecclasskey)

Apple also explicitly cautions against generating multiple keys with the same tag. Its retrieval examples can return only the first match; the production adapter must detect ambiguity instead. A preliminary lookup does not prevent concurrent creation. [Apple: generating keys](https://developer.apple.com/documentation/security/generating-new-cryptographic-keys), [Apple: storing keys](https://developer.apple.com/documentation/security/storing-keys-in-the-keychain)

Persistent references are opaque bytes intended for later retrieval, including subsequent process invocations. They are locators, not proof of authorization or public-key identity, and do not by themselves solve duplicate creation or crash recovery. [Apple: persistent reference](https://developer.apple.com/documentation/security/ksecvaluepersistentref)

Installed security-framework 3.7.0 sources show:

- `GenerateKeyOptions` lacks application-tag and access-group setters; `SecKey::generate(CFDictionary)` accepts custom attributes through a safe public method.
- `ItemSearchOptions` lacks application-tag and persistent-reference query setters. It supports access groups, private-key class and application-label filtering; those are not interchangeable with application tags.
- Its default result limit is one. Explicit cardinality checks are necessary.
- `ignore_legacy_keychains()` emits the Data Protection selector on macOS only with feature `OSX_10_15`. Without it, setting this option does not enforce Data Protection-only lookup. Current package defaults are disabled.
- Relevant raw Core Foundation constants are extern statics in security-framework-sys. Directly accessing those statics needs an unsafe boundary. This is not proof that every possible Rust integration requires new unsafe code; safe builder extensions and other maintained APIs need assessment.

Sources: [pinned key wrapper](https://docs.rs/crate/security-framework/3.7.0/source/src/key.rs), [pinned item wrapper](https://docs.rs/crate/security-framework/3.7.0/source/src/item.rs), [pinned native declarations](https://docs.rs/crate/security-framework-sys/2.17.0/source/src/item.rs). API inspection used the installed pinned source, not a newer library version.

## Smallest implementation choice

| Candidate | Benefit | Additional work and limits |
| :--- | :--- | :--- |
| Narrow Swift Security-framework helper spike | Uses Apple's imported native API without adding Rust unsafe code | Another build/package boundary; bounded protocol, caller trust, signing and failure behavior need review |
| Extend maintained Rust safe builders | Keeps native integration in the Rust dependency model | Assess/upstream missing creation/query options, pin reviewed implementation and review any native boundary; do not invent CF key strings |

The user authorized assessing the narrow Swift helper, without selecting it as the production architecture. The [compile/test spike](swift/README.md) constructs native dictionary profiles and tests fake-only lifecycle ordering. Neither option removes the signed-identity, provisioning, hardware or registry-integrity gates. No fallback to software keys or file Keychain is proposed.

## Proposed exclusive-creation reservation

A separate Data Protection generic-password record could reserve the identifier before key generation. Apple documents uniqueness for access group, account, service and synchronization state, making this a candidate atomic reservation primitive. Specify all four consistently, including synchronization disabled; never use an update-or-insert password convenience API for reservation. [Apple: generic-password item class](https://developer.apple.com/documentation/security/ksecclassgenericpassword)

This is a proposal, not a tested Apple guarantee for our packaging or a transaction spanning key generation and registry storage. Required design and tests:

1. Atomically add a pending reservation under a fixed service, trusted access group and exact identifier. Duplicate means stop, not open-or-replace.
2. Generate only after reservation succeeds. Bind its outcome to the exact key locator and validated public key; publish usable enrollment only after protected durable state is committed.
3. A crash before generation leaves a pending reservation. A crash after generation can leave an orphan key. Neither state permits automatic retries, repinning, deletion or regeneration.
4. Unknown write outcomes fail closed. Explicit recovery must distinguish incomplete enrollment from an existing identity and verify the selected key without trusting agent-supplied metadata.
5. Test simultaneous creators, failures at every boundary, restart, locked/denied access, incomplete records and registry tampering. Reservation behavior must hold across cooperating processes, not only threads.

Reservation does not defend against an already authorized malicious process deleting or rewriting its records. Access-group isolation and the trusted signer's authorization surface remain essential. Scope recovery/deletion narrowly and obtain separate approval for actual test cleanup.

## Evidence limits

Apple primary documentation text was available through current search results. Some direct documentation pages required JavaScript and their linked Markdown responses were unsupported by the fetcher. No native persistence, concurrent creation, crash recovery or release identity tests were executed. All proposed behaviors require validation with the selected adapter and an explicitly approved test identity.
