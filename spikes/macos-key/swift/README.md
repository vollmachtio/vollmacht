# Swift native-API assessment

Compile/test-only spike using Foundation and Security from the installed macOS SDK. No packages, transport, persistent backend or production helper are added. The user authorized this assessment, not native Keychain changes or a production language choice.

`Profile.swift` constructs candidate dictionaries for permanent Secure Enclave P-256 creation, exact-tag private-key lookup and a pending generic-password reservation. The access group comes from trusted configuration; input validation does not establish entitlement authorization. The only Security function executed by tests creates an in-memory access-control policy object. It does not create a key or access Keychain.

`Tests.swift` checks exact dictionary contents, invalid inputs, reserve-before-create ordering, duplicate/denied/locked/cancelled/unavailable failures and pending-reservation retention across a simulated restart. Native item operations are absent: there is no call to SecItemAdd, SecItemCopyMatching, SecItemUpdate, SecItemDelete or SecKeyCreateRandomKey. A fake backend alone implements the lifecycle interface.

## Run on macOS

From repository root with Apple's Swift compiler installed:

```sh
python3 spikes/macos-key/swift/run.py
```

Portable runner controls (success, nonzero exit, timeout, platform/argument rejection and cleanup after compiler failure) can be tested separately with `python3 spikes/macos-key/swift/test_run.py`. These do not invoke Swift or Apple APIs.

The Python 3.11+ runner uses a temporary directory for build outputs and module cache, removes it afterward, and bounds direct-child compilation to 180 seconds and execution to 15 seconds. Standard-library subprocess cleanup does not guarantee compiler-descendant lifetime or cleanup on every interruption; CI's job deadline supplies an outer bound. Do not reuse this runner for hostile helper processes. It uses the installed `/usr/bin/swiftc`, not a pinned downloaded toolchain. No certificate, identity or entitlement changes are needed. This executable only runs the tests; it is not an interactive signing helper.

## What this establishes

Swift can represent the required native constants and dictionary shapes directly, avoiding the currently missing Rust builder setters. Lookup requests at most two matches so a future adapter can distinguish one result from ambiguity without an unbounded result array. Identifier suffixes accept exactly 32 lowercase hexadecimal bytes; access-group syntax accepts at most 255 ASCII bytes. Dictionary callers cannot inject additional fields through this typed interface.

Apple documents `kSecMatchLimit` as a numeric maximum and `SecItemCopyMatching` as returning up to that many matches when greater than one. The profile uses integer two, which bridges to CFNumber. Actual Data Protection Keychain behavior with this exact profile remains a native test gate, including zero, one, two and more-than-two matches. [Apple: match limit](https://developer.apple.com/documentation/security/ksecmatchlimit), [Apple: copying matching items](https://developer.apple.com/documentation/security/secitemcopymatching(_:_:))

This is not a serialized helper protocol, concurrency test or claim that Apple accepts each profile at runtime. Successful SDK compilation does not prove entitlement enforcement, access-group isolation, token behavior, persistence or lock-state behavior. In-memory policy construction does not demonstrate hardware protection. Protection flags are fixed in source; tests inspect policy-object type but cannot independently prove Apple's internal policy semantics.

`reserveAndCreate` returns a pending handle, not enrolled authority. No registry commit, public-key export/validation, restart lookup or signing exists here. The fixed pending marker is an experiment fixture, not a production recovery schema. The fake simulates one identity and does not establish native reservation atomicity or durable crash behavior.

## Next gates

Before any real native run, review the exact profiles and define signed test identity/access group, entitlement/provisioning requirements, and explicit operation approval. Then implement bounded native results, public-key validation and binding, reservation state/commit/recovery, and error mapping. Test the [manual matrix](../DURABLE.md) with a dedicated identifier. Separately approve narrowly scoped cleanup. Do not add a generic arbitrary-dictionary or arbitrary-message signing interface.
