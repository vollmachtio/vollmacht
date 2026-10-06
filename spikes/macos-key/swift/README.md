# Swift native-API assessment

Experimental Swift assessment using installed Apple frameworks. No packages, transport or production helper are added. The automated runner remains fake-only. A separate [explicit manual restart experiment](RESTART.md) now supplies a native adapter and UI; only the user-triggered app actions access Keychain. This does not settle a production language choice.

`Profile.swift` constructs candidate dictionaries for permanent Secure Enclave P-256 creation, exact-tag private-key lookup and a pending generic-password reservation. The access group comes from trusted configuration; input validation does not establish entitlement authorization. The only Security function executed by tests creates an in-memory access-control policy object. It does not create a key or access Keychain.

`Tests.swift` checks exact dictionary contents, invalid inputs, reserve-before-create ordering, duplicate/denied/locked/cancelled/unavailable failures and pending-reservation retention across a simulated restart. Its original lifecycle interface has a fake backend only. `RuntimeTests.swift` separately exercises the manual experiment's state flow with a fake backend and a publicly known software test key. Neither test invokes native item operations. `NativeKeyBackend` methods are compiled but never invoked by the runner. There is no delete implementation.

## Run on macOS

From repository root with Apple's Swift compiler installed:

```sh
python3 spikes/macos-key/swift/run.py
```

Portable runner controls (success, nonzero exit, timeout, platform/argument rejection and cleanup after compiler failure) can be tested separately with `python3 spikes/macos-key/swift/test_run.py`. These do not invoke Swift or Apple APIs.

The Python 3.11+ runner uses a temporary directory for build outputs and module cache, removes it afterward, and bounds each direct-child compilation to 180 seconds and execution to 15 seconds. It runs two fake-only test binaries and typechecks the UI without launching it. Standard-library subprocess cleanup does not guarantee compiler-descendant lifetime or cleanup on every interruption; CI's job deadline supplies an outer bound. Do not reuse this runner for hostile helper processes. It uses the installed `/usr/bin/swiftc`, not a pinned downloaded toolchain. No certificate, identity or entitlement changes are needed for these tests.

## What this establishes

Swift can represent the required native constants and dictionary shapes directly, avoiding the currently missing Rust builder setters. Lookup requests at most two matches so a future adapter can distinguish one result from ambiguity without an unbounded result array. Identifier suffixes accept exactly 32 lowercase hexadecimal bytes; access-group syntax accepts at most 255 ASCII bytes. Dictionary callers cannot inject additional fields through this typed interface.

Apple documents `kSecMatchLimit` as a numeric maximum and `SecItemCopyMatching` as returning up to that many matches when greater than one. The profile uses integer two, which bridges to CFNumber. Actual Data Protection Keychain behavior with this exact profile remains a native test gate, including zero, one, two and more-than-two matches. [Apple: match limit](https://developer.apple.com/documentation/security/ksecmatchlimit), [Apple: copying matching items](https://developer.apple.com/documentation/security/secitemcopymatching(_:_:))

This is not a serialized helper protocol, concurrency test or claim that Apple accepts each profile at runtime. Successful SDK compilation does not prove entitlement enforcement, access-group isolation, token behavior, persistence or lock-state behavior. In-memory policy construction does not demonstrate hardware protection. Protection flags are fixed in source; tests inspect policy-object type but cannot independently prove Apple's internal policy semantics.

The original `reserveAndCreate` returns a pending handle, not enrolled authority. The new manual runtime adds a ready record, public-key binding and fixed-message signature checks, but no production registry. Its markers are experiment fixtures, not a production recovery schema. Fakes do not establish native reservation atomicity or durable crash behavior.

## Next gates

Before any real native run, independently review the runtime and UI and verify the signed test identity and provisioning. Follow the [restart instructions](RESTART.md) with its fixed dedicated identifier. The broader [manual matrix](../DURABLE.md), protected enrollment and recovery remain gates. Separately approve narrowly scoped cleanup. Do not add a generic arbitrary-dictionary or arbitrary-message signing interface.
