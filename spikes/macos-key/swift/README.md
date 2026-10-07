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

The Python 3.11+ runner uses a temporary directory for build outputs and module cache, removes it afterward, and bounds each direct-child compilation to 180 seconds and execution to 15 seconds. It runs eight fake-only test binaries (profiles, runtime, diagnostic plan, diagnostic session, delayed controller, probe operation state, probe event adapter and probe model), then typechecks all nine app sources without launching the UI. Suites five through eight and the UI typecheck use Swift 6 mode with complete strict concurrency checking. ProbeView and its production singleton factories are excluded from executed suites. Coverage configuration v7 measures sixteen implementation/test sources; the UI remains unmeasured. Standard-library subprocess cleanup does not guarantee compiler-descendant lifetime or cleanup on every interruption; CI's job deadline supplies an outer bound. Do not reuse this runner for hostile helper processes. It uses the installed `/usr/bin/swiftc`, not a pinned downloaded toolchain. No certificate, identity or entitlement changes are needed for these tests.

## What this establishes

Swift can represent the required native constants and dictionary shapes directly, avoiding the currently missing Rust builder setters. Lookup requests at most two matches so a future adapter can distinguish one result from ambiguity without an unbounded result array. Identifier suffixes accept exactly 32 lowercase hexadecimal bytes; access-group syntax accepts at most 255 ASCII bytes. Dictionary callers cannot inject additional fields through this typed interface.

Apple documents `kSecMatchLimit` as a numeric maximum and `SecItemCopyMatching` as returning up to that many matches when greater than one. The profile uses integer two, which bridges to CFNumber. Actual Data Protection Keychain behavior with this exact profile remains a native test gate, including zero, one, two and more-than-two matches. [Apple: match limit](https://developer.apple.com/documentation/security/ksecmatchlimit), [Apple: copying matching items](https://developer.apple.com/documentation/security/secitemcopymatching(_:_:))

This is not a serialized helper protocol or a claim that Apple accepts each profile at runtime. Fake scheduling tests do not establish native concurrency behavior. Successful SDK compilation does not prove entitlement enforcement, access-group isolation, token behavior, persistence or lock-state behavior. In-memory policy construction does not demonstrate hardware protection. Protection flags are fixed in source; tests inspect policy-object type but cannot independently prove Apple's internal policy semantics.

The original `reserveAndCreate` returns a pending handle, not enrolled authority. The new manual runtime adds a ready record, public-key binding and fixed-message signature checks, but no production registry. Its markers are experiment fixtures, not a production recovery schema. Fakes do not establish native reservation atomicity or durable crash behavior.

`preparePersistent` isolates the read-only existing-key path for diagnostics. It validates the caller's retained P-256 public point, exact ready record, unique lookup and matching public bytes, then returns immutable request/pin fields and the exact retained handle. It never signs, creates, updates, repins or falls back. This is a point-in-time binding, not authorization, a storage lock or protection against later native-state changes; a generic reference handle's underlying object is not made immutable. `openPersistent` reuses preparation and still verifies one fixed-message signature. Fake tests cover preparation failures and preserved open behavior. Personal project updates and native testing remain maintainer actions.

Three independently callable prepared-key diagnostics separate ready-record validation, fresh unique-key lookup with pin comparison, and fixed-message signing with the original retained handle. `diagnosePreparedLookup` never replaces that handle. `diagnosePreparedSigning` verifies the signature against the prepared public pin without re-reading the record or looking up another key. Denial in one diagnostic is deliberately not a prerequisite for another; this is observational test plumbing, not production authorization or revocation enforcement. There is no arbitrary-message API, mutation or retry. Existing create/open behavior remains unchanged. Their locked-device behavior has not been established by fake tests.

The diagnostic owner retains the original backend and its noninteractive authentication context alongside the prepared handle. The underlying generic API alone does not enforce that ownership relationship or turn point-in-time preparation into authority. Software tests establish neither screen-lock state nor Keychain-lock behavior.

`DiagnosticSession` provides that synchronous owner: explicit construction prepares the existing key once, then privately retains the backend, prepared handle, clock and one-shot plan. Callers can arm, cancel, attempt and complete, but cannot substitute the handle or claim a verified lock interval. Completion always reports inconclusive lock evidence. The reference-type session avoids accidental value-copy replay; callers must still serialize access without reentrant callbacks, and pre-existing aliases to generic reference dependencies are not isolated. It is not itself a scheduler or thread-safe controller. The UI supplies a native backend only inside the controller's explicit preparation worker; automated tests supply fakes. Raw OS status values and synthetic diagnostic failures share an integer representation, not a globally unique error namespace; a failure code alone is not proof that access was denied. Physical lock-state evidence remains pending.

## Next gates

The [delayed controller](DELAYED-CONTROLLER.md) supplies a dedicated worker, bounded timer window and exact result binding around a session factory. The manual view now wires it through one shared app-lifetime model and the exact event adapter. Opening the app stores factories without performing native work. Prepare, Arm and Cancel remain explicit actions; locked-device hardware testing is still pending.

The [shared probe operation policy](OPERATION-STATE.md) gates legacy Create/Open and the single diagnostic across views. The shared model delivers trusted controller events to the main actor before applying the adapter. Window disappearance does not reset ownership or cancel work. After independent review and CI, only the maintainer should update the personal Xcode target following [the manual handoff](RESTART.md), preserving the existing key, pin and signing identity. No personal project or hardware state is changed by the automated checks.

Before any real native run, independently review the runtime and UI and verify the signed test identity and provisioning. Follow the [restart instructions](RESTART.md) with its fixed dedicated identifier. The broader [manual matrix](../DURABLE.md), protected enrollment and recovery remain gates. Separately approve narrowly scoped cleanup. Do not add a generic arbitrary-dictionary or arbitrary-message signing interface.
