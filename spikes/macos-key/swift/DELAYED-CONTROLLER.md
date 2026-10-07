# Delayed diagnostic controller

Experimental P04b plumbing, not production authorization or a completed hardware test. There is no view integration in this slice. Do not copy these changes into the personal Xcode project or run a native diagnostic yet.

## Ownership and timing

The controller's explicit prepare command invokes a trusted driver factory on a dedicated serial worker. The factory constructs the existing-key session there, retaining its original backend, authentication context and prepared handle. Initialization of the controller itself does not invoke the factory or access Keychain. A private mutex protects the non-Sendable driver without unchecked Sendable conformance. Factories, drivers and clocks must not synchronously reenter the controller or export mutable session aliases. Observers run outside that lock and may enqueue commands; a future UI must deliver its updates on the main thread.

An explicit arm command fixes one attempt 15 seconds later, with a five-second acceptance window. The session's own timing checks also remain in force. Early, late, discontinuous or invalid-time callbacks consume the controller without starting the driver. No automatic retry, rescheduling, key replacement or cleanup is provided. Duplicate callbacks cannot run another attempt.

The elapsed-time adapter uses Apple's [ContinuousClock](https://developer.apple.com/documentation/swift/continuousclock), which continues advancing during sleep. Duration conversion and window arithmetic are checked. The constant continuity marker does not prove that sleep was absent, and the timer is not a wake guarantee. A delayed callback must still pass the continuous-time window check.

Cancellation is serialized on the worker. If accepted before the attempt, it consumes the armed session. A cancellation request queued behind a synchronous operation cannot interrupt that operation. An already entered native operation may finish after the deadline; overrun evidence is inconclusive, not proof of execution while locked. No UI should announce successful cancellation until it receives the corresponding result.

The completed report must match the controller's run ID and exact returned attempt. Results contain bounded labels and numeric statuses, not keys, signatures or raw exception text. Completion never claims a verified lock interval. User-reported screen lock and actual Keychain accessibility remain separate evidence questions.

## Validation and remaining work

The fifth fake-only suite compiles in Swift 6 mode with complete strict concurrency checking. Deterministic tests exercise timing boundaries, overflow, failures, stale callbacks, cancellation ordering and report binding. A bounded real-worker test checks off-main factory execution and observer reentry without native APIs. The injected scheduler contract requires serial, asynchronous, non-inline execution; it is trusted test/application infrastructure, not an adversarial executor.

Existing suites and UI typechecking remain mandatory. Coverage includes the controller and its tests without removing unexecuted defensive paths. This does not establish physical behavior, distribution compatibility or a complete coverage-regression gate.

Next work is reviewed UI integration and explicit manual instructions. The existing experimental key, signing identity and personal Xcode project must remain unchanged until that handoff. Denied-access and physical timing tests still require the maintainer; neither compilation nor fake success closes P04b or freezes P06.
