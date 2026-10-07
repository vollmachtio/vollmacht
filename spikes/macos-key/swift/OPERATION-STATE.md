# Shared probe operation policy

Experimental, fake-tested preparation only. `ProbeOperationState` is not wired into the view or native backend. Do not copy it into the personal Xcode project yet.

A future app must retain one main-actor instance for its entire lifetime and share it across every window. The policy issues operation tokens and excludes Create/Open while diagnostic preparation, arming, execution or cancellation is pending. It allows only one diagnostic allocation per instance, even when preparation fails. Window disappearance must not reset this owner or start new work.

`ProbeEventAdapter` now maps exact trusted controller phase/result pairs to policy acknowledgements on the main actor. It rejects unknown pairs and accepts completion summaries only with the bounded ASCII field order, known outcomes, canonical Int32 failure codes and exact timing labels. Tokens reject stale events; completion may overtake an earlier armed notification without reopening the gate. A rejected or unknown cancellation keeps operations blocked. Only accepted cancellation, genuine completion or an explicitly terminal controller failure releases the gate. This policy cannot interrupt native work or establish that a lock interval occurred.

The standalone policy suite tests shared references, overlapping operations, stale tokens, duplicate events, cancellation races and terminal behavior under Swift 6 complete concurrency checking. A separate adapter suite covers phase/result mappings and malformed completion summaries under the same strict checking. Instrumented collection measures policy, adapter and their tests; it performs no native operation.

The adapter is an in-process boundary for a trusted controller, not an authenticated event parser or proof that work happened. Future wiring must preserve observer provenance, dispatch to the main actor and retain one shared app-lifetime owner. No observer or UI integration is implemented here. A separate reviewed manual hardware handoff remains required. Existing signing, public-key pin and key identifiers remain unchanged.
