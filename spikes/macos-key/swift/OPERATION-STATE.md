# Shared probe operation policy

Experimental, fake-tested preparation only. `ProbeOperationState` is not wired into the view or native backend. Do not copy it into the personal Xcode project yet.

A future app must retain one main-actor instance for its entire lifetime and share it across every window. The policy issues operation tokens and excludes Create/Open while diagnostic preparation, arming, execution or cancellation is pending. It allows only one diagnostic allocation per instance, even when preparation fails. Window disappearance must not reset this owner or start new work.

Trusted controller events need an exact result-and-phase adapter before integration. Tokens reject stale events; completion may overtake an earlier armed notification without reopening the gate. A rejected or unknown cancellation keeps operations blocked. Only accepted cancellation, genuine completion or an explicitly terminal controller failure releases the gate. This policy cannot interrupt native work or establish that a lock interval occurred.

The standalone suite tests shared references, overlapping operations, stale tokens, duplicate events, cancellation races and terminal behavior under Swift 6 complete concurrency checking. Instrumented collection measures both policy and tests; it performs no native operation. Remaining work is the reviewed event adapter and app-lifetime UI integration, followed by a separate manual hardware handoff. Existing signing, public-key pin and key identifiers remain unchanged.
