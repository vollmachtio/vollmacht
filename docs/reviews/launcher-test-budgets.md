# Launcher test-budget review

Independent adversarial reviewer: `adversarial_p02`.

Disposition: no blocking findings in the single reviewed test file.

The former combined maximum-request test is split into two explicit tests. The nonreading-child case retains the exact 400 ms coordinator deadline and expected `DeadlineExceeded`, and adds a monotonic three-second completion bound, unchanged-counter assertion and consumed-retry rejection. The success case uses the existing suite's normal five-second success budget, while strengthening acceptance checks for counter advancement, backup flags, single use and retained committed state. Both paths retain the child-reaping check.

Maximum-size request construction still precedes the coordinator deadline expression. The elapsed bound uses `Instant`, not wall-clock time. No production timeout or lifecycle code changes. All existing failure, cancellation, registry and malformed-output tests remain present. Successful processing within 400 ms is no longer asserted; that was not a security deadline or declared latency requirement. The separate short stalled-child deadline remains covered rather than being relaxed to accommodate scheduling variation.

Independent validation: all ten launcher lifecycle integration tests passed using locked offline dependencies, including both split tests. No ignored or filtered tests, native key operations, Git mutations or reviewed-source edits. Unrelated SDK/coverage changes and a full-workspace rerun are outside this review. Passing once does not prove absence of scheduling-related test flakiness.

Reviewed source SHA-256:

```text
1253e78f20fc2814976fe7b47979d31df18cb1ddb8c0c34a81b258aa2da0cac9  spikes/helper-launcher/tests/lifecycle.rs
```
