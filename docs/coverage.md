# Coverage rollout

Coverage collection is being added without replacing existing tests. Required CI still runs the full automated suites on Linux and macOS. A passing suite does not demonstrate nondecreasing coverage or correct security behavior.

## Implemented measurements

The browser test harness names the shipped source when executing it in a VM. The attribution check runs all seven existing browser tests, requires an executed record for that exact source, and rejects anonymous VM records. This is an attribution check, not a line or branch coverage threshold.

On macOS, `scripts/coverage_swift.py` compiles and executes the two fake-only Swift suites with the selected Apple toolchain's coverage instrumentation. It exports LLVM JSON and tool metadata. Both `Profile.swift` and `Runtime.swift` must appear, and native-backend functions must be represented with zero executions. A missing report, missing expected source, or unexpectedly executed native backend fails the collector. The original noninstrumented runner and UI typecheck remain mandatory.

Run the collector with a fresh output directory:

```sh
python3 scripts/coverage_swift.py /private/tmp/vollmacht-swift-coverage-new
```

No native Keychain operation, signed app, browser ceremony or Touch ID prompt is executed. Unexecuted native backend code stays in the report; it is not removed to inflate the percentage. `ProbeView.swift` is typechecked but not executed and is explicitly listed as unmeasured in metadata. Fake-test source is also retained in the raw report, so its aggregate is not a production-only coverage figure.

CI uploads only coverage JSON and metadata, not raw profile files or executables. Reports use the runner's paths. Local reports can contain local source paths and should not be uploaded without inspection. Missing artifact files fail the upload step.

## Remaining gates

There is **no coverage-regression threshold yet**. Before adding one:

1. Collect complete, reviewed source inventories for Rust, JavaScript, Python and Swift. Explicitly account for unexecuted code and platform-specific paths.
2. Measure the exact trusted base and proposed merge with identical tooling. Do not use a PR-controlled percentage or silently reset the baseline.
3. Compare integer counts for overall and retained-file coverage; include changed-code requirements. Report line, function and branch metrics only where supported.
4. Fail on missing reports, new unclassified sources or weakened measurement policy. Review removals, skips and weakened assertions separately: percentages cannot establish test quality.
5. Make the comparison a required check only after its negative controls and cross-platform behavior have been independently reviewed.

The initial Rust instrumentation experiment found that LLVM's profiling runtime adds `__LLVM_PROFILE_RT_INIT_ONCE` to an otherwise empty process environment on the tested Mac. This makes the descriptor-inspection fixture correctly reject the altered environment. Do not skip its test or weaken its empty-environment assertion. A separately reviewed instrumentation strategy is required. Successful `execve` can also bypass normal profile flushing, so launcher success-path measurements need explicit assessment. Apple and Rust LLVM profile tools must not be mixed.

The Node helper intentionally clears its environment. Do not pass coverage variables through its production boundary just to collect profiles. Its real-helper isolation tests remain mandatory even when a separate test-only instrumentation path is used later.

Hardware tests remain explicit manual gates. A zero-hit native function or unmeasured UI cannot be described as exercised by hosted CI. Coverage is evidence about execution, not proof that assertions are sufficient or authorization is secure.
