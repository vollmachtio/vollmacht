# Browser coverage attribution review

Independent adversarial reviewer: `adversarial_p02`.

Disposition: no blocking findings in the four reviewed source files. This is a source-attribution prerequisite, not a coverage-percentage gate or a full-coverage claim.

## Scope and findings

The existing seven browser-script tests remain unchanged apart from supplying the resolved shipped script filename to the VM. The wrapper runs that same test file with a fresh temporary V8 coverage directory, checks the exact pinned Node version, propagates nonzero test exits, and rejects missing, anonymous, or unexecuted source attribution. The workspace runner executes the new validator controls before the wrapper.

The runtime is trusted developer tooling. Its direct subprocesses have 10-second version and 30-second test deadlines; Python kills and reaps the direct child on timeout, and the temporary directory is context-managed. This is not hostile process-tree containment, a disk/output quota, or proof of runtime authenticity. No such guarantee is claimed. The tests use browser doubles, not a browser or hardware authenticator.

## Independent verification

- Pinned Node 24.21.0: all seven existing browser tests passed, with zero failures, cancellations, or skips; shipped `app.js` attribution passed.
- All seven new Python validator tests passed, including unrelated execution, wrong source paths, anonymous VM records, empty/reversed/zero-hit ranges, multiple records, and native-path/file-URI acceptance.
- Reviewer diagnostics confirmed test failure and timeout propagation, wrong-version rejection before test launch, and rejection of missing source, anonymous VM source, and zero executed ranges.
- Compared the original and changed browser test declarations: all seven are retained. Reviewed the final workspace runner integration statically.

The reviewer did not rerun the complete Rust/Swift workspace checks for this narrow change. Separate untracked coverage collectors are outside this review.

## Reviewed source SHA-256

| File | SHA-256 |
| :--- | :--- |
| `scripts/check.py` | `bbacf562131e34c03640d5ab822cfe9687f190d9fedb6854d5b177fd5824d105` |
| `scripts/test_browser_coverage.py` | `01e02d23c10817f48aa194bba6ae4859a481b031cbf815c8b04abf0eb8f19ff1` |
| `scripts/test_browser_coverage_checks.py` | `7ce67caf2d033da047bd98c335444039b32b44cbf4730cdf224b26efcc37ae9a` |
| `spikes/webauthn/tests/browser.cjs` | `6f17745adabe47900f80f6fdc37c66cb0a566fdcd7159408f186ad1bfad368b1` |
