# P03e.2c launcher descriptor hygiene

Experimental exec-only boundary for macOS and Linux. It prevents unrelated inherited file descriptors from reaching the helper. It is not a sandbox, privilege boundary, key protector or production distribution. The Rust coordinator still owns a single child PID and its existing pipes throughout launch, verification, cancellation and cleanup.

## Invocation and ownership

The coordinator requires an explicit absolute `Launch.launcher` path. It launches that executable with an empty environment, the configured working directory and private stdin/stdout/stderr pipes. Arguments are the absolute target executable and optionally one absolute helper path. There is no PATH lookup, shell command, environment override or arbitrary argument forwarding. Target and launcher ownership/integrity are trusted configuration assumptions until packaging work establishes them. Never put tokens or evidence in these arguments.

The launcher replaces its own process image. It never creates a wrapper child to supervise or detach. Thus the PID tracked by the coordinator is also the target PID, preserving the existing kill/reap behavior. Launcher errors are silent nonzero exits: 125 for invalid arguments, 126 for native/exec failure. The coordinator denies these as helper failures; no fallback direct launch is attempted. A pipe error can be observed before the nonzero exit, so callers must not depend on a unique diagnostic ordering.

The trusted launcher briefly inherits unrelated descriptors; the target must not. The coordinator clears the environment before the launcher's dynamic loader runs, and the launcher supplies an empty environment again at target exec. Standalone direct invocation with an injected loader environment is not a supported trust boundary. Same-user malware or a replaced launcher can bypass this design; absolute paths are not integrity proofs.

## Platform mechanism

On macOS, native `posix_spawn` uses `POSIX_SPAWN_SETEXEC` to replace the current image and `POSIX_SPAWN_CLOEXEC_DEFAULT` to exclude descriptors except explicitly declared file actions. Only self-dup actions for 0, 1 and 2 are supplied. Attribute/action initialization, flag setup and action setup are checked; errors never proceed to target execution. Initialized native objects are destroyed on return. [Apple spawn flags](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/posix_spawnattr_setflags.3.html) and [Apple kernel descriptor-inheritance handling](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c) are the primary references.

On Linux, the launcher invokes `close_range` with `CLOSE_RANGE_CLOEXEC` for descriptors 3 through `UINT_MAX`, then `execve`. No descriptor enumeration or soft-resource-limit scan is used. Unsupported or denied syscalls fail closed, with no older-kernel fallback. The CLOEXEC flag requires Linux 5.11 or later; actual syscall availability is checked by its return value, not by trusting a version string. [Linux close_range reference](https://man7.org/linux/man-pages/man2/close_range.2.html).

The Linux process is deliberately single-threaded between descriptor marking and exec. Do not add background runtimes, worker threads, plugins, callbacks or code that opens inheritable descriptors there. Other targets are unsupported. Native launcher source assumes Unix; this is not a Windows implementation.

## Unsafe boundary decision

The existing workspace retains `unsafe_code = forbid`. Only this new executable package uses `deny` with local allowances for `src/native.rs` and the descriptor test fixtures. There is no exported library API offering arbitrary native spawn operations. The target and coordinator code retain their existing prohibition.

The native boundary uses the already locked libc bindings, not copied platform declarations. Every passed string is an owned CString, every argv/env array is NUL-terminated and remains alive across the native call, and each macOS handle is destroyed only after successful initialization. The native module is allowed unsafe code only for this purpose and requires adversarial review when changed. Test-only allowances create deliberately inheritable descriptors and inspect their status.

Alternatives considered: clearing the environment alone does not close descriptors; changing descriptor flags in the multithreaded coordinator introduces shared-state races; generic pre-exec callbacks add post-fork safety constraints; an ordinary wrapper that spawns another child changes cleanup ownership. The isolated exec-only design avoids these concerns at the cost of an additional trusted artifact and narrow native code. This remains an experimental implementation decision, not the final P06 architecture ADR.

## Tests and remaining gates

`cargo test -p vollmacht-helper-launcher` runs file and Unix-socket leak controls, PID and standard-stream preservation, environment clearing, invalid-argument and missing-target failures, no shell fallback, and the nine lifecycle regression tests now routed through the launcher. The direct-launch negative control must actually inherit both descriptors before protected-launch results count. The parent's descriptors remain open and unchanged. The fake-helper and descriptor-probe binaries are fixtures, not runtime verification tools.

`python3 scripts/check.py` runs the full workspace, including the original codec and delayed-launch/reaping tests. Those injected ownership-fault unit tests use an ordinary exec wrapper; real-child integration tests use this launcher. Local execution validates macOS only. Linux runtime results must come from the hosted Linux CI job; do not infer cross-platform success from compilation or source review.

This addresses descriptor leakage when this trusted launcher is used on the tested platforms. It does not establish signed packaging, installation ownership, malicious-descendant containment, durable replay protection or fresh mandate generation. These remain separate gates. P03e.3 adds the [real-helper example](../simplewebauthn/README.md#p03e3-private-assertion-helper) to exercise actual WebAuthn assertion verification through this boundary using trusted synthetic enrollment. No hardware prompt or live GitHub operation is required for these tests.
