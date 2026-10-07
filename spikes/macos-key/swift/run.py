"""Compile Swift experiments and run fake-only tests on macOS (Python 3.11+)."""

from pathlib import Path
import subprocess
import sys
import tempfile


def run(command, timeout):
    # Trusted compiler/test process only. Standard-library timeout cleanup owns the
    # direct child; this intentionally makes no descendant-lifetime guarantee.
    subprocess.run(command, check=True, timeout=timeout)


def main():
    if sys.platform != "darwin":
        raise SystemExit("unsupported_platform: this assessment requires macOS")
    if len(sys.argv) != 1:
        raise SystemExit("This test runner accepts no arguments.")
    source = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix="vollmacht-swift-profile-") as temporary:
        directory = Path(temporary)
        executable = directory / "profile-tests"
        run([
            "/usr/bin/swiftc", "-warnings-as-errors",
            "-module-cache-path", str(directory / "cache"),
            str(source / "Profile.swift"), str(source / "Tests.swift"),
            "-o", str(executable),
        ], timeout=180)
        run([str(executable)], timeout=15)
        runtime_tests = directory / "runtime-tests"
        run([
            "/usr/bin/swiftc", "-warnings-as-errors",
            "-module-cache-path", str(directory / "cache"),
            str(source / "Profile.swift"), str(source / "Runtime.swift"),
            str(source / "RuntimeTests.swift"), "-o", str(runtime_tests),
        ], timeout=180)
        run([str(runtime_tests)], timeout=15)
        diagnostic_tests = directory / "diagnostic-plan-tests"
        run([
            "/usr/bin/swiftc", "-warnings-as-errors",
            "-module-cache-path", str(directory / "cache"),
            str(source / "DiagnosticPlan.swift"),
            str(source / "DiagnosticPlanTests.swift"), "-o", str(diagnostic_tests),
        ], timeout=180)
        run([str(diagnostic_tests)], timeout=15)
        session_tests = directory / "diagnostic-session-tests"
        run([
            "/usr/bin/swiftc", "-warnings-as-errors",
            "-module-cache-path", str(directory / "cache"),
            str(source / "Profile.swift"), str(source / "Runtime.swift"),
            str(source / "DiagnosticPlan.swift"), str(source / "DiagnosticSession.swift"),
            str(source / "DiagnosticSessionTests.swift"), "-o", str(session_tests),
        ], timeout=180)
        run([str(session_tests)], timeout=15)
        # Check the manual UI without launching it or accessing Keychain.
        run([
            "/usr/bin/swiftc", "-warnings-as-errors", "-typecheck",
            "-module-cache-path", str(directory / "cache"),
            str(source / "Profile.swift"), str(source / "Runtime.swift"),
            str(source / "ProbeView.swift"),
        ], timeout=180)


if __name__ == "__main__":
    try:
        main()
    except (OSError, subprocess.SubprocessError) as error:
        raise SystemExit(f"Swift assessment failed: {type(error).__name__}") from None
