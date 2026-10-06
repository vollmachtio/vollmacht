"""Collect Swift fake-test coverage without launching the native backend (Python 3.11+)."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def execute(command, *, timeout=180, env=None):
    # Standard-library timeouts own the direct child, not arbitrary descendants.
    # The CI job deadline is the outer bound for compiler descendants.
    return subprocess.run(
        command, check=True, timeout=timeout, env=env,
        capture_output=True, text=True,
    ).stdout


def validate_report(report, source):
    if report.get("type") != "llvm.coverage.json.export":
        raise ValueError("unexpected coverage format")
    data = report.get("data", [])
    files = {item["filename"] for unit in data for item in unit.get("files", [])}
    for name in ("Profile.swift", "Runtime.swift"):
        if str(source / name) not in files:
            raise ValueError("missing expected Swift source")
    native = [
        function for unit in data for function in unit.get("functions", [])
        if "NativeKeyBackend" in function.get("name", "")
    ]
    if not native or any(function.get("count") != 0 for function in native):
        raise ValueError("native backend must be represented and unexecuted")


def collect(destination):
    if sys.platform != "darwin":
        raise ValueError("Swift coverage requires macOS")
    # Never overwrite an existing destination, even an empty directory.
    destination.mkdir()
    source = Path(__file__).resolve().parent.parent / "spikes/macos-key/swift"
    option = chr(45) * 2
    tools = {}
    versions = {}
    for name in ("swiftc", "llvm-profdata", "llvm-cov"):
        tool = execute(["/usr/bin/xcrun", option + "find", name], timeout=15).strip()
        if not Path(tool).is_absolute() or not Path(tool).is_file():
            raise ValueError("missing selected developer tool")
        tools[name] = tool
        versions[name] = execute([tool, option + "version"], timeout=15).strip()
    sdk = execute(["/usr/bin/xcrun", option + "show-sdk-path"], timeout=15).strip()
    if not Path(sdk).is_absolute() or not Path(sdk).is_dir():
        raise ValueError("missing selected SDK")

    with tempfile.TemporaryDirectory(prefix="vollmacht-swift-coverage-") as temporary:
        directory = Path(temporary)
        objects = []
        profiles = []
        for name, inputs in (
            ("profile-tests", ["Profile.swift", "Tests.swift"]),
            ("runtime-tests", ["Profile.swift", "Runtime.swift", "RuntimeTests.swift"]),
        ):
            binary = directory / name
            execute([
                tools["swiftc"], "-warnings-as-errors", "-Onone",
                "-sdk", sdk,
                "-profile-generate", "-profile-coverage-mapping",
                "-module-cache-path", str(directory / "cache"),
                *[str(source / item) for item in inputs], "-o", str(binary),
            ])
            environment = dict(os.environ)
            environment["LLVM_PROFILE_FILE"] = str(directory / (name + "-%p.profraw"))
            execute([str(binary)], timeout=15, env=environment)
            produced = sorted(directory.glob(name + "-*.profraw"))
            if not produced or any(path.stat().st_size == 0 for path in produced):
                raise ValueError("missing fake-test profile")
            profiles.extend(produced)
            objects.append(binary)

        merged = directory / "coverage.profdata"
        execute([
            tools["llvm-profdata"], "merge", "-sparse",
            *[str(path) for path in profiles], "-o", str(merged),
        ])
        report = json.loads(execute([
            tools["llvm-cov"], "export", str(objects[0]),
            "-object", str(objects[1]), "-instr-profile", str(merged),
        ]))
        validate_report(report, source)
        metadata = {
            "schema": 1,
            "tools": tools,
            "versions": versions,
            "sdk": sdk,
            "measured_suites": ["Tests.swift", "RuntimeTests.swift"],
            "native_backend": "represented in coverage, required zero executions",
            "unmeasured": {
                "ProbeView.swift": "UI is typechecked by the existing runner, not executed here",
                "native_keychain": "manual signed-app, Secure Enclave, persistence and entitlement gate",
                "touch_id": "manual browser and platform-authenticator gate",
            },
            "limits": "collection only; no coverage percentage or regression threshold",
        }
        (destination / "coverage.json").write_text(json.dumps(report) + "\n")
        (destination / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")


def main():
    if len(sys.argv) != 2:
        raise ValueError("usage: coverage_swift.py FRESH_OUTPUT_DIRECTORY")
    collect(Path(sys.argv[1]).absolute())


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        raise SystemExit(f"Swift coverage failed: {type(error).__name__}") from None
