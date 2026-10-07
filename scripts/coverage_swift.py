"""Collect Swift fake-test coverage without launching the native backend (Python 3.11+)."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

SUITES = [
    ("profile-tests", ["Profile.swift", "Tests.swift"]),
    ("runtime-tests", ["Profile.swift", "Runtime.swift", "RuntimeTests.swift"]),
    ("diagnostic-plan-tests", ["DiagnosticPlan.swift", "DiagnosticPlanTests.swift"]),
    ("diagnostic-session-tests", ["Profile.swift", "Runtime.swift", "DiagnosticPlan.swift",
                                  "DiagnosticSession.swift", "DiagnosticSessionTests.swift"]),
]
MEASURED_SOURCES = sorted({name for _, inputs in SUITES for name in inputs})
MEASURED_SUITES = [inputs[-1] for _, inputs in SUITES]


def compiler_target(version):
    targets = re.findall(r"^Target: ([a-zA-Z0-9_.-]+)$", version, re.MULTILINE)
    if len(targets) != 1 or not re.fullmatch(r"(?:arm64|x86_64)-apple-macosx[0-9]+(?:\.[0-9]+){0,2}", targets[0]):
        raise ValueError("missing supported macOS compiler target")
    return targets[0]


def configuration(target):
    return {
        "id": "swift-fake-suites-v3", "target": target,
        "compile_flags": ["-warnings-as-errors", "-Onone", "-profile-generate", "-profile-coverage-mapping"],
        "suites": [inputs.copy() for _, inputs in SUITES],
        "merge": "sparse", "export": "single-merged-json", "environment": "inherited-v1",
    }


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
    if not isinstance(data, list) or len(data) != 1:
        raise ValueError("expected one merged Swift coverage unit")
    files = [item["filename"] for unit in data for item in unit.get("files", [])]
    if len(files) != len(set(files)) or set(files) != {str(source / name) for name in MEASURED_SOURCES}:
        raise ValueError("missing, duplicate or unexpected Swift source")
    native = [
        function for unit in data for function in unit.get("functions", [])
        if "NativeKeyBackend" in function.get("name", "")
    ]
    if not native or any(type(function.get("count")) is not int or function["count"] != 0 for function in native):
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
    xcrun = ["/usr/bin/xcrun", option + "sdk", "macosx"]
    for name in ("swiftc", "llvm-profdata", "llvm-cov"):
        tool = execute([*xcrun, option + "find", name], timeout=15).strip()
        if not Path(tool).is_absolute() or not Path(tool).is_file():
            raise ValueError("missing selected developer tool")
        tools[name] = tool
        versions[name] = execute([tool, option + "version"], timeout=15).strip()
        if not versions[name] or not versions[name].isascii() or any(
            char != "\n" and not 32 <= ord(char) < 127 for char in versions[name]
        ):
            raise ValueError("missing compiler or LLVM version")
    sdk = {"name": "macosx"}
    for field, query in (("path", "show-sdk-path"), ("version", "show-sdk-version"), ("build", "show-sdk-build-version")):
        sdk[field] = execute([*xcrun, option + query], timeout=15).strip()
    if not Path(sdk["path"]).is_absolute() or not Path(sdk["path"]).is_dir():
        raise ValueError("missing selected SDK")
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,3}", sdk["version"]) or not re.fullmatch(r"[A-Za-z0-9.]+", sdk["build"]):
        raise ValueError("missing SDK version or build")
    config = configuration(compiler_target(versions["swiftc"]))

    with tempfile.TemporaryDirectory(prefix="vollmacht-swift-coverage-") as temporary:
        directory = Path(temporary)
        objects = []
        profiles = []
        for name, inputs in zip((name for name, _ in SUITES), config["suites"], strict=True):
            binary = directory / name
            execute([
                tools["swiftc"], *config["compile_flags"],
                "-sdk", sdk["path"], "-target", config["target"],
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
            *[argument for binary in objects[1:] for argument in ("-object", str(binary))],
            "-instr-profile", str(merged),
        ]))
        validate_report(report, source)
        metadata = {
            "schema": 2,
            "tools": tools,
            "versions": versions,
            "sdk": sdk,
            "collector_config": config,
            "measured_suites": MEASURED_SUITES.copy(),
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
