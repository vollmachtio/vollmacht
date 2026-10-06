"""Normalize the one merged Swift fake-suite export, not a complete coverage gate."""

import hashlib
import json
from pathlib import PurePosixPath
import re
import sys

from coverage_compare import InvalidReport, fields, load, require, validate


PREFIX = "spikes/macos-key/swift/"
SOURCES = [PREFIX + name for name in (
    "Profile.swift", "Runtime.swift", "RuntimeTests.swift", "Tests.swift",
)]
METRICS = ["lines", "functions"]
POLICY = "swift-fake-suites-v1-sdk-build-unverified"


def canonical_absolute(value):
    require(type(value) is str and bool(value), "invalid absolute path")
    path = PurePosixPath(value)
    require(path.is_absolute() and str(path) == value and path.anchor == "/"
            and ".." not in path.parts and "\\" not in value
            and all(ord(char) >= 32 and ord(char) != 127 for char in value),
            "noncanonical absolute path")
    return path


def tool_identity(metadata):
    fields(metadata, {"schema", "tools", "versions", "sdk", "measured_suites",
                      "native_backend", "unmeasured", "limits"}, "invalid collector metadata")
    require(type(metadata["schema"]) is int and metadata["schema"] == 1,
            "unsupported collector metadata version")
    names = {"swiftc", "llvm-profdata", "llvm-cov"}
    fields(metadata["versions"], names, "missing compiler or LLVM versions")
    fields(metadata["tools"], names, "missing compiler or LLVM tool paths")
    for path in metadata["tools"].values():
        canonical_absolute(path)
    canonical_absolute(metadata["sdk"])
    for version in metadata["versions"].values():
        require(type(version) is str and bool(version) and version.isascii()
                and all(char == "\n" or 32 <= ord(char) < 127 for char in version),
                "invalid compiler or LLVM version")
    targets = re.findall(r"^Target: ([a-zA-Z0-9_.-]+)$", metadata["versions"]["swiftc"], re.MULTILINE)
    require(len(targets) == 1 and "-apple-macosx" in targets[0], "missing macOS compiler target")
    require(metadata["measured_suites"] == ["Tests.swift", "RuntimeTests.swift"],
            "unexpected measured suite list")
    fields(metadata["unmeasured"], {"ProbeView.swift", "native_keychain", "touch_id"},
           "missing explicit manual coverage boundaries")
    for value in [metadata["native_backend"], metadata["limits"], *metadata["unmeasured"].values()]:
        require(type(value) is str and bool(value.strip()), "missing measurement limitation")
    # Paths vary between machines. Exact version text and target remain part of
    # identity, but SDK build information is absent from collector schema 1.
    versions = json.dumps(metadata["versions"], sort_keys=True, separators=(",", ":"))
    return {
        "name": "swift-llvm-cov", "version": "sha256:" + hashlib.sha256(versions.encode()).hexdigest(),
        "platform": targets[0], "policy_id": POLICY,
    }


def normalize(report, metadata, source_root):
    root = canonical_absolute(source_root)
    require(root != PurePosixPath("/"), "repository root cannot be filesystem root")
    require(type(report) is dict and report.get("type") == "llvm.coverage.json.export"
            and report.get("version") == "3.0.1", "unsupported LLVM export")
    data = report.get("data")
    require(type(data) is list and len(data) == 1 and type(data[0]) is dict,
            "expected one LLVM-merged export unit")
    unit = data[0]
    require(type(unit.get("files")) is list, "missing LLVM source list")
    expected = {str(root / name): name for name in SOURCES}
    files = {}
    for item in unit["files"]:
        require(type(item) is dict, "invalid LLVM source")
        filename = item.get("filename")
        canonical_absolute(filename)
        require(filename in expected, "unexpected or outside-root LLVM source")
        name = expected[filename]
        require(name not in files, "duplicate LLVM source")
        summary = item.get("summary")
        require(type(summary) is dict, "missing source summary")
        counts = {}
        for metric in METRICS:
            raw = summary.get(metric)
            require(type(raw) is dict and "covered" in raw and "count" in raw,
                    "missing measured metric")
            require(all(type(raw[key]) is int and 0 <= raw[key] <= 2**63 - 1
                        for key in ("covered", "count")), "invalid measured count")
            require(raw["covered"] <= raw["count"], "covered exceeds measured total")
            counts[metric] = {"covered": raw["covered"], "total": raw["count"]}
        files[name] = counts
    require(set(files) == set(SOURCES), "missing expected LLVM source")
    functions = unit.get("functions")
    require(type(functions) is list, "missing native function evidence")
    native = []
    for function in functions:
        require(type(function) is dict and type(function.get("name")) is str,
                "invalid function evidence")
        if "NativeKeyBackend" in function["name"]:
            require(function.get("filenames") == [str(root / (PREFIX + "Runtime.swift"))],
                    "native function attributed to unexpected source")
            require(type(function.get("count")) is int and function["count"] == 0,
                    "native backend must remain unexecuted")
            native.append(function)
    require(bool(native), "native backend absent from export")
    normalized = {"version": 1, "tool": tool_identity(metadata), "metrics": METRICS.copy(),
                  "files": dict(sorted(files.items()))}
    validate(normalized, SOURCES)
    return normalized


def main():
    if len(sys.argv) != 4:
        raise InvalidReport("usage: normalize_swift_coverage.py EXPORT METADATA TRUSTED_SOURCE_ROOT")
    value = normalize(load(sys.argv[1]), load(sys.argv[2]), sys.argv[3])
    print(json.dumps(value, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (InvalidReport, OSError, RecursionError) as error:
        raise SystemExit(f"Swift coverage normalization failed: {error}") from None
