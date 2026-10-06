"""Account for tracked sources without treating classification as coverage."""

import json
import os
from pathlib import Path
import subprocess
import sys

from coverage_compare import InvalidReport, fields, inventory, load, require

SUFFIXES = {".rs", ".py", ".js", ".mjs", ".cjs", ".swift"}
ROLES = {"cli_scaffold", "experiment", "test", "test_support", "developer_tool",
         "fixture_generator", "assessment_model", "documentation_only"}
MEASUREMENTS = {"unmeasured", "attribution_only", "raw_swift_fake_tests"}


def tracked_sources(raw):
    require(type(raw) is bytes, "Git inventory must be bytes")
    require(not raw or raw.endswith(b"\0"), "Git inventory must be NUL terminated")
    try:
        names = raw.decode("utf-8").split("\0")[:-1] if raw else []
    except UnicodeError as error:
        raise InvalidReport("Git inventory is not UTF-8") from error
    require(all(names) and len(set(names)) == len(names), "empty or duplicate Git path")
    selected = [name for name in names if Path(name).suffix in SUFFIXES]
    return inventory(selected)


def validate(document, tracked):
    fields(document, {"version", "sources"}, "invalid inventory fields")
    require(type(document["version"]) is int and document["version"] == 1,
            "unsupported inventory version")
    require(type(document["sources"]) is list, "sources must be an array")
    entries = {}
    for item in document["sources"]:
        fields(item, {"path", "role", "measurement"}, "invalid source record fields")
        path = item["path"]
        inventory([path])
        require(Path(path).suffix in SUFFIXES, "unsupported source extension")
        require(path not in entries, "duplicate source record")
        require(type(item["role"]) is str and item["role"] in ROLES, "unknown source role")
        require(type(item["measurement"]) is str and item["measurement"] in MEASUREMENTS,
                "unknown measurement status")
        entries[path] = item
    expected = inventory(list(tracked))
    missing = sorted(expected - entries.keys())
    stale = sorted(entries.keys() - expected)
    require(not missing and not stale,
            f"source inventory requires review: unclassified={missing}, untracked_or_removed={stale}")
    return {"sources": len(entries),
            "roles": {role: sum(item["role"] == role for item in entries.values())
                      for role in sorted(ROLES)},
            "measurements": {status: sum(item["measurement"] == status for item in entries.values())
                             for status in sorted(MEASUREMENTS)}}


def main():
    if len(sys.argv) != 1:
        raise SystemExit("coverage_inventory.py accepts no arguments.")
    root = Path(__file__).resolve().parent.parent
    # No inherited GIT_DIR/GIT_WORK_TREE override may redirect this inventory.
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=True, capture_output=True, timeout=15, env={"PATH": os.defpath},
    )
    document = load(root / "coverage/sources.json")
    print(json.dumps(validate(document, tracked_sources(result.stdout)), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (InvalidReport, OSError, subprocess.SubprocessError, RecursionError) as error:
        raise SystemExit(f"Coverage source inventory failed: {error}") from None
