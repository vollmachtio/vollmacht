"""Strict normalized coverage comparison; no raw collector or trust discovery."""

import json
from pathlib import Path, PurePosixPath
import sys

METRICS = {"lines", "functions", "branches"}
MAX_REPORT_BYTES = 8 * 1024 * 1024


class InvalidReport(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise InvalidReport(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON member")
        result[key] = value
    return result


def load(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_REPORT_BYTES + 1)
    require(len(raw) <= MAX_REPORT_BYTES, "input exceeds size limit")
    require(not raw.startswith(b"\xef\xbb\xbf"), "UTF-8 BOM is unsupported")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                          parse_int=unsigned_integer, parse_constant=lambda _: reject_constant())
    except (UnicodeError, json.JSONDecodeError) as error:
        raise InvalidReport("invalid UTF-8 JSON") from error


def reject_constant():
    raise InvalidReport("nonfinite JSON number")


def unsigned_integer(token):
    require(not token.startswith("-") and len(token) <= 19, "invalid integer token")
    return int(token)


def inventory(value):
    require(type(value) is list, "inventory must be an array")
    result = set()
    for name in value:
        require(type(name) is str and bool(name), "invalid source name")
        require(name.isascii() and all(32 <= ord(c) < 127 for c in name), "invalid source name")
        path = PurePosixPath(name)
        require(not path.is_absolute() and str(path) == name
                and ".." not in path.parts and "\\" not in name
                and ":" not in name and name != ".", "noncanonical source path")
        require(name not in result, "duplicate inventory source")
        result.add(name)
    return result


def fields(value, names, message):
    require(type(value) is dict and set(value) == set(names), message)


def validate(report, sources):
    expected = inventory(sources)
    fields(report, {"version", "tool", "metrics", "files"}, "invalid report fields")
    require(type(report["version"]) is int and report["version"] == 1, "unsupported report version")
    fields(report["tool"], {"name", "version", "platform", "policy_id"}, "invalid tool fields")
    require(all(type(value) is str and value and value.isascii()
                and all(32 <= ord(c) < 127 for c in value)
                for value in report["tool"].values()), "invalid tool identity")
    metrics = report["metrics"]
    require(type(metrics) is list and bool(metrics)
            and all(type(metric) is str and metric in METRICS for metric in metrics), "invalid metrics")
    require(len(set(metrics)) == len(metrics), "duplicate metric")
    files = report["files"]
    require(type(files) is dict and set(files) == expected, "missing or unclassified source")
    for counts in files.values():
        fields(counts, metrics, "missing or extra source metric")
        for item in counts.values():
            fields(item, {"covered", "total"}, "invalid count fields")
            require(all(type(value) is int and 0 <= value <= 2**63 - 1
                        for value in item.values()), "invalid count")
            require(item["covered"] <= item["total"], "covered exceeds total")
    return expected


def nondecreasing(base, head):
    # A metric with no measurable items is vacuously complete, never zero percent.
    base_covered, base_total = (base["covered"], base["total"]) if base["total"] else (1, 1)
    head_covered, head_total = (head["covered"], head["total"]) if head["total"] else (1, 1)
    return head_covered * base_total >= base_covered * head_total


def compare(base, head, base_sources, head_sources):
    old = validate(base, base_sources)
    new = validate(head, head_sources)
    require(base["tool"] == head["tool"], "measurement tool or policy mismatch")
    require(set(base["metrics"]) == set(head["metrics"]), "measurement metrics mismatch")
    regressions = []
    for metric in sorted(base["metrics"]):
        def overall(report):
            return {key: sum(counts[metric][key] for counts in report["files"].values())
                    for key in ("covered", "total")}
        if not nondecreasing(overall(base), overall(head)):
            regressions.append({"scope": "overall", "metric": metric})
        for name in sorted(old & new):
            if not nondecreasing(base["files"][name][metric], head["files"][name][metric]):
                regressions.append({"scope": "file", "path": name, "metric": metric})
    return {"regressions": regressions, "added": sorted(new - old), "removed": sorted(old - new)}


def main():
    if len(sys.argv) != 5:
        raise SystemExit("Usage: coverage_compare.py BASE HEAD BASE_INVENTORY HEAD_INVENTORY")
    try:
        result = compare(*(load(path) for path in sys.argv[1:]))
    except (InvalidReport, OSError, RecursionError) as error:
        raise SystemExit(f"Coverage comparison failed: {error}") from None
    print(json.dumps(result, sort_keys=True))
    if result["regressions"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
