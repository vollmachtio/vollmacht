"""Portable Swift export normalization controls; no compiler or Apple APIs."""

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import coverage_compare as compare
import normalize_swift_coverage as adapter


ROOT = "/trusted/repository"


def fixture():
    files = [{"filename": ROOT + "/" + name, "summary": {
        "lines": {"count": 10, "covered": 4, "percent": 99.99},
        "functions": {"count": 3, "covered": 1},
        "regions": {"count": 100, "covered": 100},
        "instantiations": {"count": 9, "covered": 8},
    }} for name in adapter.SOURCES]
    report = {"type": "llvm.coverage.json.export", "version": "3.0.1", "data": [{
        "files": files, "functions": [{"name": "$sNativeKeyBackend.reserve", "count": 0,
                                        "filenames": [ROOT + "/" + adapter.PREFIX + "Runtime.swift"]}],
    }]}
    metadata = {"schema": 1,
                "tools": {name: "/tools/" + name for name in ("swiftc", "llvm-profdata", "llvm-cov")},
                "versions": {"swiftc": "Apple Swift 6.3.3\nTarget: arm64-apple-macosx26.0",
                             "llvm-profdata": "Apple LLVM 21.0.0", "llvm-cov": "Apple LLVM 21.0.0"},
                "sdk": "/tools/MacOSX.sdk", "measured_suites": ["Tests.swift", "RuntimeTests.swift"],
                "native_backend": "unexecuted", "limits": "collection only",
                "unmeasured": {key: "manual gate" for key in ("ProbeView.swift", "native_keychain", "touch_id")}}
    return report, metadata


class NormalizeTests(unittest.TestCase):
    def test_summary_counts_not_regions_percentages_or_instantiations(self):
        normalized = adapter.normalize(*fixture(), ROOT)
        compare.validate(normalized, adapter.SOURCES)
        self.assertEqual(normalized["metrics"], ["lines", "functions"])
        for counts in normalized["files"].values():
            self.assertEqual(counts, {"lines": {"covered": 4, "total": 10},
                                      "functions": {"covered": 1, "total": 3}})
        self.assertNotIn(adapter.PREFIX + "ProbeView.swift", normalized["files"])

    def test_zero_hit_source_and_regression(self):
        report, metadata = fixture()
        base = adapter.normalize(report, metadata, ROOT)
        report["data"][0]["files"][0]["summary"]["lines"]["covered"] = 0
        head = adapter.normalize(report, metadata, ROOT)
        self.assertEqual(head["files"][adapter.SOURCES[0]]["lines"], {"covered": 0, "total": 10})
        self.assertTrue(compare.compare(base, head, adapter.SOURCES, adapter.SOURCES)["regressions"])

    def test_invalid_exports(self):
        for mutation in ("version", "multiple", "missing", "duplicate", "outside", "alias", "ui",
                         "native_missing", "native_hits", "native_boolean", "native_path"):
            with self.subTest(mutation=mutation):
                report, metadata = fixture()
                unit = report["data"][0]
                if mutation == "version": report["version"] = "4.0.0"
                elif mutation == "multiple": report["data"].append(copy.deepcopy(unit))
                elif mutation == "missing": unit["files"].pop()
                elif mutation == "duplicate": unit["files"].append(copy.deepcopy(unit["files"][0]))
                elif mutation == "outside": unit["files"][0]["filename"] = "/outside/Profile.swift"
                elif mutation == "alias": unit["files"][0]["filename"] = ROOT + "/x/../" + adapter.SOURCES[0]
                elif mutation == "ui": unit["files"][0]["filename"] = ROOT + "/" + adapter.PREFIX + "ProbeView.swift"
                elif mutation == "native_missing": unit["functions"] = []
                elif mutation == "native_hits": unit["functions"][0]["count"] = 1
                elif mutation == "native_boolean": unit["functions"][0]["count"] = False
                elif mutation == "native_path": unit["functions"][0]["filenames"] = [unit["files"][0]["filename"]]
                with self.assertRaises(compare.InvalidReport): adapter.normalize(report, metadata, ROOT)

    def test_invalid_counts(self):
        for value in (-1, True, 0.5, 2**63, "4", None, 11):
            with self.subTest(value=value):
                report, metadata = fixture()
                report["data"][0]["files"][0]["summary"]["lines"]["covered"] = value
                with self.assertRaises(compare.InvalidReport): adapter.normalize(report, metadata, ROOT)

    def test_metadata_identity_and_manual_boundary(self):
        report, metadata = fixture()
        baseline = adapter.normalize(report, metadata, ROOT)
        metadata["tools"]["swiftc"] = "/other/tool/swiftc"
        self.assertEqual(baseline["tool"], adapter.normalize(report, metadata, ROOT)["tool"])
        metadata["versions"]["llvm-cov"] = "Apple LLVM 22.0.0"
        changed = adapter.normalize(report, metadata, ROOT)
        with self.assertRaises(compare.InvalidReport): compare.compare(baseline, changed, adapter.SOURCES, adapter.SOURCES)
        del metadata["unmeasured"]["ProbeView.swift"]
        with self.assertRaises(compare.InvalidReport): adapter.normalize(report, metadata, ROOT)

    def test_bad_roots(self):
        for root in ("relative", "/", "/trusted//repository", "/trusted/../repository"):
            with self.subTest(root=root), self.assertRaises(compare.InvalidReport):
                adapter.normalize(*fixture(), root)

    def test_cli_uses_bounded_duplicate_rejecting_loader(self):
        with tempfile.TemporaryDirectory() as temporary:
            report_path, metadata_path = (Path(temporary) / name for name in ("report", "metadata"))
            report, metadata = fixture()
            metadata_path.write_text(json.dumps(metadata))
            with patch.object(sys, "argv", ["adapter", str(report_path), str(metadata_path), ROOT]):
                report_path.write_text(json.dumps(report))
                with patch("builtins.print") as output:
                    adapter.main()
                    compare.validate(json.loads(output.call_args.args[0]), adapter.SOURCES)
                for raw in ('{"data":[],"data":[]}', '{"n":NaN}', '\ufeff{}'):
                    report_path.write_text(raw)
                    with self.assertRaises(compare.InvalidReport): adapter.main()
                with patch.object(compare, "MAX_REPORT_BYTES", 5):
                    report_path.write_text(json.dumps(report))
                    with self.assertRaises(compare.InvalidReport): adapter.main()


if __name__ == "__main__":
    unittest.main()
