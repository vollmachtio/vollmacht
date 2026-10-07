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
    metadata = {"schema": 2,
                "tools": {name: "/tools/" + name for name in ("swiftc", "llvm-profdata", "llvm-cov")},
                "versions": {"swiftc": "Apple Swift 6.3.3\nTarget: arm64-apple-macosx26.0",
                             "llvm-profdata": "Apple LLVM 21.0.0", "llvm-cov": "Apple LLVM 21.0.0"},
                "sdk": {"name": "macosx", "path": "/tools/MacOSX.sdk", "version": "26.5", "build": "25F70"},
                "collector_config": adapter.configuration("arm64-apple-macosx26.0"),
                "measured_suites": ["Tests.swift", "RuntimeTests.swift", "DiagnosticPlanTests.swift", "DiagnosticSessionTests.swift",
                                    "DelayedDiagnosticControllerTests.swift", "ProbeOperationStateTests.swift"],
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

    def test_scope_is_exactly_twelve_sources_and_every_source_is_required(self):
        names = {"Profile.swift", "Runtime.swift", "RuntimeTests.swift", "Tests.swift",
                 "DiagnosticPlan.swift", "DiagnosticPlanTests.swift", "DiagnosticSession.swift", "DiagnosticSessionTests.swift",
                 "DelayedDiagnosticController.swift", "DelayedDiagnosticControllerTests.swift",
                 "ProbeOperationState.swift", "ProbeOperationStateTests.swift"}
        self.assertEqual(set(adapter.SOURCES), {adapter.PREFIX + name for name in names})
        for name in adapter.SOURCES:
            for duplicate in (False, True):
                with self.subTest(name=name, duplicate=duplicate):
                    report, metadata = fixture()
                    items = report["data"][0]["files"]
                    selected = next(item for item in items if item["filename"] == ROOT + "/" + name)
                    if duplicate:
                        items.append(copy.deepcopy(selected))
                    else:
                        items.remove(selected)
                    with self.assertRaises(compare.InvalidReport):
                        adapter.normalize(report, metadata, ROOT)

    def test_old_scope_and_weakened_suite_metadata_are_rejected(self):
        for mutation in ("v2-id", "v3-id", "v4-id", "v2-suites", "v3-suites", "v4-suites", "missing-suite", "duplicate-suite", "reordered-suite"):
            report, metadata = fixture()
            if mutation in ("v2-id", "v3-id", "v4-id"):
                metadata["collector_config"]["id"] = "swift-fake-suites-" + mutation[:2]
            elif mutation in ("v2-suites", "v3-suites", "v4-suites"):
                count = {"v2-suites": 2, "v3-suites": 4, "v4-suites": 5}[mutation]
                metadata["collector_config"]["suites"] = metadata["collector_config"]["suites"][:count]
                metadata["measured_suites"] = metadata["measured_suites"][:count]
            elif mutation == "missing-suite":
                metadata["measured_suites"].pop()
            elif mutation == "duplicate-suite":
                metadata["measured_suites"].append("Tests.swift")
            else:
                metadata["measured_suites"].reverse()
            with self.subTest(mutation=mutation), self.assertRaises(compare.InvalidReport):
                adapter.normalize(report, metadata, ROOT)
        report, metadata = fixture()
        head = adapter.normalize(report, metadata, ROOT)
        for version in ("v2", "v3", "v4"):
            base = copy.deepcopy(head)
            base["tool"]["policy_id"] = "swift-fake-suites-" + version + "-sdk-config-identity"
            with self.subTest(version=version), self.assertRaises(compare.InvalidReport):
                compare.compare(base, head, adapter.SOURCES, adapter.SOURCES)

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
        metadata["sdk"]["path"] = "/other/sdk/MacOSX.sdk"
        self.assertEqual(baseline["tool"], adapter.normalize(report, metadata, ROOT)["tool"])
        metadata["versions"]["llvm-cov"] = "Apple LLVM 22.0.0"
        changed = adapter.normalize(report, metadata, ROOT)
        with self.assertRaises(compare.InvalidReport): compare.compare(baseline, changed, adapter.SOURCES, adapter.SOURCES)
        del metadata["unmeasured"]["ProbeView.swift"]
        with self.assertRaises(compare.InvalidReport): adapter.normalize(report, metadata, ROOT)

    def test_sdk_identity_changes_and_old_metadata_rejected(self):
        report, metadata = fixture()
        baseline = adapter.normalize(report, metadata, ROOT)
        for key, value in (("build", "25F71"), ("version", "26.6")):
            with self.subTest(key=key):
                changed = copy.deepcopy(metadata)
                changed["sdk"][key] = value
                normalized = adapter.normalize(report, changed, ROOT)
                with self.assertRaises(compare.InvalidReport):
                    compare.compare(baseline, normalized, adapter.SOURCES, adapter.SOURCES)
        for mutation in ("schema", "missing-sdk-build", "empty-sdk-build", "flags", "target", "suites", "merge", "export",
                         "missing-suite-flags", "weakened-controller-flags", "weakened-operation-flags", "changed-original-flags"):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(metadata)
                if mutation == "schema":
                    changed["schema"] = 1
                elif mutation == "missing-sdk-build":
                    del changed["sdk"]["build"]
                elif mutation == "empty-sdk-build":
                    changed["sdk"]["build"] = ""
                elif mutation == "flags":
                    changed["collector_config"]["compile_flags"][1] = "-O"
                elif mutation == "suites":
                    changed["collector_config"]["suites"].pop()
                elif mutation == "missing-suite-flags":
                    del changed["collector_config"]["suite_compile_flags"]
                elif mutation == "weakened-controller-flags":
                    changed["collector_config"]["suite_compile_flags"][4] = []
                elif mutation == "weakened-operation-flags":
                    changed["collector_config"]["suite_compile_flags"][-1] = []
                elif mutation == "changed-original-flags":
                    changed["collector_config"]["suite_compile_flags"][0] = ["-swift-version", "6"]
                else:
                    changed["collector_config"][mutation] = "different"
                with self.assertRaises(compare.InvalidReport): adapter.normalize(report, changed, ROOT)

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
