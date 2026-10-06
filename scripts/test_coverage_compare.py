"""Portable negative controls for normalized coverage comparison."""

import copy
from fractions import Fraction
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from coverage_compare import InvalidReport, compare, inventory, load, nondecreasing


def report(covered=8, total=10):
    return {"version": 1,
            "tool": {"name": "example", "version": "1", "platform": "test", "policy_id": "reviewed-1"},
            "metrics": ["lines", "branches", "functions"],
            "files": {"src/a.rs": {metric: {"covered": covered, "total": total}
                                   for metric in ["lines", "branches", "functions"]}}}


def run(base, head, old=None, new=None):
    return compare(base, head, ["src/a.rs"] if old is None else old,
                   ["src/a.rs"] if new is None else new)


class ComparisonTests(unittest.TestCase):
    def test_equal_and_improved_counts(self):
        self.assertEqual(run(report(), report())["regressions"], [])
        self.assertEqual(run(report(), report(9))["regressions"], [])

    def test_every_metric_regression_is_reported(self):
        for metric in report()["metrics"]:
            head = report()
            head["files"]["src/a.rs"][metric]["covered"] = 7
            self.assertEqual(run(report(), head)["regressions"], [
                {"scope": "overall", "metric": metric},
                {"scope": "file", "path": "src/a.rs", "metric": metric},
            ])

    def test_other_file_improvement_cannot_mask_retained_file_loss(self):
        base, head = report(), report(7)
        base["files"]["src/b.rs"] = copy.deepcopy(report(0)["files"]["src/a.rs"])
        head["files"]["src/b.rs"] = copy.deepcopy(report(10)["files"]["src/a.rs"])
        result = run(base, head, list(base["files"]), list(head["files"]))
        self.assertEqual(len(result["regressions"]), 3)
        self.assertTrue(all(item["scope"] == "file" for item in result["regressions"]))

    def test_new_uncovered_file_counts_toward_overall(self):
        head = report()
        head["files"]["src/new.rs"] = report(0)["files"]["src/a.rs"]
        result = run(report(), head, new=list(head["files"]))
        self.assertEqual(result["added"], ["src/new.rs"])
        self.assertEqual(len(result["regressions"]), 3)

    def test_removals_reported_without_inventing_retained_file(self):
        base = report()
        base["files"]["src/removed.rs"] = report(0)["files"]["src/a.rs"]
        result = run(base, report(), old=list(base["files"]))
        self.assertEqual(result["removed"], ["src/removed.rs"])
        self.assertEqual(result["regressions"], [])

    def test_missing_unclassified_and_renamed_files_fail(self):
        for names in [[], ["src/other.rs"], ["src/a.rs", "src/missing.rs"]]:
            with self.subTest(names=names), self.assertRaises(InvalidReport):
                compare(report(), report(), ["src/a.rs"], names)

    def test_invalid_counts_are_not_coerced(self):
        for value in [True, False, "8", 8.0, -1, None, 2**63]:
            for key in ["covered", "total"]:
                head = report()
                head["files"]["src/a.rs"]["lines"][key] = value
                with self.subTest(value=value, key=key), self.assertRaises(InvalidReport):
                    run(report(), head)
        with self.assertRaises(InvalidReport):
            run(report(), report(11, 10))

    def test_unknown_missing_duplicate_metric_and_schema_fail(self):
        candidates = []
        for key in report():
            candidate = report()
            del candidate[key]
            candidates.append(candidate)
        for metrics in [[], ["lines", "lines"], ["statements"], "lines", [True]]:
            candidate = report()
            candidate["metrics"] = metrics
            candidates.append(candidate)
        candidate = report()
        candidate["extra"] = 1
        candidates.append(candidate)
        candidate = report()
        del candidate["files"]["src/a.rs"]["branches"]
        candidates.append(candidate)
        candidate = report()
        candidate["version"] = True
        candidates.append(candidate)
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(InvalidReport):
                run(report(), candidate)

    def test_tools_platform_policy_and_metric_sets_must_match(self):
        for key in report()["tool"]:
            head = report()
            head["tool"][key] += "-changed"
            with self.subTest(key=key), self.assertRaises(InvalidReport):
                run(report(), head)
        head = report()
        head["metrics"].remove("branches")
        del head["files"]["src/a.rs"]["branches"]
        with self.assertRaises(InvalidReport):
            run(report(), head)

    def test_inventory_paths_are_explicit_and_canonical(self):
        for names in [["src/a.rs", "src/a.rs"], ["../a"], ["/a"], ["a//b"],
                      ["a/./b"], ["a\\b"], ["C:a"], ["."], ["a\n"], ["é"], [True], "a"]:
            with self.subTest(names=names), self.assertRaises(InvalidReport):
                inventory(names)

    def test_zero_denominator_and_exact_large_integer_ratios(self):
        empty = {"covered": 0, "total": 0}
        self.assertTrue(nondecreasing(empty, empty))
        self.assertTrue(nondecreasing(empty, {"covered": 10, "total": 10}))
        self.assertFalse(nondecreasing(empty, {"covered": 9, "total": 10}))
        self.assertTrue(nondecreasing({"covered": 9, "total": 10}, empty))
        large = 2**63 - 1
        self.assertFalse(nondecreasing({"covered": large - 1, "total": large},
                                      {"covered": large - 2, "total": large}))

    def test_generated_ratios_match_standard_library_rationals(self):
        for base_total in range(1, 8):
            for head_total in range(1, 8):
                for old in range(base_total + 1):
                    for new in range(head_total + 1):
                        self.assertEqual(nondecreasing({"covered": old, "total": base_total},
                                                       {"covered": new, "total": head_total}),
                                         Fraction(new, head_total) >= Fraction(old, base_total))

    def test_json_duplicate_nonfinite_malformed_and_encoding_rejected(self):
        invalid = [b'{"x":1,"x":2}', b'{"x":{"a":1,"\\u0061":2}}',
                   b'{"x":NaN}', b'{"x":Infinity}', b'{}{}', b'\xff', b'\xef\xbb\xbf{}',
                   b'{"x":-0}', b'{"x":-1}', b'{"x":100000000000000000000}']
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "report.json"
            for raw in invalid:
                source.write_bytes(raw)
                with self.subTest(raw=raw), self.assertRaises(InvalidReport):
                    load(source)

    def test_bounded_input_loading(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "report.json"
            source.write_bytes(b"{} ")
            with patch("coverage_compare.MAX_REPORT_BYTES", 3):
                self.assertEqual(load(source), {})
            with patch("coverage_compare.MAX_REPORT_BYTES", 2):
                with self.assertRaisesRegex(InvalidReport, "size"):
                    load(source)

    def test_empty_inventory_does_not_hide_nonempty_report(self):
        with self.assertRaises(InvalidReport):
            run(report(), report(), old=[], new=[])
        empty = report()
        empty["files"] = {}
        self.assertEqual(run(empty, empty, old=[], new=[])["regressions"], [])

    def test_cli_success_regression_and_invalid_input_exit_status(self):
        script = Path(__file__).with_name("coverage_compare.py")
        with tempfile.TemporaryDirectory() as temporary:
            paths = [Path(temporary) / name for name in ["base", "head", "old", "new"]]
            values = [report(), report(), ["src/a.rs"], ["src/a.rs"]]
            for path, value in zip(paths, values):
                path.write_text(json.dumps(value))

            def execute():
                return subprocess.run([sys.executable, str(script), *(str(path) for path in paths)],
                                      capture_output=True, text=True, timeout=10, check=False)

            result = execute()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["regressions"], [])
            paths[1].write_text(json.dumps(report(7)))
            result = execute()
            self.assertEqual(result.returncode, 1)
            self.assertEqual(len(json.loads(result.stdout)["regressions"]), 6)
            paths[1].write_text('{"version":1,"version":1}')
            result = execute()
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertIn("duplicate", result.stderr)


if __name__ == "__main__":
    unittest.main()
