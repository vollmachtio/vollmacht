"""Portable negative controls; never modifies the Git index."""

import copy
import unittest
from unittest.mock import patch

import coverage_inventory as subject
from coverage_compare import InvalidReport


def document():
    return {"version": 1, "sources": [
        {"path": "src/a.rs", "role": "experiment", "measurement": "unmeasured"},
        {"path": "tests/support/a.py", "role": "test_support", "measurement": "unmeasured"},
    ]}


TRACKED = {"src/a.rs", "tests/support/a.py"}


class InventoryTests(unittest.TestCase):
    def test_complete_inventory_accounts_for_test_support(self):
        result = subject.validate(document(), TRACKED)
        self.assertEqual(result["sources"], 2)
        self.assertEqual(result["roles"]["test_support"], 1)
        self.assertEqual(result["measurements"]["unmeasured"], 2)

    def test_addition_removal_and_rename_require_review(self):
        for tracked in [TRACKED | {"new.js"}, {"src/a.rs"}, {"src/renamed.rs", "tests/support/a.py"}]:
            with self.subTest(tracked=tracked), self.assertRaisesRegex(InvalidReport, "requires review"):
                subject.validate(document(), tracked)

    def test_duplicates_do_not_replace_classification(self):
        value = document()
        value["sources"].append(copy.deepcopy(value["sources"][0]))
        with self.assertRaisesRegex(InvalidReport, "duplicate"):
            subject.validate(value, TRACKED)

    def test_missing_extra_fields_and_wrong_types_reject(self):
        candidates = [{}, [], {"version": True, "sources": []},
                      {"version": 2, "sources": []}, {"version": 1, "sources": {}},
                      {"version": 1, "sources": [], "extra": True}]
        for key in ["path", "role", "measurement"]:
            value = document()
            del value["sources"][0][key]
            candidates.append(value)
        value = document()
        value["sources"][0]["exclude"] = True
        candidates.append(value)
        for value in candidates:
            with self.subTest(value=value), self.assertRaises(InvalidReport):
                subject.validate(value, TRACKED)

    def test_unknown_roles_statuses_paths_and_extensions_reject(self):
        for key, replacements in {
            "role": ["production", "skip", "", None, []],
            "measurement": ["covered", "excluded", "", True, {}],
            "path": ["../a.rs", "/a.rs", "a//b.rs", "a\\b.rs", "a.txt", "é.rs", None],
        }.items():
            for replacement in replacements:
                value = document()
                value["sources"][0][key] = replacement
                with self.subTest(key=key, replacement=replacement), self.assertRaises(InvalidReport):
                    subject.validate(value, TRACKED)

    def test_git_nul_paths_cover_all_extensions_without_test_exclusions(self):
        paths = ["a" + suffix for suffix in sorted(subject.SUFFIXES)] + ["tests/support/x.rs"]
        raw = "\0".join(paths + ["README.md", "a space.py"]).encode() + b"\0"
        self.assertEqual(subject.tracked_sources(raw), set(paths + ["a space.py"]))
        self.assertEqual(subject.tracked_sources(b""), set())

    def test_malformed_git_output_rejects(self):
        for raw in [b"a.rs", b"a.rs\0a.rs\0", b"\0", b"a.rs\0\0", b"\xff.rs\0",
                    b"../a.rs\0", "a.rs\0"]:
            with self.subTest(raw=raw), self.assertRaises(InvalidReport):
                subject.tracked_sources(raw)

    def test_cli_git_query_has_fixed_root_and_no_inherited_git_override(self):
        with patch.object(subject.sys, "argv", ["coverage_inventory.py"]), \
                patch.object(subject.subprocess, "run") as execute, \
                patch.object(subject, "load", return_value=document()), \
                patch("builtins.print"):
            execute.return_value.stdout = b"src/a.rs\0tests/support/a.py\0"
            subject.main()
        call = execute.call_args
        self.assertEqual(call.args[0][:2], ["git", "-C"])
        self.assertEqual(call.args[0][-2:], ["ls-files", "-z"])
        self.assertEqual(call.kwargs["env"], {"PATH": subject.os.defpath})
        self.assertTrue(call.kwargs["check"])
        self.assertEqual(call.kwargs["timeout"], 15)

    def test_cli_arguments_reject_before_git_query(self):
        with patch.object(subject.sys, "argv", ["coverage_inventory.py", "other-root"]), \
                patch.object(subject.subprocess, "run") as execute:
            with self.assertRaises(SystemExit):
                subject.main()
            execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
