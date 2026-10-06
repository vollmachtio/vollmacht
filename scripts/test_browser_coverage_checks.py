"""Negative controls for VM attribution checks; no Node process is needed."""

from pathlib import Path
import unittest

from test_browser_coverage import validate_attribution


SOURCE = Path(__file__).resolve().parent.parent / "spikes/webauthn/web/app.js"


def record(url, count=1, start=0, end=10):
    return {
        "url": url,
        "functions": [{"ranges": [{
            "count": count, "startOffset": start, "endOffset": end,
        }]}],
    }


class AttributionTests(unittest.TestCase):
    def test_absolute_source_path_and_file_uri_are_accepted(self):
        for name in [str(SOURCE), SOURCE.as_uri()]:
            with self.subTest(name=name):
                validate_attribution([record(name)], SOURCE)

    def test_missing_source_and_unrelated_execution_are_rejected(self):
        for records in [[], [record("file:///unrelated.js")]]:
            with self.subTest(records=records):
                with self.assertRaisesRegex(ValueError, "missing"):
                    validate_attribution(records, SOURCE)

    def test_anonymous_vm_is_rejected_even_with_attributed_execution(self):
        for records in [
            [record("evalmachine.<anonymous>")],
            [record(str(SOURCE)), record("evalmachine.<anonymous>")],
        ]:
            with self.subTest(records=records):
                with self.assertRaisesRegex(ValueError, "Anonymous"):
                    validate_attribution(records, SOURCE)

    def test_unexecuted_source_cannot_borrow_unrelated_execution(self):
        records = [record(str(SOURCE), count=0), record("file:///unrelated.js")]
        with self.assertRaisesRegex(ValueError, "no executed"):
            validate_attribution(records, SOURCE)

    def test_empty_reversed_or_zero_count_ranges_are_rejected(self):
        for candidate in [
            record(str(SOURCE), count=0),
            record(str(SOURCE), end=0),
            record(str(SOURCE), start=10, end=0),
            {"url": str(SOURCE), "functions": []},
            {"url": str(SOURCE), "functions": [{"ranges": []}]},
        ]:
            with self.subTest(candidate=candidate):
                with self.assertRaisesRegex(ValueError, "no executed"):
                    validate_attribution([candidate], SOURCE)

    def test_different_basename_match_is_not_the_shipped_source(self):
        with self.assertRaisesRegex(ValueError, "missing"):
            validate_attribution([record("file:///different/app.js")], SOURCE)

    def test_multiple_records_may_include_executed_source(self):
        validate_attribution([
            record(str(SOURCE), count=0), record(str(SOURCE)),
            record("file:///unrelated.js"),
        ], SOURCE)


if __name__ == "__main__":
    unittest.main()
