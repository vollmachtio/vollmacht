"""Preflight failure controls, requiring only Python 3.11+ and Unix."""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import dev


class ToolTests(unittest.TestCase):
    def run_python(self, code, timeout=2):
        return dev.run_bounded([sys.executable, "-c", code], dev.ROOT, timeout)

    def test_output_and_empty_environment(self):
        with patch.dict(os.environ, {"VOLLMACHT_SENTINEL": "do_not_inherit"}):
            value = json.loads(self.run_python(
                "import os,json; print(json.dumps(os.environ.get('VOLLMACHT_SENTINEL')))"))
        self.assertIsNone(value)

    def test_stdin_is_eof(self):
        self.assertEqual(self.run_python("import sys; print(len(sys.stdin.read()))"), b"0\n")

    def test_nonzero_does_not_reflect_output(self):
        with self.assertRaisesRegex(dev.Failure, "^tool_failed$"):
            self.run_python("import sys; print('private'); sys.exit(1)")

    def test_timeout(self):
        with self.assertRaisesRegex(dev.Failure, "^tool_timeout$"):
            self.run_python("import time; time.sleep(10)", timeout=0.1)

    def test_timeout_after_output_eof(self):
        with self.assertRaisesRegex(dev.Failure, "^tool_timeout$"):
            self.run_python("import os,time; os.close(1); os.close(2); time.sleep(10)", timeout=0.1)

    def test_both_output_caps(self):
        for fd in (1, 2):
            with self.subTest(fd=fd), self.assertRaisesRegex(dev.Failure, "^tool_output_limit$"):
                self.run_python(f"import os; os.write({fd}, b'x'*70000)")

    def test_exited_leader_cannot_leave_a_same_group_descendant(self):
        with tempfile.TemporaryDirectory(prefix="vollmacht-descendant-test-") as directory:
            pid_path = Path(directory) / "pid"
            code = (
                "import subprocess,sys,pathlib; "
                "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'],"
                "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
                f"pathlib.Path({str(pid_path)!r}).write_text(str(p.pid)); sys.exit(1)"
            )
            with self.assertRaisesRegex(dev.Failure, "^tool_failed$"):
                self.run_python(code)
            pid = int(pid_path.read_text())

            def running():
                try:
                    os.kill(pid, 0)
                    # Linux container init may retain an orphan zombie after SIGKILL.
                    status = Path(f"/proc/{pid}/stat")
                    if status.exists() and status.read_text().rsplit(")", 1)[1].split()[0] == "Z":
                        return False
                    return True
                except (ProcessLookupError, FileNotFoundError):
                    return False

            deadline = time.monotonic() + 1
            while running() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertFalse(running(), "descendant survived failed tool cleanup")

    def test_launch_error(self):
        with self.assertRaisesRegex(dev.Failure, "^tool_launch_failed$"):
            dev.run_bounded(["/nonexistent-vollmacht-test-runtime"], dev.ROOT)

    def test_darwin_census_requires_only_zombies_in_target_group(self):
        for body, expected in [(b"12 Z\n12 Z+\n13 S\n", True),
                               (b"12 Z\n12 S\n", False), (b"13 Z\n", False)]:
            with patch.object(dev, "run_bounded", return_value=body):
                self.assertEqual(dev.darwin_group_exited(12, dev.ROOT), expected)

    def test_darwin_census_rejects_malformed_or_unavailable_snapshot(self):
        with patch.object(dev, "run_bounded", return_value=b"not a process row"):
            with self.assertRaises(dev.Failure):
                dev.darwin_group_exited(12, dev.ROOT)
        with patch.object(dev, "run_bounded", side_effect=dev.Failure("tool_output_limit")):
            with self.assertRaises(dev.Failure):
                dev.darwin_group_exited(12, dev.ROOT)

    def test_real_cleanup_denial_does_not_report_success(self):
        with patch.object(dev.os, "killpg", side_effect=PermissionError), \
                patch.object(dev, "darwin_group_exited", return_value=False):
            with self.assertRaisesRegex(dev.Failure, "^tool_cleanup_failed$"):
                self.run_python("print('ok')")

    def test_path_validation(self):
        for path, error in [("node", "absolute_path_required"),
                            ("/nonexistent-vollmacht-test-runtime", "missing_or_not_executable"),
                            (str(dev.ROOT), "missing_or_not_executable")]:
            with self.subTest(path=path), self.assertRaisesRegex(dev.Failure, error):
                dev.executable(path, "node")
        self.assertEqual(dev.executable(sys.executable, "node"), Path(sys.executable).resolve())


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="vollmacht-dev-test-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        (self.directory / ".node-version").write_text("26.5.1\n")
        self.package_dir = self.directory / "node_modules" / "example"
        self.package_dir.mkdir(parents=True)
        self.package = {"name": "example", "version": "1.0.0", "license": "MIT", "integrity": "test"}
        self.save_package()
        (self.directory / "package-lock.json").write_text(json.dumps(
            {"packages": {"": {}, "node_modules/example": self.package}}))

    def save_package(self):
        (self.package_dir / "package.json").write_text(json.dumps(self.package))

    def assess(self):
        return dev.assess("doctor", sys.executable, sys.executable, sys.executable, self.directory)

    def test_inventory_reports_metadata_not_integrity(self):
        report = dev.inventory(self.directory)
        self.assertEqual(report["count"], 1)
        self.assertGreater(report["regular_file_bytes"], 0)
        self.assertFalse(report["content_integrity_verified"])

    def test_missing_dependency(self):
        (self.package_dir / "package.json").unlink()
        with self.assertRaisesRegex(dev.Failure, "dependencies_missing_run_npm_ci"):
            dev.inventory(self.directory)

    def test_mismatched_dependency(self):
        self.package["version"] = "2.0.0"
        self.save_package()
        with self.assertRaisesRegex(dev.Failure, "dependency_version_mismatch"):
            dev.inventory(self.directory)

    def test_path_escape(self):
        (self.directory / "package-lock.json").write_text(json.dumps(
            {"packages": {"node_modules/../example": self.package}}))
        with self.assertRaisesRegex(dev.Failure, "dependency_path_invalid"):
            dev.inventory(self.directory)

    def test_wrong_runtime_stops_before_dependency_import(self):
        with patch.object(dev, "run_bounded", return_value=b'{"version":"99.0.0"}') as run:
            with self.assertRaisesRegex(dev.Failure, "node_version_mismatch"):
                self.assess()
            self.assertEqual(run.call_count, 1)

    def test_missing_helper(self):
        with patch.object(dev, "run_bounded", return_value=b'{"version":"26.5.1"}'):
            with self.assertRaisesRegex(dev.Failure, "helper_files_missing"):
                self.assess()

    def test_bad_cli_and_fixed_error_output(self):
        with contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(dev.main([]), 2)
            self.assertEqual(dev.main(["doctor", "/secret/missing", sys.executable, sys.executable]), 1)
        self.assertNotIn("/secret", output.getvalue())
        self.assertIn("node_missing_or_not_executable", output.getvalue())


if __name__ == "__main__":
    unittest.main()
