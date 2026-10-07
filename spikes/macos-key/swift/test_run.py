"""Portable runner controls; no Swift compiler or Apple APIs invoked."""

from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import run


class RunnerTests(unittest.TestCase):
    def test_success(self):
        run.run([sys.executable, "-c", "pass"], timeout=5)

    def test_nonzero_fails(self):
        with self.assertRaises(subprocess.CalledProcessError):
            run.run([sys.executable, "-c", "raise SystemExit(3)"], timeout=5)

    def test_timeout_fails(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            run.run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.1)

    def test_wrong_platform_never_spawns(self):
        with patch.object(sys, "platform", "linux"), patch.object(run, "run") as execute:
            with self.assertRaises(SystemExit):
                run.main()
            execute.assert_not_called()

    def test_extra_arguments_never_spawn(self):
        with patch.object(sys, "platform", "darwin"), patch.object(sys, "argv", ["run.py", "extra"]), patch.object(run, "run") as execute:
            with self.assertRaises(SystemExit):
                run.main()
            execute.assert_not_called()

    def test_temp_cleanup_after_compile_failure(self):
        observed = []

        def fail(command, timeout):
            observed.append(Path(command[-1]).parent)
            self.assertTrue(observed[0].is_dir())
            self.assertEqual(command[0], "/usr/bin/swiftc")
            self.assertEqual(timeout, 180)
            raise subprocess.CalledProcessError(1, command)

        with patch.object(sys, "platform", "darwin"), patch.object(sys, "argv", ["run.py"]), patch.object(run, "run", side_effect=fail):
            with self.assertRaises(subprocess.CalledProcessError):
                run.main()
        self.assertEqual(len(observed), 1)
        self.assertFalse(observed[0].exists())

    def test_only_fake_binaries_execute_and_ui_is_typechecked(self):
        with patch.object(sys, "platform", "darwin"), patch.object(sys, "argv", ["run.py"]), patch.object(run, "run") as execute:
            run.main()
        calls = execute.call_args_list
        self.assertEqual(len(calls), 11)
        for index in (0, 2, 4, 6, 8, 10):
            self.assertEqual(calls[index].args[0][0], "/usr/bin/swiftc")
            self.assertEqual(calls[index].kwargs["timeout"], 180)
        for index, name in ((1, "profile-tests"), (3, "runtime-tests"),
                            (5, "diagnostic-plan-tests"), (7, "diagnostic-session-tests"),
                            (9, "delayed-diagnostic-controller-tests")):
            self.assertEqual(len(calls[index].args[0]), 1)
            self.assertEqual(Path(calls[index].args[0][0]).name, name)
            self.assertEqual(calls[index].kwargs["timeout"], 15)
        diagnostic_sources = [Path(arg).name for arg in calls[4].args[0] if arg.endswith(".swift")]
        self.assertEqual(diagnostic_sources, ["DiagnosticPlan.swift", "DiagnosticPlanTests.swift"])
        session_sources = [Path(arg).name for arg in calls[6].args[0] if arg.endswith(".swift")]
        self.assertEqual(session_sources, ["Profile.swift", "Runtime.swift", "DiagnosticPlan.swift",
                                          "DiagnosticSession.swift", "DiagnosticSessionTests.swift"])
        controller_sources = [Path(arg).name for arg in calls[8].args[0] if arg.endswith(".swift")]
        self.assertEqual(controller_sources, ["Profile.swift", "Runtime.swift", "DiagnosticPlan.swift", "DiagnosticSession.swift",
                                             "DelayedDiagnosticController.swift", "DelayedDiagnosticControllerTests.swift"])
        self.assertIn("-strict-concurrency=complete", calls[8].args[0])
        self.assertEqual(calls[8].args[0][calls[8].args[0].index("-swift-version") + 1], "6")
        self.assertIn("-typecheck", calls[10].args[0])
        self.assertEqual(Path(calls[10].args[0][-1]).name, "ProbeView.swift")


if __name__ == "__main__":
    unittest.main()
