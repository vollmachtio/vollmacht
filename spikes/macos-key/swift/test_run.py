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


if __name__ == "__main__":
    unittest.main()
