"""Mocked demo-runner controls: no compiler, network or native operation runs."""
import contextlib
import io
import os
from pathlib import Path
import subprocess
import signal
import unittest
from unittest.mock import patch, Mock, call

import demo


EVENTS = (
    "proposal", "synthetic_approval", "issued", "claimed",
    "verified_candidate", "replay_denied", "negatives_passed",
)
PIN = "v" + (demo.ROOT / "spikes/simplewebauthn/.node-version").read_text().strip()


def transcript(events=EVENTS):
    return "compiler noise\n" + "".join(f"VOLLMACHT_DEMO:{event}\n" for event in events)


def completed(output="", code=0):
    return subprocess.CompletedProcess([], code, stdout=output, stderr="diagnostic-secret")


class DemoTests(unittest.TestCase):
    def invoke(self, outcomes, missing=None):
        output = io.StringIO()
        def runtime(name):
            return None if name == missing else f"/fixture/bin/{name}"
        with patch.object(demo.shutil, "which", side_effect=runtime), \
                patch.object(demo.subprocess, "run", side_effect=outcomes[:1]) as run, \
                patch.object(demo, "run_flow", side_effect=outcomes[1:]) as flow, \
                contextlib.redirect_stdout(output):
            status = demo.main()
        return status, output.getvalue(), run.call_args_list + flow.call_args_list

    def assert_denied(self, status, output):
        self.assertNotEqual(status, 0)
        self.assertNotIn("Simulation passed", output)
        self.assertNotIn("1. Proposed:", output)
        self.assertNotIn("diagnostic-secret", output)

    def test_missing_runtime_never_starts_a_process(self):
        for name in ("node", "cargo"):
            with self.subTest(name=name):
                status, output, calls = self.invoke([], missing=name)
                self.assert_denied(status, output)
                self.assertEqual(calls, [])

    def test_wrong_or_failed_version_never_starts_the_flow(self):
        for result in (completed("v0.0.0\n"), completed(PIN, code=1)):
            with self.subTest(result=result):
                status, output, calls = self.invoke([result])
                self.assert_denied(status, output)
                self.assertEqual(len(calls), 1)

    def test_child_failure_cannot_be_hidden_by_a_complete_transcript(self):
        status, output, calls = self.invoke([completed(PIN), completed(transcript(), code=1)])
        self.assert_denied(status, output)
        self.assertEqual(len(calls), 2)

    def test_timeout_and_process_errors_are_bounded_failures(self):
        for error in (OSError("diagnostic-secret"), subprocess.TimeoutExpired("cargo", 300)):
            for version_failure in (True, False):
                with self.subTest(error=error, version_failure=version_failure):
                    results = [error] if version_failure else [completed(PIN), error]
                    status, output, _ = self.invoke(results)
                    self.assert_denied(status, output)

    def test_missing_reordered_duplicate_and_unknown_markers_fail(self):
        wrong = [
            (), EVENTS[:-1], EVENTS[1:], tuple(reversed(EVENTS)),
            EVENTS + (EVENTS[-1],), EVENTS[:3] + (EVENTS[2],) + EVENTS[3:],
            EVENTS + ("unknown",),
        ]
        for events in wrong:
            with self.subTest(events=events):
                status, output, _ = self.invoke([completed(PIN), completed(transcript(events))])
                self.assert_denied(status, output)
        for raw in (transcript().replace("VOLLMACHT_DEMO:", " VOLLMACHT_DEMO:"),
                    transcript().replace("proposal\n", "proposal \n")):
            status, output, _ = self.invoke([completed(PIN), completed(raw)])
            self.assert_denied(status, output)

    def test_valid_transcript_runs_only_locked_exact_synthetic_test(self):
        with patch.dict(os.environ, {"DEMO_TEST_SENTINEL": "retained"}):
            status, output, calls = self.invoke([completed(PIN + "\n"), completed(transcript())])
        self.assertEqual(status, 0)
        self.assertIn("Simulation passed", output)
        self.assertIn("no Touch ID, no GitHub writes", output)
        self.assertIn("NOT sent", output)
        self.assertIn("not dispatch authority", output)
        self.assertNotIn("diagnostic-secret", output)
        self.assertEqual(len([line for line in output.splitlines() if line[:1].isdigit()]), 7)
        prefix = chr(45) * 2
        self.assertEqual(calls[0].args[0], ["/fixture/bin/node", prefix + "version"])
        self.assertEqual(calls[0].kwargs["timeout"], 10)
        self.assertEqual(calls[1].args[0], [
            "/fixture/bin/cargo", "test", "-p", "vollmacht-helper-launcher", prefix + "locked",
            prefix + "test", "fresh_simulated_merge",
            "fresh_synthetic_approval_issuance_and_execution_record_one_candidate",
            prefix, prefix + "exact", prefix + "nocapture",
        ])
        environment = calls[1].args[1]
        self.assertEqual(environment["VOLLMACHT_TEST_NODE"], str(Path("/fixture/bin/node").resolve()))
        self.assertEqual(environment["VOLLMACHT_DEMO_TRACE"], "1")
        self.assertEqual(environment["DEMO_TEST_SENTINEL"], "retained")
        self.assertNotIn(prefix + "ignored", calls[1].args[0])

    def test_cancellation_reports_no_success(self):
        status, output, _ = self.invoke([completed(PIN), KeyboardInterrupt()])
        self.assert_denied(status, output)
        self.assertEqual(status, 130)

    def test_flow_process_uses_owned_session_and_no_interactive_input(self):
        process = Mock(returncode=0)
        process.communicate.return_value = (transcript(), "")
        with patch.object(demo.subprocess, "Popen", return_value=process) as popen:
            result = demo.run_flow(["cargo", "test"], {"ONLY": "test"})
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, transcript())
        popen.assert_called_once_with(
            ["cargo", "test"], cwd=demo.ROOT, env={"ONLY": "test"},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True,
        )
        process.communicate.assert_called_once_with(timeout=300)

    def test_timeout_or_interrupt_kills_owned_group_and_reaps_before_reraising(self):
        for error in (subprocess.TimeoutExpired("cargo", 300), KeyboardInterrupt()):
            with self.subTest(error=error):
                process = Mock(pid=12345)
                process.communicate.side_effect = [error, ("", "")]
                with patch.object(demo.subprocess, "Popen", return_value=process), \
                        patch.object(demo.os, "killpg") as kill:
                    with self.assertRaises(type(error)):
                        demo.run_flow(["cargo"], {})
                kill.assert_called_once_with(12345, signal.SIGKILL)
                self.assertEqual(process.communicate.call_args_list, [call(timeout=300), call(timeout=5)])

    def test_stuck_pipes_cleanup_stays_bounded_even_after_group_is_gone(self):
        process = Mock(pid=12345)
        process.communicate.side_effect = subprocess.TimeoutExpired("cargo", 300)
        process.wait.side_effect = subprocess.TimeoutExpired("cargo", 5)
        with patch.object(demo.subprocess, "Popen", return_value=process), \
                patch.object(demo.os, "killpg", side_effect=ProcessLookupError):
            with self.assertRaises(subprocess.TimeoutExpired):
                demo.run_flow(["cargo"], {})
        process.stdout.close.assert_called_once()
        process.stderr.close.assert_called_once()
        process.wait.assert_called_once_with(timeout=5)
        self.assertEqual(process.communicate.call_args_list, [call(timeout=300), call(timeout=5)])


if __name__ == "__main__":
    unittest.main()
