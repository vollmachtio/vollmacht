"""Mocked demo-runner controls: no compiler, network or native operation runs."""
import contextlib
import io
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import signal
import unittest
from unittest.mock import patch, Mock, call

import demo


EVENTS = (
    "proposal", "synthetic_approval", "issued", "claimed",
    "verified_candidate", "resource_checked", "replay_denied", "negatives_passed",
)
PIN = "v" + (demo.ROOT / "spikes/simplewebauthn/.node-version").read_text().strip()


def proposal():
    fixture = json.loads((demo.ROOT / "spikes/canonicalization/fixtures/candidate-profile-vector.json").read_text())
    return {"payload": fixture["approval"], "fingerprint": "cPADub8ZYk9k4lytHWn0RCCKrzTZhTnW0oAeVlhGmjg"}


def fingerprint(payload):
    # This fixture subset has only ASCII strings and safe positive integers,
    # for which standard sorted compact JSON supplies independent JCS bytes.
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(b"vollmacht:mandate:v1\0" + canonical).digest()).rstrip(b"=").decode()


def transcript(events=EVENTS, record=None):
    record = proposal() if record is None else record
    lines = ["compiler noise"]
    for event in events:
        if event == "proposal":
            lines.append("VOLLMACHT_PROPOSAL:" + json.dumps(record, separators=(",", ":")))
        lines.append(f"VOLLMACHT_DEMO:{event}")
    return "\n".join(lines) + "\n"


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

    def test_proposal_fingerprint_matches_independent_fixed_oracle(self):
        record = proposal()
        self.assertEqual(fingerprint(record["payload"]), record["fingerprint"])

    def test_missing_duplicate_or_ambiguous_proposal_record_fails(self):
        valid = transcript()
        line = next(line for line in valid.splitlines() if line.startswith("VOLLMACHT_PROPOSAL:"))
        ambiguous = line.replace('"fingerprint":', '"fingerprint":"wrong","fingerprint":', 1)
        escaped_duplicate = line.replace('"fingerprint":', '"\\u0066ingerprint":"wrong","fingerprint":', 1)
        payload_duplicate = line.replace('"version":1', '"version":1,"version":1', 1)
        for raw in (
            valid.replace(line + "\n", ""), valid + line + "\n",
            valid.replace(line, ambiguous), valid.replace(line, escaped_duplicate),
            valid.replace(line, payload_duplicate), valid.replace(line, "VOLLMACHT_PROPOSAL:{"),
            valid.replace(line + "\n", "").replace("VOLLMACHT_DEMO:synthetic_approval\n", "VOLLMACHT_DEMO:synthetic_approval\n" + line + "\n"),
        ):
            with self.subTest(raw=raw[-80:]):
                status, output, _ = self.invoke([completed(PIN), completed(raw)])
                self.assert_denied(status, output)

    def test_malformed_fields_and_control_text_do_not_render(self):
        original = proposal()
        bad = []
        for name in original["payload"]:
            record = copy.deepcopy(original)
            del record["payload"][name]
            bad.append(record)
        for path in (("operation",), ("operation", "resource"), ("operation", "constraints"), ("display",)):
            original_object = original["payload"]
            for part in path:
                original_object = original_object[part]
            for name in original_object:
                record = copy.deepcopy(original)
                target = record["payload"]
                for part in path:
                    target = target[part]
                del target[name]
                bad.append(record)
            record = copy.deepcopy(original)
            target = record["payload"]
            for part in path:
                target = target[part]
            target["extra"] = 1
            bad.append(record)
        for replacement in (None, [], "payload", True):
            bad.append({"payload": replacement, "fingerprint": original["fingerprint"]})
        for field, value in (("version", True), ("issued_at", 1.0), ("expires_at", -1), ("crypto_profile", "unknown")):
            record = copy.deepcopy(original)
            record["payload"][field] = value
            record["fingerprint"] = fingerprint(record["payload"])
            bad.append(record)
        for text in ("owner/\u001b[31mred", "owner/\nspoof", "owner/\rspoof", "owner/\tspoof", "owner/\u007f", "owner/é", "x" * 9000):
            record = copy.deepcopy(original)
            record["payload"]["display"]["repository"] = text
            record["fingerprint"] = fingerprint(record["payload"])
            bad.append(record)
        record = copy.deepcopy(original)
        record["payload"]["extra"] = "field"
        bad.append(record)
        bad.append({**original, "extra": 1})
        for value in (None, 7, "A" * 43, original["fingerprint"] + "=", "\u001b[31m"):
            bad.append({**original, "fingerprint": value})
        for record in bad:
            with self.subTest(record=record):
                status, output, _ = self.invoke([completed(PIN), completed(transcript(record=record))])
                self.assert_denied(status, output)
                self.assertNotIn("\u001b", output)

    def test_mutating_proposal_without_updating_fingerprint_fails(self):
        for path, value in (
            (("operation", "constraints", "expected_head_sha"), "b" * 40),
            (("operation", "resource", "repository_id"), "98765"),
            (("expires_at",), 1800000119),
            (("agent_jkt",), "A" * 43),
        ):
            record = proposal()
            target = record["payload"]
            for name in path[:-1]:
                target = target[name]
            target[path[-1]] = value
            status, output, _ = self.invoke([completed(PIN), completed(transcript(record=record))])
            self.assert_denied(status, output)

    def test_display_uses_actual_payload_not_canned_fixture_values(self):
        record = proposal()
        payload = record["payload"]
        payload["display"]["repository"] = "review/changed"
        payload["operation"]["resource"].update(repository_id="987654", pull_request_number=73)
        payload["operation"]["constraints"].update(base_ref="release/review", expected_head_sha="b" * 40, merge_method="rebase")
        payload["expires_at"] = payload["issued_at"] + 60
        record["fingerprint"] = fingerprint(payload)
        status, output, _ = self.invoke([completed(PIN), completed(transcript(record=record))])
        self.assertEqual(status, 0)
        for value in ("review/changed", "987654", "73", "release/review", "b" * 40, "rebase", record["fingerprint"]):
            self.assertIn(value, output)
        self.assertNotIn("squash PR 42", output)

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
        self.assertEqual(len([line for line in output.splitlines() if line[:1].isdigit()]), 8)
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
