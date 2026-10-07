"""Portable coverage-runner tests: all compiler and Apple tool calls are mocked."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import coverage_swift as runner


SOURCE = Path(runner.__file__).resolve().parent.parent / "spikes/macos-key/swift"
EXPECTED_SUITES = [
    ["Profile.swift", "Tests.swift"],
    ["Profile.swift", "Runtime.swift", "RuntimeTests.swift"],
    ["DiagnosticPlan.swift", "DiagnosticPlanTests.swift"],
    ["Profile.swift", "Runtime.swift", "DiagnosticPlan.swift", "DiagnosticSession.swift", "DiagnosticSessionTests.swift"],
    ["Profile.swift", "Runtime.swift", "DiagnosticPlan.swift", "DiagnosticSession.swift",
     "DelayedDiagnosticController.swift", "DelayedDiagnosticControllerTests.swift"],
    ["ProbeOperationState.swift", "ProbeOperationStateTests.swift"],
    ["Profile.swift", "Runtime.swift", "DiagnosticPlan.swift", "DiagnosticSession.swift",
     "DelayedDiagnosticController.swift", "ProbeOperationState.swift", "ProbeEventAdapter.swift", "ProbeEventAdapterTests.swift"],
]
EXPECTED_BINARIES = ["profile-tests", "runtime-tests", "diagnostic-plan-tests", "diagnostic-session-tests",
                     "delayed-diagnostic-controller-tests", "probe-operation-state-tests", "probe-event-adapter-tests"]
EXPECTED_SUITE_FLAGS = [[], [], [], [], ["-swift-version", "6", "-strict-concurrency=complete"],
                        ["-swift-version", "6", "-strict-concurrency=complete"],
                        ["-swift-version", "6", "-strict-concurrency=complete"]]
EXPECTED_SOURCES = sorted({name for inputs in EXPECTED_SUITES for name in inputs})


def report():
    return {
        "type": "llvm.coverage.json.export",
        "data": [{
            "files": [{"filename": str(SOURCE / name)} for name in EXPECTED_SOURCES],
            "functions": [{"name": "$sNativeKeyBackend.reserve", "count": 0}],
        }],
    }


class CoverageTests(unittest.TestCase):
    def test_report_requires_expected_files_and_zero_native_execution(self):
        runner.validate_report(report(), SOURCE)
        for mutation in ("format", "source", "duplicate", "extra", "units", "native", "executed", "boolean"):
            with self.subTest(mutation=mutation):
                value = report()
                if mutation == "format":
                    value["type"] = "other"
                elif mutation == "source":
                    value["data"][0]["files"].pop()
                elif mutation == "native":
                    value["data"][0]["functions"] = []
                elif mutation == "duplicate":
                    value["data"][0]["files"].append(value["data"][0]["files"][0].copy())
                elif mutation == "extra":
                    value["data"][0]["files"].append({"filename": str(SOURCE / "ProbeView.swift")})
                elif mutation == "units":
                    value["data"].append(value["data"][0].copy())
                elif mutation == "boolean":
                    value["data"][0]["functions"][0]["count"] = False
                else:
                    value["data"][0]["functions"][0]["count"] = 1
                with self.assertRaises(ValueError):
                    runner.validate_report(value, SOURCE)

    def test_platform_and_existing_destination_rejected_before_commands(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(runner, "execute") as execute:
            destination = Path(temporary) / "output"
            with patch.object(sys, "platform", "linux"):
                with self.assertRaises(ValueError):
                    runner.collect(destination)
            self.assertFalse(destination.exists())
            with patch.object(sys, "platform", "darwin"):
                destination.mkdir()
                with self.assertRaises(FileExistsError):
                    runner.collect(destination)
            execute.assert_not_called()

    def test_arguments(self):
        for arguments in (["runner"], ["runner", "one", "two"]):
            with patch.object(sys, "argv", arguments), patch.object(runner, "collect") as collect:
                with self.assertRaises(ValueError):
                    runner.main()
                collect.assert_not_called()

    def test_execute_timeout_and_failure_propagate(self):
        for error in (subprocess.TimeoutExpired("compiler", 3), subprocess.CalledProcessError(1, "compiler")):
            with patch.object(subprocess, "run", side_effect=error) as run:
                with self.assertRaises(type(error)):
                    runner.execute(["compiler"], timeout=3, env={"X": "Y"})
                run.assert_called_once_with(
                    ["compiler"], check=True, timeout=3, env={"X": "Y"},
                    capture_output=True, text=True,
                )

    def exercise(self, failure=None):
        commands = []
        build_directories = []
        option = chr(45) * 2
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            destination = directory / "report"
            sdk = directory / "sdk"
            sdk.mkdir()
            tool = directory / "tool"
            tool.touch()

            def execute(command, *, timeout=180, env=None):
                commands.append((command, timeout, env))
                if command[:1] == ["/usr/bin/xcrun"]:
                    self.assertEqual(command[1:3], [option + "sdk", "macosx"])
                    query = command[3]
                    if query == option + "show-sdk-path":
                        return str(sdk)
                    if query == option + "show-sdk-version":
                        return "" if failure == "sdk-version" else "26.5"
                    if query == option + "show-sdk-build-version":
                        if failure == "sdk-query":
                            raise subprocess.CalledProcessError(1, command)
                        return "" if failure == "sdk-build" else "25F70"
                    self.assertEqual(query, option + "find")
                    return str(tool)
                if command[-1] == option + "version":
                    return "" if failure == "tool-version" else "fixture tool version\nTarget: arm64-apple-macosx26.0"
                if "-profile-generate" in command:
                    build_directories.append(Path(command[-1]).parent)
                    if failure == "compile":
                        raise subprocess.CalledProcessError(1, command)
                    return ""
                if env is not None:
                    self.assertEqual(timeout, 15)
                    self.assertEqual(len(command), 1)
                    self.assertIn(Path(command[0]).name, EXPECTED_BINARIES)
                    if (failure == "run"
                        or (failure == "session-run" and Path(command[0]).name == "diagnostic-session-tests")
                        or (failure == "controller-run" and Path(command[0]).name == "delayed-diagnostic-controller-tests")
                        or (failure == "operation-run" and Path(command[0]).name == "probe-operation-state-tests")
                        or (failure == "adapter-run" and Path(command[0]).name == "probe-event-adapter-tests")):
                        raise subprocess.TimeoutExpired(command, timeout)
                    if failure != "profile":
                        Path(env["LLVM_PROFILE_FILE"].replace("%p", "123")).write_bytes(b"profile")
                    return ""
                if "export" in command:
                    if failure == "json":
                        return "not json"
                    value = report()
                    if failure == "source":
                        value["data"][0]["files"] = []
                    return json.dumps(value)
                self.assertIn("merge", command)
                return ""

            with patch.object(sys, "platform", "darwin"), patch.object(runner, "execute", side_effect=execute):
                if failure:
                    with self.assertRaises((ValueError, subprocess.SubprocessError)):
                        runner.collect(destination)
                    self.assertFalse((destination / "coverage.json").exists())
                    self.assertFalse((destination / "metadata.json").exists())
                else:
                    runner.collect(destination)
                    self.assertEqual(json.loads((destination / "coverage.json").read_text()), report())
                    metadata = json.loads((destination / "metadata.json").read_text())
                    self.assertEqual(metadata["schema"], 2)
                    self.assertEqual(metadata["sdk"], {"name": "macosx", "path": str(sdk), "version": "26.5", "build": "25F70"})
                    config = metadata["collector_config"]
                    self.assertEqual(config["compile_flags"], ["-warnings-as-errors", "-Onone", "-profile-generate", "-profile-coverage-mapping"])
                    self.assertEqual(metadata["measured_suites"], [inputs[-1] for inputs in EXPECTED_SUITES])
                    self.assertEqual(config["id"], "swift-fake-suites-v6")
                    self.assertEqual(config["suites"], EXPECTED_SUITES)
                    self.assertEqual(config["suite_compile_flags"], EXPECTED_SUITE_FLAGS)
                    self.assertIn("ProbeView.swift", metadata["unmeasured"])
                    self.assertIn("native_keychain", metadata["unmeasured"])
                    compile_calls = [command for command, _, _ in commands if "-profile-generate" in command]
                    self.assertEqual(len(compile_calls), 7)
                    self.assertEqual([Path(command[-1]).name for command in compile_calls], EXPECTED_BINARIES)
                    for command, inputs, flags in zip(compile_calls, EXPECTED_SUITES, EXPECTED_SUITE_FLAGS, strict=True):
                        self.assertIn("-profile-coverage-mapping", command)
                        self.assertNotIn(str(SOURCE / "ProbeView.swift"), command)
                        self.assertEqual(command[1:5], config["compile_flags"])
                        self.assertEqual(command[5:command.index("-sdk")], flags)
                        self.assertEqual(command[command.index("-target") + 1], config["target"])
                        self.assertEqual(command[command.index("-sdk") + 1], metadata["sdk"]["path"])
                        self.assertEqual([Path(value).name for value in command if value.endswith(".swift")], inputs)
                    export = [command for command, _, _ in commands if "export" in command][0]
                    self.assertEqual(Path(export[2]).name, EXPECTED_BINARIES[0])
                    self.assertIn("-object", export)
                    self.assertEqual([Path(export[index + 1]).name for index, argument in enumerate(export)
                                      if argument == "-object"], EXPECTED_BINARIES[1:])
                    executed = [Path(command[0]).name for command, _, env in commands if env is not None]
                    self.assertEqual(executed, EXPECTED_BINARIES)
                    self.assertEqual(config["export"], "single-merged-json")
                    merge = [command for command, _, _ in commands if "merge" in command][0]
                    self.assertEqual([Path(argument).name for argument in merge if argument.endswith(".profraw")],
                                     [name + "-123.profraw" for name in EXPECTED_BINARIES])
                    self.assertEqual(config["merge"], "sparse")
                    self.assertIn("-sparse", merge)
            if failure in ("sdk-version", "sdk-build", "sdk-query", "tool-version"):
                self.assertFalse(build_directories)
            else:
                self.assertTrue(build_directories)
            self.assertTrue(all(not path.exists() for path in build_directories))

    def test_success_commands_and_metadata(self):
        self.exercise()

    def test_every_declared_source_is_required_including_tests(self):
        for name in EXPECTED_SOURCES:
            with self.subTest(name=name):
                value = report()
                value["data"][0]["files"] = [item for item in value["data"][0]["files"]
                                               if item["filename"] != str(SOURCE / name)]
                with self.assertRaises(ValueError):
                    runner.validate_report(value, SOURCE)

    def test_failures_leave_no_success_artifact_and_clean_temporary_builds(self):
        for failure in ("compile", "run", "session-run", "controller-run", "operation-run", "adapter-run", "profile", "json", "source", "sdk-version", "sdk-build", "sdk-query", "tool-version"):
            with self.subTest(failure=failure):
                self.exercise(failure)


if __name__ == "__main__":
    unittest.main()
