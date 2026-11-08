"""Run the existing synthetic vertical slice as a reviewable, non-live demo."""

import os
from pathlib import Path
import shutil
import signal
import subprocess


ROOT = Path(__file__).resolve().parent.parent
PREFIX = "VOLLMACHT_DEMO:"
STAGES = (
    ("proposal", "Proposed: squash PR 42 in fixture repository vollmacht-disposable/example."),
    ("synthetic_approval", "Approved with a synthetic authenticator; real WebAuthn verification follows."),
    ("issued", "Verified approval evidence and signed a fresh, bounded mandate."),
    ("claimed", "Committed the execution attempt to disposable SQLite storage."),
    ("verified_candidate", "Verified the agent proof and approval evidence: merge candidate ready."),
    ("resource_checked", "Compared fixture repository facts and current method restrictions; changed head or base is denied."),
    ("replay_denied", "Reopened storage: replay denied without another verification call."),
    ("negatives_passed", "Tampering, expiry, stored-binding changes and concurrent attempts checked."),
)


def run_flow(command, environment):
    """Own the Cargo process group so cancellation also stops its children."""
    process = subprocess.Popen(
        command, cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=300)
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.stdout.close()
            process.stderr.close()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        raise


def main():
    print("Vollmacht review demo: synthetic approval, no Touch ID, no GitHub writes.", flush=True)
    node = shutil.which("node")
    cargo = shutil.which("cargo")
    if not node or not cargo:
        print("Install the pinned Node and Rust prerequisites from docs/development.md, then retry.")
        return 1
    expected = "v" + (ROOT / "spikes/simplewebauthn/.node-version").read_text().strip()
    option = chr(45) * 2
    try:
        version = subprocess.run(
            [node, option + "version"], capture_output=True, text=True, timeout=10, check=False
        )
        if version.returncode != 0 or version.stdout.strip() != expected:
            print(f"Select Node {expected}; the demo does not install or change runtimes.")
            return 1
        environment = os.environ.copy()
        environment["VOLLMACHT_TEST_NODE"] = str(Path(node).resolve())
        environment["VOLLMACHT_DEMO_TRACE"] = "1"
        print("Running the verified flow and failure scenarios. First build may take a few minutes.", flush=True)
        result = run_flow(
            [cargo, "test", "-p", "vollmacht-helper-launcher", option + "locked",
             option + "test", "fresh_simulated_merge",
             "fresh_synthetic_approval_issuance_and_execution_record_one_candidate",
             option, option + "exact", option + "nocapture"],
            environment,
        )
    except KeyboardInterrupt:
        print("Demo cancelled. No successful walkthrough is reported.")
        return 130
    except (OSError, subprocess.TimeoutExpired):
        print("Demo could not complete. No successful walkthrough is reported.")
        print("Check prerequisites and run the fresh-flow test in docs/development.md for diagnostics.")
        return 1
    if result.returncode != 0:
        print("Demo checks failed. No successful walkthrough is reported.")
        print("Run the fresh-flow test in docs/development.md for diagnostics; no checks were skipped.")
        return 1
    events = [line[len(PREFIX):] for line in result.stdout.splitlines() if line.startswith(PREFIX)]
    if events != [event for event, _ in STAGES]:
        print("Demo transcript is incomplete or unexpected. No successful walkthrough is reported.")
        return 1
    for number, (_, description) in enumerate(STAGES, 1):
        print(f"{number}. {description}")
    print("Simulation passed. The GitHub action was NOT sent; the result is a candidate, not dispatch authority.")
    print("Next review: approval wording and flow. Real approval, reservation and live deployment remain unfinished.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
