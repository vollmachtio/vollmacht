"""Run the existing synthetic vertical slice as a reviewable, non-live demo."""

import os
import base64
import hashlib
import json
import re
from pathlib import Path
import shutil
import signal
import subprocess


ROOT = Path(__file__).resolve().parent.parent
PREFIX = "VOLLMACHT_DEMO:"
STAGES = (
    ("proposal", "Proposed: exact synthetic operation shown above."),
    ("synthetic_approval", "Approved with a synthetic authenticator; real WebAuthn verification follows."),
    ("issued", "Verified approval evidence and signed a fresh, bounded mandate."),
    ("claimed", "Committed the execution attempt to disposable SQLite storage."),
    ("verified_candidate", "Verified the agent proof and approval evidence: merge candidate ready."),
    ("resource_checked", "Compared fixture repository facts and current method restrictions; changed head or base is denied."),
    ("replay_denied", "Reopened storage: replay denied without another verification call."),
    ("negatives_passed", "Tampering, expiry, stored-binding changes and concurrent attempts checked."),
)


def proposal_lines(output):
    """Validate a diagnostic display, never authorize an operation.

    Compact sorted JSON matches JCS only for this ASCII/safe-integer subset.
    This is not a general canonicalizer or a replacement for the Rust verifier.
    """
    prefix = "VOLLMACHT_PROPOSAL:"
    lines = output.splitlines()
    records = [i for i, line in enumerate(lines) if line.startswith(prefix)]
    if len(records) != 1 or records[0] >= lines.index(PREFIX + "proposal"):
        raise ValueError("proposal record")
    raw = lines[records[0]][len(prefix):]
    if len(raw) > 16384:
        raise ValueError("proposal size")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate field")
            result[key] = value
        return result

    def exact(value, fields):
        if type(value) is not dict or set(value) != set(fields.split()):
            raise ValueError("fields")
        return value

    def text(value, pattern, maximum):
        if type(value) is not str or not 1 <= len(value) <= maximum or re.fullmatch(pattern, value) is None:
            raise ValueError("text")
        return value

    def number(value, minimum=0, maximum=9007199254740991):
        if type(value) is not int or not minimum <= value <= maximum:
            raise ValueError("integer")
        return value

    def binary(value, minimum, maximum):
        text(value, r"[A-Za-z0-9_-]+", (maximum * 4 + 2) // 3)
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        if not minimum <= len(decoded) <= maximum or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value:
            raise ValueError("binary")

    record = exact(json.loads(raw, object_pairs_hook=unique), "payload fingerprint")
    p = exact(record["payload"], "version crypto_profile mandate_id nonce issuer_id audience principal_id credential_id agent_jkt policy_revision issued_at expires_at operation display")
    number(p["version"], 1, 1)
    if p["crypto_profile"] != "vollmacht-local-es256-v1":
        raise ValueError("profile")
    for name in ("mandate_id", "issuer_id", "audience", "principal_id"):
        text(p[name], r"[0-9a-f]{32}", 32)
    for name in ("nonce", "agent_jkt"):
        binary(p[name], 32, 32)
    binary(p["credential_id"], 1, 1024)
    binary(record["fingerprint"], 32, 32)
    number(p["policy_revision"], 1)
    issued, expiry = number(p["issued_at"]), number(p["expires_at"])
    if not 1 <= expiry - issued <= 300:
        raise ValueError("lifetime")
    operation = exact(p["operation"], "action resource constraints")
    if operation["action"] != "github.pull_request.merge":
        raise ValueError("action")
    resource = exact(operation["resource"], "host repository_id pull_request_number")
    if resource["host"] != "github.com":
        raise ValueError("host")
    text(resource["repository_id"], r"[1-9][0-9]{0,19}", 20)
    number(resource["pull_request_number"], 1, 2147483647)
    constraints = exact(operation["constraints"], "expected_head_sha base_ref merge_method")
    text(constraints["expected_head_sha"], r"[0-9a-f]{40}", 40)
    branch = text(constraints["base_ref"], r"[!-~]+", 255)
    if (branch in ("@", "HEAD") or branch.startswith(("-", "/")) or branch.endswith(("/", "."))
            or any(part in branch for part in ("//", "..", "@{"))
            or any(char in branch for char in "~^:?*[\\")
            or any(part.startswith(".") or part.endswith(".lock") for part in branch.split("/"))):
        raise ValueError("branch")
    if constraints["merge_method"] not in ("merge", "squash", "rebase"):
        raise ValueError("method")
    display = exact(p["display"], "version repository")
    number(display["version"], 1, 1)
    text(display["repository"], r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", 201)
    canonical = json.dumps(p, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("ascii")
    expected = base64.urlsafe_b64encode(hashlib.sha256(b"vollmacht:mandate:v1\0" + canonical).digest()).rstrip(b"=").decode()
    if len(canonical) > 8192 or expected != record["fingerprint"]:
        raise ValueError("fingerprint")
    return [
        "Recorded synthetic proposal (not an interactive approval prompt):",
        f"  Action: {operation['action']}",
        f"  Repository: {display['repository']} (ID {resource['repository_id']})",
        f"  PR: {resource['pull_request_number']} | base: {branch} | method: {constraints['merge_method']}",
        f"  Exact head: {constraints['expected_head_sha']}",
        f"  Principal: {p['principal_id']} | credential: {p['credential_id']}",
        f"  Agent thumbprint: {p['agent_jkt']}",
        f"  Issuer: {p['issuer_id']} | audience: {p['audience']}",
        f"  Mandate: {p['mandate_id']} | profile: {p['crypto_profile']} | policy: {p['policy_revision']}",
        f"  Simulated clock: issued {issued}, expires {expiry} (TTL {expiry - issued}s)",
        f"  Mandate fingerprint: {record['fingerprint']}",
    ]


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
    try:
        proposal = proposal_lines(result.stdout)
    except (ValueError, TypeError, KeyError, RecursionError):
        print("Demo proposal is invalid or inconsistent. No successful walkthrough is reported.")
        return 1
    print("\n".join(proposal))
    for number, (_, description) in enumerate(STAGES, 1):
        print(f"{number}. {description}")
    print("Simulation passed. The GitHub action was NOT sent; the result is a candidate, not dispatch authority.")
    print("Next review: approval wording and flow. Real approval, reservation and live deployment remain unfinished.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
