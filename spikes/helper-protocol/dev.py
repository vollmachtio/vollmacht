"""Read-only developer assessment. Never installs, updates, or authorizes actions."""
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "spikes" / "simplewebauthn"
OUTPUT_LIMIT = 65_536


class Failure(Exception):
    """Fixed local error code, without subprocess output or supplied path reflection."""


def executable(value, label):
    path = Path(value)
    if not path.is_absolute():
        raise Failure(f"{label}_absolute_path_required")
    if not path.is_file() or not os.access(path, os.X_OK):
        raise Failure(f"{label}_missing_or_not_executable")
    return path.resolve()


def darwin_group_exited(pid, directory):
    # XNU killpg1 excludes zombies, returning EPERM for zombie-only groups.
    # EPERM can also be a real denial. Require a bounded, complete system census.
    data = run_bounded(["/bin/ps", "-axo", "pgid=,stat="], directory, timeout=1, group_cleanup=False)
    found = False
    for line in data.decode("ascii").splitlines():
        fields = line.split()
        if len(fields) != 2 or not fields[0].isdigit():
            raise Failure("tool_cleanup_failed")
        if int(fields[0]) == pid:
            found = True
            if not fields[1].startswith("Z"):
                return False
    return found


def run_bounded(args, directory, timeout=5, *, group_cleanup=True):
    """Empty environment, no shell, capped output, finite wait for trusted tools."""
    deadline = time.monotonic() + timeout
    try:
        child = subprocess.Popen(
            [str(arg) for arg in args], cwd=directory, env={},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError:
        raise Failure("tool_launch_failed") from None
    buffers = {child.stdout: bytearray(), child.stderr: bytearray()}
    try:
        with selectors.DefaultSelector() as selector:
            for stream in buffers:
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Failure("tool_timeout")
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    buffers[key.fileobj].extend(chunk)
                    if len(buffers[key.fileobj]) > OUTPUT_LIMIT:
                        raise Failure("tool_output_limit")
        # Observe exit without reaping: reserve the leader PID until group cleanup.
        # Otherwise an exited leader could leave descendants or its ID could be reused.
        while True:
            status = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if status is not None:
                break
            if time.monotonic() >= deadline:
                raise Failure("tool_timeout")
            time.sleep(0.01)
        if status.si_code != os.CLD_EXITED or status.si_status != 0:
            raise Failure("tool_failed")
        return bytes(buffers[child.stdout])
    finally:
        # The measure tool starts a Rust child which starts the real helper.
        # On failure, stop the group before reaping its leader. Not a sandbox:
        # a malicious descendant can deliberately escape its process group.
        cleanup_error = False
        try:
            if group_cleanup:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    exited = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    if not (platform.system() == "Darwin" and exited is not None
                            and darwin_group_exited(child.pid, directory)):
                        cleanup_error = True
            else:
                # Only used for the fixed /bin/ps census, which has no descendants.
                child.kill()
        except (OSError, Failure, ValueError):
            cleanup_error = True
        finally:
            try:
                if cleanup_error:
                    child.kill()  # Best effort leader cleanup even after group denial.
                child.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                cleanup_error = True
            finally:
                child.stdout.close()
                child.stderr.close()
        if cleanup_error:
            raise Failure("tool_cleanup_failed") from None


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65_536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inventory(directory):
    lock = json.loads((directory / "package-lock.json").read_text())
    if not isinstance(lock, dict) or not isinstance(lock.get("packages"), dict):
        raise Failure("dependency_metadata_invalid")
    packages = []
    for relative, package in sorted(lock["packages"].items()):
        if not relative:
            continue
        location = directory / relative
        if (not relative.startswith("node_modules/") or ".." in Path(relative).parts
                or not location.resolve().is_relative_to((directory / "node_modules").resolve())):
            raise Failure("dependency_path_invalid")
        try:
            installed = json.loads((location / "package.json").read_text())
        except (OSError, ValueError):
            raise Failure("dependencies_missing_run_npm_ci") from None
        name = relative.rsplit("node_modules/", 1)[1]
        if (not isinstance(installed, dict) or installed.get("name") != name
                or installed.get("version") != package["version"]):
            raise Failure("dependency_version_mismatch_run_npm_ci")
        packages.append({"name": name, "version": package["version"],
                         "license": package["license"], "integrity": package["integrity"]})
    # Logical bytes, not allocated disk blocks or a redistributable bundle size.
    size = sum(path.stat().st_size for path in (directory / "node_modules").rglob("*")
               if not path.is_symlink() and path.is_file())
    return {"packages": packages, "count": len(packages), "regular_file_bytes": size,
            "content_integrity_verified": False}


def assess(mode, node, launcher, driver, directory=PROBE):
    if platform.system() not in ("Darwin", "Linux"):
        raise Failure("unsupported_platform")
    node = executable(node, "node")
    launcher = executable(launcher, "launcher")
    driver = executable(driver, "driver")
    expected = (directory / ".node-version").read_text().strip()
    runtime = json.loads(run_bounded([
        node, "-p", "JSON.stringify({version:process.versions.node,arch:process.arch,platform:process.platform})",
    ], directory))
    if not isinstance(runtime, dict) or runtime.get("version") != expected:
        raise Failure("node_version_mismatch_use_repository_pin")
    required = ("helper.mjs", "helper-protocol.mjs", "helper-runner.mjs", "helper-measure.mjs",
                "helper-fixture.mjs", "fixture.mjs", "probe.mjs", "check-lock.mjs")
    if any(not (directory / name).is_file() for name in required):
        raise Failure("helper_files_missing")
    dependencies = inventory(directory)
    run_bounded([node, directory / "check-lock.mjs"], directory)
    # Import check only. Doctor does not execute the launcher or test driver.
    run_bounded([node, "-e", "import('./helper.mjs')"], directory)
    report = {
        "schema": 1, "status": "developer_preflight_passed", "runtime": runtime,
        "integration_exercised": mode == "measure",
        "host": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
        "lock_sha256": sha256(directory / "package-lock.json"),
        "artifacts": {label: {"bytes": path.stat().st_size, "sha256": sha256(path)}
                      for label, path in {"node_executable": node, "launcher": launcher, "test_driver": driver}.items()},
        "dependencies": dependencies,
        "limitations": ["trusted local paths; hashes are observations, not provenance checks",
                        "doctor checks launcher/driver executability, not function or architecture",
                        "installed package versions checked, not package content integrity",
                        "runtime shared libraries and npm are excluded from size totals",
                        "no signed bundle, sandbox, production approval or vulnerability certification"],
    }
    if mode == "measure":
        report["measurement"] = json.loads(run_bounded(
            [node, directory / "helper-measure.mjs", driver, launcher], directory, timeout=60))
    return report


def main(args):
    if len(args) != 4 or args[0] not in ("doctor", "measure"):
        print("usage: python3 dev.py doctor|measure /absolute/node /absolute/launcher /absolute/test-driver", file=sys.stderr)
        return 2
    try:
        print(json.dumps(assess(*args), indent=2))
        return 0
    except Failure as error:
        print(str(error), file=sys.stderr)
    except (OSError, ValueError, KeyError, TypeError):
        print("developer_assessment_failed", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
