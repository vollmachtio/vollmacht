"""Run the same toolchain and Cargo checks locally and in CI (Python 3.11+)."""

from pathlib import Path
import subprocess
import tomllib


def main():
    root = Path(__file__).resolve().parent.parent
    toolchain = tomllib.loads((root / "rust-toolchain.toml").read_text())
    expected = toolchain["toolchain"]["channel"]
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    if manifest["workspace"]["package"]["rust-version"] != expected:
        raise SystemExit("Cargo rust-version must match the pinned toolchain.")

    for program in ("rustc", "cargo"):
        result = subprocess.run(
            [program, "-V"], cwd=root, check=True, capture_output=True, text=True
        )
        if result.stdout.split()[1] != expected:
            raise SystemExit(f"{program} must be version {expected}; found {result.stdout.strip()}")
        print(result.stdout.strip(), flush=True)

    # Keep options in one place so local and CI verification cannot drift.
    option = chr(45) * 2
    commands = [
        ["python3", "spikes/helper-protocol/dev_test.py"],
        ["python3", "spikes/macos-key/swift/test_run.py"],
        ["python3", "scripts/check-canonicalization.py"],
        ["python3", "scripts/check-jose.py"],
        ["node", "spikes/webauthn/tests/browser.cjs"],
        ["cargo", "fmt", option + "all", option, option + "check"],
        ["cargo", "clippy", option + "workspace", option + "all-targets", option + "locked", option, "-D", "warnings"],
        ["cargo", "test", option + "workspace", option + "locked"],
        ["cargo", "build", option + "workspace", option + "release", option + "locked"],
    ]
    for command in commands:
        print("Running " + " ".join(command), flush=True)
        subprocess.run(command, cwd=root, check=True)


if __name__ == "__main__":
    main()
