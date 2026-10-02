"""Install or run the pinned dependency checker (network access required)."""

from pathlib import Path
import subprocess
import sys

VERSION = "0.20.2"


def main():
    root = Path(__file__).resolve().parent.parent
    option = chr(45) * 2
    if sys.argv[1:] == ["install"]:
        subprocess.run(
            ["cargo", "install", "cargo-deny", option + "version", VERSION, option + "locked"],
            cwd=root, check=True,
        )
    elif sys.argv[1:]:
        raise SystemExit("Usage: python3 scripts/dependencies.py [install]")

    version = subprocess.run(
        ["cargo", "deny", "-V"], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()
    if version != f"cargo-deny {VERSION}":
        raise SystemExit(f"Expected cargo-deny {VERSION}; found {version}")
    subprocess.run(
        ["cargo", "deny", option + "workspace", option + "locked", "check"], cwd=root, check=True
    )
    subprocess.run(
        ["cargo", "deny", option + "manifest-path", "spikes/canonicalization/Cargo.toml",
         option + "locked", option + "config", "deny.toml", "check"],
        cwd=root, check=True,
    )


if __name__ == "__main__":
    main()
