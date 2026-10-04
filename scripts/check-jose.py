"""Check the isolated signing-interface experiment, not production authorization."""

from pathlib import Path
import subprocess


def main():
    root = Path(__file__).resolve().parent.parent
    spike = root / "spikes" / "jose"
    option = chr(45) * 2
    commands = [
        ["cargo", "fmt", option, option + "check"],
        ["cargo", "clippy", option + "all-targets", option + "locked", option, "-D", "warnings"],
        ["cargo", "test", option + "locked"],
    ]
    for command in commands:
        subprocess.run(command, cwd=spike, check=True, timeout=300)


if __name__ == "__main__":
    main()
