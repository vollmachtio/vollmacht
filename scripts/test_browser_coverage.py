"""Check VM source attribution, not coverage percentage (Python 3.11+)."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile


def validate_attribution(records, source):
    """Require executed source attribution; not a percentage or authenticity check."""
    if any(record["url"].startswith("evalmachine.") for record in records):
        raise ValueError("Anonymous VM source remains in browser coverage.")
    attributed = [
        record for record in records
        if record["url"] in {str(source), source.as_uri()}
    ]
    if not attributed:
        raise ValueError("Shipped app.js is missing from V8 coverage.")
    if not any(
        item["count"] > 0 and item["endOffset"] > item["startOffset"]
        for record in attributed
        for function in record["functions"]
        for item in function["ranges"]
    ):
        raise ValueError("Shipped app.js has no executed coverage ranges.")


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Provide the absolute path to the pinned Node executable.")
    node = Path(sys.argv[1])
    if not node.is_absolute() or not node.is_file():
        raise SystemExit("Node executable must be an existing absolute file path.")
    root = Path(__file__).resolve().parent.parent
    expected = "v" + (root / "spikes/simplewebauthn/.node-version").read_text().strip()
    version = subprocess.run(
        [str(node), "-v"], check=True, capture_output=True, text=True,
        timeout=10, env={},
    ).stdout.strip()
    if version != expected:
        raise SystemExit(f"Expected Node {expected}; found {version}.")

    source = (root / "spikes/webauthn/web/app.js").resolve()
    with tempfile.TemporaryDirectory(prefix="vollmacht-browser-coverage-") as temporary:
        subprocess.run(
            [str(node), str(root / "spikes/webauthn/tests/browser.cjs")],
            cwd=root, check=True, timeout=30,
            env={"NODE_V8_COVERAGE": temporary},
        )
        reports = list(Path(temporary).glob("coverage-*.json"))
        if not reports:
            raise SystemExit("No V8 coverage report was generated.")
        records = [
            record
            for report in reports
            for record in json.loads(report.read_text())["result"]
        ]
        try:
            validate_attribution(records, source)
        except ValueError as error:
            raise SystemExit(str(error)) from None
    print("Browser VM coverage identifies executed shipped app.js; no anonymous VM source.")


if __name__ == "__main__":
    main()
