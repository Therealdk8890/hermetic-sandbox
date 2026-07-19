"""Replay a downloaded proof artifact and compare every captured value."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROOF = ROOT / ".hermetic-proof"


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    artifact = Path(args[0]).resolve() if args else PROOF / "download"
    expected_path = artifact / "observed.json"
    journals = artifact / "sealed"
    actual_path = PROOF / "observed.json"
    actual_path.unlink(missing_ok=True)

    handoff_started_text = os.environ.get("HERMETIC_HANDOFF_STARTED")
    handoff_started = (
        float(handoff_started_text) if handoff_started_text is not None else None
    )
    started = time.monotonic()
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "hermetic",
            "replay",
            str(journals),
            "--",
            "-q",
        ],
        cwd=ROOT,
        check=False,
    )
    elapsed = time.monotonic() - started
    if result.returncode != 1:
        raise SystemExit(
            f"replay proof expected the recorded failure, got exit {result.returncode}"
        )
    if not actual_path.is_file():
        raise SystemExit("replay proof did not execute the recorded test")
    expected = json.loads(expected_path.read_text())
    actual = json.loads(actual_path.read_text())
    if actual != expected:
        raise SystemExit("replay proof values differ from the recording")
    if elapsed >= 60:
        raise SystemExit(f"replay proof exceeded 60 seconds ({elapsed:.3f}s)")
    if handoff_started is not None:
        handoff_elapsed = time.time() - handoff_started
        if handoff_elapsed >= 60:
            raise SystemExit(
                "artifact download through exact replay exceeded 60 seconds "
                f"({handoff_elapsed:.3f}s)"
            )
        print(
            f"exact replay proven in {elapsed:.3f}s "
            f"({handoff_elapsed:.3f}s from download start)"
        )
    else:
        print(f"exact replay proven in {elapsed:.3f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
