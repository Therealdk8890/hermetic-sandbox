"""Record one known-safe synthetic failure and validate its upload policy."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from hermetic._security import require_upload_safe


ROOT = Path(__file__).resolve().parents[2]
PROOF = ROOT / ".hermetic-proof"
SEALED = PROOF / "sealed"


def main() -> int:
    shutil.rmtree(PROOF, ignore_errors=True)
    PROOF.mkdir()
    environment = os.environ.copy()
    environment["PYTHONHASHSEED"] = "0"
    with tempfile.TemporaryDirectory(prefix="hermetic-proof-raw-") as temporary:
        journals_directory = Path(temporary) / "journals"
        command = [
            sys.executable,
            "-m",
            "pytest",
            str(ROOT / ".github/replay-proof/case.py"),
            f"--hermetic-record={journals_directory}",
            "-q",
        ]
        started = time.monotonic()
        result = subprocess.run(command, cwd=ROOT, env=environment, check=False)
        elapsed = time.monotonic() - started
        if result.returncode != 1:
            raise SystemExit(
                f"record proof expected one test failure, got exit {result.returncode}"
            )

        journals = sorted(journals_directory.glob("*.json.gz"))
        if len(journals) != 1:
            raise SystemExit(
                f"record proof expected one journal, found {len(journals)}"
            )
        security = require_upload_safe(
            journals[0],
            encrypted=True,
            current_env=environment,
        )
        if security.is_upload_safe(encrypted=False):
            raise SystemExit(
                "record proof expected replay-sensitive plaintext to be blocked"
            )
        sealed = subprocess.run(
            [
                sys.executable,
                "-m",
                "hermetic",
                "journal",
                "seal",
                str(journals_directory),
                "--output",
                str(SEALED),
            ],
            cwd=ROOT,
            env=environment,
            check=False,
        )
        if sealed.returncode != 0:
            raise SystemExit(
                f"record proof could not seal its journal (exit {sealed.returncode})"
            )

    envelopes = sorted(SEALED.glob("*.sealed"))
    if len(envelopes) != 1:
        raise SystemExit(
            f"record proof expected one sealed journal, found {len(envelopes)}"
        )
    if not (PROOF / "observed.json").is_file():
        raise SystemExit("record proof did not write its observation")
    print(f"record proof complete in {elapsed:.3f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
