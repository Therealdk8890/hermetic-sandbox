"""Synthetic failure used only by the cross-runner replay proof workflow."""

from __future__ import annotations

import datetime
import json
import random
import secrets
import time
import uuid
from pathlib import Path

import pytest


@pytest.mark.hermetic(
    network="block",
    allow_loopback=False,
    allow_unix=False,
    scrub_env=True,
)
def test_cross_runner_replay() -> None:
    observed = {
        "wall": time.time(),
        "monotonic": time.monotonic(),
        "performance": time.perf_counter(),
        "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "random": random.random(),
        "uuid": str(uuid.uuid4()),
        "token": secrets.token_hex(12),
    }
    output = Path(".hermetic-proof") / "observed.json"
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(observed, sort_keys=True))
    pytest.fail("synthetic Hermetic cross-runner replay proof")
