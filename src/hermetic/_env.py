"""Environment variable snapshot/restore, overrides and scrubbing."""

from __future__ import annotations

import os
from typing import Mapping

from ._patch import PatchSet

# Kept when scrub_env=True: enough for subprocesses, temp files and locale
# handling to keep working. Sandbox fs/env overrides are applied afterwards.
_SCRUB_KEEP = {
    "PATH", "HOME", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "LC_CTYPE",
    "TZ", "TERM", "SHELL", "USER", "PYTHONHASHSEED", "VIRTUAL_ENV",
    "PYTEST_CURRENT_TEST", "PYTEST_XDIST_WORKER", "PYTEST_XDIST_WORKER_COUNT",
    "PYTEST_XDIST_TESTRUNUID",
}


def install_env_patches(
    patches: PatchSet,
    overrides: Mapping[str, str | None] | None,
    scrub: bool,
) -> None:
    """Snapshot os.environ (restored wholesale on teardown), then scrub/override.

    An override value of ``None`` removes the variable.
    """
    snapshot = dict(os.environ)

    def restore() -> None:
        os.environ.clear()
        os.environ.update(snapshot)

    patches.add_undo(restore)

    if scrub:
        for key in list(os.environ):
            if key in _SCRUB_KEEP or key.startswith("LC_"):
                continue
            del os.environ[key]

    for key, value in (overrides or {}).items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = str(value)
