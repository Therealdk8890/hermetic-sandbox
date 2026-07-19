"""Opt-in filesystem isolation (``fs="isolate"``).

Not a fake filesystem: a fresh real tempdir with ``cwd/``, ``home/`` and
``tmp/`` subdirectories. ``HOME``/``TMPDIR``/``tempfile`` are redirected (and
optionally the working directory moved) so tests that write "wherever" land in
a directory that is deleted on exit instead of polluting the machine.

This is deliberately **off by default**: silently chdir-ing breaks the very
common pytest pattern of reading fixture files by path relative to the repo
root, and relocates coverage output. Turn it on for tests that scribble.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from ._patch import PatchSet


class FsIsolation:
    """Paths of the sandboxed filesystem area (``sb.fs``)."""

    def __init__(self) -> None:
        # resolve(): on macOS mkdtemp returns /var/... which is a symlink to
        # /private/var/... — os.getcwd() reports the resolved form.
        self.root = Path(tempfile.mkdtemp(prefix="hermetic-")).resolve()
        self.cwd = self.root / "cwd"
        self.home = self.root / "home"
        self.tmp = self.root / "tmp"
        for path in (self.cwd, self.home, self.tmp):
            path.mkdir()

    def __repr__(self) -> str:
        return f"FsIsolation(root={str(self.root)!r})"


def install_fs_patches(patches: PatchSet, chdir: bool) -> FsIsolation:
    # mkdtemp() inside FsIsolation caches its computed default into the module
    # global tempfile.tempdir as a side effect; put the pre-sandbox value back
    # before patches.setattr snapshots it, or teardown "restores" the cache.
    original_tempdir = tempfile.tempdir
    isolation = FsIsolation()
    tempfile.tempdir = original_tempdir

    # Registered first so it runs LAST on teardown (after cwd is restored and
    # env vars no longer point into the tree).
    patches.add_undo(lambda: shutil.rmtree(isolation.root, ignore_errors=True))

    for var in ("TMPDIR", "TEMP", "TMP"):
        patches.setitem(os.environ, var, str(isolation.tmp))
    patches.setitem(os.environ, "HOME", str(isolation.home))
    # tempfile caches its choice; point it directly at the sandbox tmp.
    patches.setattr(tempfile, "tempdir", str(isolation.tmp))

    if chdir:
        original_cwd = os.getcwd()

        def restore_cwd() -> None:
            try:
                os.chdir(original_cwd)
            except OSError:
                os.chdir(Path.home())
        os.chdir(isolation.cwd)
        patches.add_undo(restore_cwd)

    return isolation
