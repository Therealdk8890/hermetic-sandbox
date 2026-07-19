"""The record/replay journal.

A journal is one JSON (optionally gzip) file capturing everything nondeterministic
that the sandbox intercepted during a run: per-source value queues (clock
readings, urandom draws), the initial ``random`` state, an environment-name
snapshot, and a machine fingerprint used to warn when a replay happens in a
meaningfully different environment.

Durability rules learned from CI reality:

- Writes are atomic (temp file + ``os.replace``) so an interrupted run never
  leaves truncated JSON in an artifact directory.
- Paths must be resolved to absolute *before* the sandbox potentially chdirs.
- Recording from more than one thread is detected and stamped into the journal
  (``concurrency_unfaithful``) — per-source queues cannot faithfully replay a
  multi-threaded interleaving, and pretending otherwise burns trust.

Security note (documented in the README): recorded urandom draws are verbatim —
anything the test derived from them (tokens, keys) is recoverable from the
journal. Environment variables are recorded as names only, except the values of
TZ and PYTHONHASHSEED (and the locale string), which the fingerprint needs for
replay-fidelity warnings.
"""

from __future__ import annotations

import gzip
import json
import locale
import os
import platform
import socket
import subprocess
import sys
import threading
import time as _time_module
from pathlib import Path
from typing import Any

from ._clock import REAL_TIME
from ._errors import ReplayMismatch

FORMAT = "hermetic-journal"
VERSION = 1
DEFAULT_EVENT_CAP = 100_000

_git_sha_cache: dict[str, str | None] = {}


def _git_sha(cwd: str) -> str | None:
    if cwd not in _git_sha_cache:
        try:
            out = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=cwd, capture_output=True, text=True, timeout=2.0,
            )
            _git_sha_cache[cwd] = out.stdout.strip() if out.returncode == 0 else None
        except (OSError, subprocess.SubprocessError):
            _git_sha_cache[cwd] = None
    return _git_sha_cache[cwd]


def collect_fingerprint() -> dict[str, Any]:
    """Facts a replay needs to judge whether it can be faithful."""
    try:
        current_locale = locale.setlocale(locale.LC_ALL)
    except locale.Error:
        current_locale = None
    return {
        "python": sys.version.split()[0],
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "hostname": socket.gethostname(),
        "cpu_count": os.cpu_count(),
        "tz_env": os.environ.get("TZ"),
        "tzname": list(_time_module.tzname),
        "locale": current_locale,
        "hash_seed_env": os.environ.get("PYTHONHASHSEED"),
        "hash_randomization": bool(sys.flags.hash_randomization),
        "git_sha": _git_sha(os.getcwd()),
    }


def fingerprint_warnings(recorded: dict[str, Any], current: dict[str, Any]) -> list[str]:
    """Human-readable per-field mismatch warnings for replay."""
    warnings: list[str] = []
    labels = {
        "python": "Python version",
        "implementation": "Python implementation",
        "platform": "platform",
        "tz_env": "TZ environment variable",
        "tzname": "timezone",
        "locale": "locale",
        "hash_seed_env": "PYTHONHASHSEED",
        "cpu_count": "CPU count",
        "git_sha": "git commit",
    }
    for key, label in labels.items():
        rec, cur = recorded.get(key), current.get(key)
        if rec is not None and rec != cur:
            warnings.append(
                f"recorded {label} was {rec!r}, this environment has {cur!r}"
            )
    if recorded.get("hash_randomization") and not recorded.get("hash_seed_env"):
        warnings.append(
            "the recorded run used hash randomization with an unknown seed "
            "(set PYTHONHASHSEED in CI to make dict/set-order flakes replayable)"
        )
    return warnings


class JournalWriter:
    """Accumulates events during a record-mode run and writes the file at exit."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        config: dict[str, Any],
        test_id: str | None = None,
        event_cap: int = DEFAULT_EVENT_CAP,
    ) -> None:
        # Resolve now: the sandbox may chdir after this.
        self.path = Path(path).resolve()
        self._config = config
        self._test_id = test_id
        self._cap = event_cap
        self._events: dict[str, list[Any]] = {}
        self._overflow: set[str] = set()
        self._threads: dict[str, set[str]] = {}
        self._recording_thread = threading.current_thread().name
        self._random_state: list | None = None
        self._env_names: list[str] = sorted(os.environ)
        self._fingerprint = collect_fingerprint()
        self._lock = threading.Lock()

    def record_event(self, source: str, value: Any) -> None:
        with self._lock:
            threads = self._threads.setdefault(source, set())
            threads.add(threading.current_thread().name)
            queue = self._events.setdefault(source, [])
            if len(queue) >= self._cap:
                self._overflow.add(source)
                return
            queue.append(value)

    def set_random_state(self, serialized_state: list) -> None:
        self._random_state = serialized_state

    def as_dict(self) -> dict[str, Any]:
        multi_thread = sorted(
            source for source, threads in self._threads.items() if len(threads) > 1
        )
        return {
            "format": FORMAT,
            "version": VERSION,
            # REAL_TIME: while recording, time.time is patched to journal every
            # reading — stamping via the patched clock would record our own write.
            "created_at": REAL_TIME(),
            "test": self._test_id,
            "config": self._config,
            "fingerprint": self._fingerprint,
            "random_state": self._random_state,
            "events": self._events,
            "counts": {source: len(q) for source, q in self._events.items()},
            "overflow": sorted(self._overflow),
            "concurrency_unfaithful": multi_thread,
            "env": {"mode": "names", "names": self._env_names},
        }

    def write(self) -> Path:
        """Atomically write the journal (gzip when the path ends in .gz)."""
        payload = json.dumps(self.as_dict(), separators=(",", ":")).encode()
        if self.path.name.endswith(".gz"):
            payload = gzip.compress(payload, mtime=0)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + f".part-{os.getpid()}")
        tmp.write_bytes(payload)
        os.replace(tmp, self.path)
        return self.path


class JournalReader:
    """Loads and validates a journal for replay."""

    def __init__(self, data: dict[str, Any], path: Path) -> None:
        self.path = path
        if data.get("format") != FORMAT:
            raise ReplayMismatch(f"hermetic: {path} is not a hermetic journal")
        if data.get("version") != VERSION:
            raise ReplayMismatch(
                f"hermetic: {path} has journal version {data.get('version')!r}; "
                f"this hermetic reads version {VERSION}"
            )
        self.test: str | None = data.get("test")
        self.config: dict[str, Any] = data.get("config") or {}
        self.fingerprint: dict[str, Any] = data.get("fingerprint") or {}
        self.random_state: list | None = data.get("random_state")
        self.events: dict[str, list[Any]] = data.get("events") or {}
        self.overflow: list[str] = data.get("overflow") or []
        self.concurrency_unfaithful: list[str] = data.get("concurrency_unfaithful") or []

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> "JournalReader":
        resolved = Path(path).resolve()
        try:
            raw = resolved.read_bytes()
        except OSError as exc:
            raise ReplayMismatch(f"hermetic: cannot read journal {resolved}: {exc}") from exc
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise ReplayMismatch(
                f"hermetic: journal {resolved} is corrupt (truncated upload?): {exc}"
            ) from exc
        return cls(data, resolved)

    def faithfulness_warnings(self) -> list[str]:
        """Warnings to surface before replaying this journal."""
        warnings = [
            f"hermetic replay: {message}"
            for message in fingerprint_warnings(self.fingerprint, collect_fingerprint())
        ]
        if self.overflow:
            warnings.append(
                f"hermetic replay: journal hit its event cap for {self.overflow} — "
                "the tail of the run was not captured; replay is partial"
            )
        if self.concurrency_unfaithful:
            warnings.append(
                "hermetic replay: sources "
                f"{self.concurrency_unfaithful} were recorded from multiple threads; "
                "per-source replay cannot reproduce a thread interleaving faithfully"
            )
        recorded_network = (self.config or {}).get("network")
        if recorded_network not in ("block", None):
            warnings.append(
                f"hermetic replay: the recorded run allowed network ({recorded_network!r}); "
                "network traffic is NOT captured in journals, so those calls will not "
                "behave as recorded"
            )
        if (self.config or {}).get("clock") == "off":
            warnings.append(
                "hermetic replay: the recorded run used clock='off'; clock readings "
                "were not captured"
            )
        return warnings
