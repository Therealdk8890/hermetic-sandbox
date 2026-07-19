"""The record/replay journal.

A journal is one JSON (optionally gzip) file capturing everything nondeterministic
that the sandbox intercepted during a run: per-source value queues (clock
readings, urandom draws), the initial ``random`` state, and a minimal
compatibility fingerprint used to judge replay fidelity. Journal v2 omits
environment names, environment values, and the hostname.

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
import hashlib
import importlib.metadata
import json
import locale
import os
import platform
import subprocess
import sys
import threading
import time as _time_module
from pathlib import Path
from typing import Any

from ._clock import REAL_TIME
from ._envelope import ensure_private_path
from ._errors import ReplayExhausted, ReplayMismatch

FORMAT = "hermetic-journal"
VERSION = 2
SUPPORTED_VERSIONS = {1, VERSION}
DEFAULT_EVENT_CAP = 100_000
_IS_WINDOWS = os.name == "nt"

_git_sha_cache: dict[str, str | None] = {}
_git_diff_cache: dict[str, str | None] = {}


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


def _git_diff_sha(cwd: str) -> str | None:
    if cwd not in _git_diff_cache:
        try:
            out = subprocess.run(
                ["git", "diff", "--no-ext-diff", "--binary", "HEAD", "--"],
                cwd=cwd, capture_output=True, timeout=2.0,
            )
            _git_diff_cache[cwd] = (
                hashlib.sha256(out.stdout).hexdigest()
                if out.returncode == 0
                else None
            )
        except (OSError, subprocess.SubprocessError):
            _git_diff_cache[cwd] = None
    return _git_diff_cache[cwd]


def _test_file_sha(test_id: str | None, cwd: str) -> str | None:
    if not test_id:
        return None
    raw_path = test_id.split("::", 1)[0]
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = Path(cwd) / candidate
    try:
        return hashlib.sha256(candidate.read_bytes()).hexdigest()
    except OSError:
        return None


def _distribution_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def collect_fingerprint(test_id: str | None = None) -> dict[str, Any]:
    """Facts a replay needs to judge whether it can be faithful."""
    cwd = os.getcwd()
    try:
        current_locale = locale.setlocale(locale.LC_ALL)
    except locale.Error:
        current_locale = None
    return {
        "python": sys.version.split()[0],
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "tz_env": os.environ.get("TZ"),
        "tzname": list(_time_module.tzname),
        "locale": current_locale,
        "hash_seed_env": os.environ.get("PYTHONHASHSEED"),
        "hash_randomization": bool(sys.flags.hash_randomization),
        "git_sha": _git_sha(cwd),
        "git_diff_sha256": _git_diff_sha(cwd),
        "test_file_sha256": _test_file_sha(test_id, cwd),
        "hermetic_version": _distribution_version("hermetic-sandbox"),
        "pytest_version": _distribution_version("pytest"),
    }


def _enforce_private_file(path: Path, descriptor: int | None = None) -> None:
    if _IS_WINDOWS:
        ensure_private_path(path)
    elif descriptor is not None and hasattr(os, "fchmod"):
        os.fchmod(descriptor, 0o600)
    else:
        ensure_private_path(path)


def _atomic_write_private(path: Path, payload: bytes) -> Path:
    """Atomically replace *path* with an owner-only regular file.

    The temporary file is opened with O_EXCL (and O_NOFOLLOW where available),
    so a pre-planted symlink cannot redirect sensitive journal bytes.  A small
    deterministic suffix search avoids drawing entropy while os.urandom may be
    patched by the recorder itself.
    """
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    base = path.with_name(f".{path.name}.part-{os.getpid()}-{threading.get_ident()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd: int | None = None
    tmp: Path | None = None
    try:
        for attempt in range(100):
            candidate = base if attempt == 0 else base.with_name(f"{base.name}-{attempt}")
            try:
                fd = os.open(candidate, flags, 0o600)
            except FileExistsError:
                continue
            tmp = candidate
            break
        if fd is None or tmp is None:
            raise OSError(f"could not create a private temporary file for {path}")

        try:
            _enforce_private_file(tmp, fd)
            with os.fdopen(fd, "wb", closefd=True) as stream:
                fd = None
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            if fd is not None:
                os.close(fd)

        os.replace(tmp, path)
        tmp = None
        _enforce_private_file(path)
        return path
    finally:
        if tmp is not None:
            try:
                tmp.unlink()
            except OSError:
                pass


def write_private_json(path: str | os.PathLike[str], data: Any) -> Path:
    """Write JSON atomically with private file permissions."""
    resolved = Path(path).resolve()
    payload = json.dumps(data, indent=2, sort_keys=True).encode()
    return _atomic_write_private(resolved, payload)


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
        "git_diff_sha256": "tracked source changes",
        "test_file_sha256": "recorded test file",
        "hermetic_version": "Hermetic version",
        "pytest_version": "pytest version",
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


def fingerprint_blockers(
    recorded: dict[str, Any], current: dict[str, Any]
) -> list[str]:
    """Environment mismatches that make a strict replay misleading."""
    blockers: list[str] = []
    strict_fields = {
        "python": "Python version",
        "implementation": "Python implementation",
        "hash_seed_env": "PYTHONHASHSEED",
        "git_sha": "git commit",
        "git_diff_sha256": "tracked source state",
        "test_file_sha256": "test file content",
        "hermetic_version": "Hermetic version",
        "pytest_version": "pytest version",
    }
    for key, label in strict_fields.items():
        expected = recorded.get(key)
        if expected is not None and expected != current.get(key):
            blockers.append(f"{label} differs from the recording")

    # An explicit recorded TZ can be applied before user code runs. With no TZ
    # override, the host zone is an ambient input and must already match.
    if recorded.get("tz_env") is None:
        if recorded.get("tzname") is not None and recorded.get("tzname") != current.get("tzname"):
            blockers.append("host timezone differs and the recording had no TZ override")
        if current.get("tz_env") is not None:
            blockers.append("current TZ override was absent from the recording")
    return blockers


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
        self._sequence: list[str] = []
        self._overflow: set[str] = set()
        self._threads: dict[str, set[int]] = {}
        self._thread_names: dict[int, str] = {}
        self._recording_thread = threading.get_ident()
        self._random_state: list | None = None
        self._random_state_after: list | None = None
        self._fingerprint = collect_fingerprint(test_id)
        self._lock = threading.Lock()

    def record_event(self, source: str, value: Any) -> None:
        with self._lock:
            threads = self._threads.setdefault(source, set())
            ident = threading.get_ident()
            threads.add(ident)
            self._thread_names[ident] = threading.current_thread().name
            queue = self._events.setdefault(source, [])
            if len(queue) >= self._cap:
                self._overflow.add(source)
                return
            queue.append(value)
            self._sequence.append(source)

    def set_random_state(self, serialized_state: list) -> None:
        self._random_state = serialized_state

    def set_random_state_after(self, serialized_state: list) -> None:
        self._random_state_after = serialized_state

    def as_dict(self) -> dict[str, Any]:
        all_event_threads = set().union(*self._threads.values()) if self._threads else set()
        concurrency_unfaithful = (
            sorted(self._threads)
            if len(all_event_threads) > 1
            or any(ident != self._recording_thread for ident in all_event_threads)
            else []
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
            "random_state_after": self._random_state_after,
            "events": self._events,
            "sequence": self._sequence,
            "counts": {source: len(q) for source, q in self._events.items()},
            "overflow": sorted(self._overflow),
            "concurrency_unfaithful": concurrency_unfaithful,
        }

    def write(self) -> Path:
        """Atomically write the journal (gzip when the path ends in .gz)."""
        payload = json.dumps(self.as_dict(), separators=(",", ":")).encode()
        if self.path.name.endswith(".gz"):
            payload = gzip.compress(payload, mtime=0)
        return _atomic_write_private(self.path, payload)


class JournalReader:
    """Loads and validates a journal for replay."""

    def __init__(self, data: dict[str, Any], path: Path) -> None:
        self.path = path
        if data.get("format") != FORMAT:
            raise ReplayMismatch(f"hermetic: {path} is not a hermetic journal")
        self.version = data.get("version")
        if self.version not in SUPPORTED_VERSIONS:
            raise ReplayMismatch(
                f"hermetic: {path} has an unsupported journal version; this "
                f"hermetic reads versions {sorted(SUPPORTED_VERSIONS)}"
            )
        self.test: str | None = data.get("test")
        self.config: dict[str, Any] = data.get("config") or {}
        self.fingerprint: dict[str, Any] = data.get("fingerprint") or {}
        self.random_state: list | None = data.get("random_state")
        self.random_state_after: list | None = data.get("random_state_after")
        self.events: dict[str, list[Any]] = data.get("events") or {}
        sequence = data.get("sequence")
        self.sequence: list[str] | None = sequence if isinstance(sequence, list) else None
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
            for message in fingerprint_warnings(
                self.fingerprint, collect_fingerprint(self.test)
            )
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
        if self.sequence is None:
            warnings.append(
                "hermetic replay: this legacy journal has no global event sequence; "
                "cross-source ordering cannot be verified"
            )
        if self.random_state is not None and self.random_state_after is None:
            warnings.append(
                "hermetic replay: this legacy journal has no final random state; "
                "under-consumption of the global random stream cannot be verified"
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

    def strict_blockers(self) -> list[str]:
        """Conditions that make an exact strict replay impossible."""
        blockers: list[str] = []
        if self.overflow:
            blockers.append(f"event-cap overflow for {sorted(self.overflow)!r}")
        if self.concurrency_unfaithful:
            blockers.append(
                "events recorded across threads for "
                f"{sorted(self.concurrency_unfaithful)!r}"
            )
        blockers.extend(
            fingerprint_blockers(
                self.fingerprint,
                collect_fingerprint(self.test),
            )
        )
        return blockers


class ReplaySequence:
    """Enforce the global order and complete consumption of journal events."""

    def __init__(
        self,
        expected: list[str] | None,
        *,
        strict: bool,
        on_fallback,
    ) -> None:
        self._expected = list(expected) if expected is not None else None
        self._index = 0
        self._strict = strict
        self._on_fallback = on_fallback
        self._disabled = expected is None

    def consume(self, source: str) -> None:
        if self._disabled or self._expected is None:
            return
        if self._index >= len(self._expected):
            if self._strict:
                raise ReplayExhausted(source, self._index)
            self._disabled = True
            self._on_fallback("event sequence")
            return
        expected = self._expected[self._index]
        if source != expected:
            if self._strict:
                raise ReplayMismatch(
                    "hermetic: replay diverged at global event "
                    f"#{self._index + 1}: expected source {expected!r}, "
                    f"observed {source!r}"
                )
            self._disabled = True
            self._on_fallback("event sequence")
            return
        self._index += 1

    def assert_consumed(self) -> None:
        if (
            self._strict
            and not self._disabled
            and self._expected is not None
            and self._index != len(self._expected)
        ):
            remaining = len(self._expected) - self._index
            next_source = self._expected[self._index]
            raise ReplayMismatch(
                "hermetic: replay ended before consuming all recorded events "
                f"({remaining} remain; next source is {next_source!r})"
            )
