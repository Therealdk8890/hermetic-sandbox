"""Time sources and the patched ``time`` module functions.

Three interchangeable sources feed every patched time API:

- :class:`VirtualTimeSource` — deterministic mode. Wall time is frozen except
  when ``sleep``/``advance`` move it; ``monotonic``/``perf_counter`` additionally
  auto-advance by a tiny ``tick`` per reading so elapsed-time code makes
  progress. ``sleep`` advances the timeline instead of blocking.
- :class:`RecordingTimeSource` — record mode. Real clock values flow through and
  each reading is appended to the journal.
- :class:`ReplayTimeSource` — replay mode. Readings come back from the journal's
  per-function queues; ``sleep`` is a no-op because the recorded readings already
  embody however long the original run waited.

Originals are captured at import time so recording/patched wrappers can never
recurse into themselves.
"""

from __future__ import annotations

import threading
import time as _time_module
from datetime import datetime, timezone
from typing import Callable

from ._errors import ReplayExhausted, SandboxError
from ._patch import PatchSet

# Real functions, captured before any sandbox can patch the time module.
REAL_TIME = _time_module.time
REAL_TIME_NS = _time_module.time_ns
REAL_MONOTONIC = _time_module.monotonic
REAL_MONOTONIC_NS = _time_module.monotonic_ns
REAL_PERF_COUNTER = _time_module.perf_counter
REAL_PERF_COUNTER_NS = _time_module.perf_counter_ns
REAL_SLEEP = _time_module.sleep
REAL_LOCALTIME = _time_module.localtime
REAL_GMTIME = _time_module.gmtime
REAL_CTIME = _time_module.ctime
REAL_STRFTIME = _time_module.strftime
REAL_ASCTIME = _time_module.asctime

# Arbitrary but recognizable bases so virtual monotonic/perf_counter values are
# clearly synthetic and never near zero (some code treats 0.0 as "unset").
_MONO_BASE = 1000.0
_PERF_BASE = 2000.0

DEFAULT_NOW = "2020-01-01T00:00:00+00:00"
DEFAULT_TICK = 1e-6
DEFAULT_SPIN_LIMIT = 1_000_000


class TimeSource:
    """Interface consumed by the patched ``time``/``datetime`` functions."""

    def wall(self) -> float:
        raise NotImplementedError

    def monotonic(self) -> float:
        raise NotImplementedError

    def perf_counter(self) -> float:
        raise NotImplementedError

    def sleep(self, seconds: float) -> None:
        raise NotImplementedError

    # Control surface used by sb.clock; every mode supports it so a test that
    # advances the clock behaves consistently under record and replay too.
    def advance(self, seconds: float) -> None:
        raise NotImplementedError

    def set_wall(self, epoch: float) -> None:
        raise NotImplementedError


class VirtualTimeSource(TimeSource):
    """One deterministic timeline behind all clock functions.

    - ``wall()`` is frozen: it moves only via ``sleep``/``advance``/``set_wall``.
    - ``monotonic()``/``perf_counter()`` share the same timeline but additionally
      accumulate ``tick`` seconds per reading, so code measuring elapsed time or
      polling a deadline makes progress instead of dividing by zero.
    - A spin detector counts clock readings since the last ``sleep``/``advance``;
      exceeding ``spin_limit`` raises instead of letting a poll loop hang CI.
    """

    def __init__(
        self,
        start_epoch: float,
        tick: float = DEFAULT_TICK,
        spin_limit: int = DEFAULT_SPIN_LIMIT,
    ) -> None:
        if tick < 0:
            raise ValueError("tick must be >= 0")
        self._start = start_epoch
        self._tick = tick
        self._offset = 0.0  # advanced by sleep/advance only
        self._ticks = 0.0  # accumulated per-reading auto-advance
        self._reads_since_advance = 0
        self._spin_limit = spin_limit
        self._lock = threading.RLock()

    def _count_read(self) -> None:
        self._reads_since_advance += 1
        if self._spin_limit and self._reads_since_advance > self._spin_limit:
            raise SandboxError(
                f"hermetic: the clock was read {self._reads_since_advance:,} times "
                "without any sleep/advance — this looks like a poll loop spinning "
                "against the virtual clock. Fix: call time.sleep() inside the loop, "
                "advance time with sb.clock.advance(), raise tick=, or raise/disable "
                "the detector with spin_limit=."
            )

    def wall(self) -> float:
        with self._lock:
            self._count_read()
            return self._start + self._offset

    def monotonic(self) -> float:
        with self._lock:
            self._count_read()
            value = _MONO_BASE + self._offset + self._ticks
            self._ticks += self._tick
            return value

    def perf_counter(self) -> float:
        with self._lock:
            self._count_read()
            value = _PERF_BASE + self._offset + self._ticks
            self._ticks += self._tick
            return value

    def sleep(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("sleep length must be non-negative")
        with self._lock:
            self._offset += seconds
            self._reads_since_advance = 0

    # -- control surface (exposed via Clock handle) --

    def advance(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("cannot advance the clock backwards")
        with self._lock:
            self._offset += seconds
            self._reads_since_advance = 0

    def set_wall(self, epoch: float) -> None:
        with self._lock:
            self._start = epoch - self._offset
            self._reads_since_advance = 0

    def peek_wall(self) -> float:
        with self._lock:
            return self._start + self._offset


class RecordingTimeSource(TimeSource):
    """Real time, with every reading journaled.

    ``sb.clock.advance``/``set`` layer an offset over the real clock (instead
    of raising) so tests that use the documented clock API keep passing when
    ``--hermetic-record`` is turned on; the journaled readings include the
    offset, keeping the journal self-consistent for replay.
    """

    def __init__(self, record_event: Callable[[str, object], None]) -> None:
        self._record = record_event
        self._offset = 0.0  # advance(): applies to all clocks
        self._wall_shift = 0.0  # set_wall(): wall only, like the virtual source
        self._lock = threading.Lock()

    def wall(self) -> float:
        with self._lock:
            value = REAL_TIME() + self._offset + self._wall_shift
        self._record("time.time", value)
        return value

    def monotonic(self) -> float:
        with self._lock:
            value = REAL_MONOTONIC() + self._offset
        self._record("time.monotonic", value)
        return value

    def perf_counter(self) -> float:
        with self._lock:
            value = REAL_PERF_COUNTER() + self._offset
        self._record("time.perf_counter", value)
        return value

    def sleep(self, seconds: float) -> None:
        # Record mode must behave exactly like production: really sleep.
        REAL_SLEEP(seconds)

    def advance(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("cannot advance the clock backwards")
        with self._lock:
            self._offset += seconds

    def set_wall(self, epoch: float) -> None:
        with self._lock:
            self._wall_shift = epoch - (REAL_TIME() + self._offset)


class ReplayTimeSource(TimeSource):
    """Feeds back journaled readings in order, one queue per function."""

    def __init__(
        self,
        queues: dict[str, list[float]],
        fallback: VirtualTimeSource,
        strict: bool,
        on_fallback: Callable[[str], None],
        on_event: Callable[[str], None] | None = None,
    ) -> None:
        self._queues = {name: iter(values) for name, values in queues.items()}
        self._totals = {name: len(values) for name, values in queues.items()}
        self._consumed: dict[str, int] = {}
        self._fallback = fallback
        self._strict = strict
        self._on_fallback = on_fallback  # warns (once per source) on fallback
        self._on_event = on_event
        self._lock = threading.Lock()

    def _next(self, source: str, fallback_value: Callable[[], float]) -> float:
        if self._on_event is not None:
            self._on_event(source)
        with self._lock:
            it = self._queues.get(source)
            if it is not None:
                try:
                    value = next(it)
                except StopIteration:
                    pass
                else:
                    self._consumed[source] = self._consumed.get(source, 0) + 1
                    return value
        if self._strict:
            raise ReplayExhausted(source, self._consumed.get(source, 0))
        self._on_fallback(source)
        return fallback_value()

    def assert_consumed(self) -> None:
        """Fail strict replay when recorded clock events were skipped."""
        if not self._strict:
            return
        leftovers = {
            source: total - self._consumed.get(source, 0)
            for source, total in self._totals.items()
            if total != self._consumed.get(source, 0)
        }
        if leftovers:
            raise ReplayExhausted(
                "unconsumed clock events "
                + ", ".join(f"{source}={count}" for source, count in sorted(leftovers.items())),
                sum(self._consumed.values()),
            )

    def wall(self) -> float:
        return self._next("time.time", self._fallback.wall)

    def monotonic(self) -> float:
        return self._next("time.monotonic", self._fallback.monotonic)

    def perf_counter(self) -> float:
        return self._next("time.perf_counter", self._fallback.perf_counter)

    def sleep(self, seconds: float) -> None:
        # The recorded readings already reflect the original run's waiting;
        # sleeping for real would only slow the replay down.
        return None

    def advance(self, seconds: float) -> None:
        # The recorded run's advances are already baked into its journaled
        # readings; replaying the advance again would double-apply it.
        return None

    def set_wall(self, epoch: float) -> None:
        return None


class Clock:
    """User-facing clock control handle (``sb.clock``)."""

    def __init__(self, source: TimeSource | None) -> None:
        self._source = source

    def _require(self) -> TimeSource:
        if self._source is None:
            raise SandboxError(
                "sb.clock is unavailable with clock='off' — the sandbox is not "
                "patching time at all"
            )
        return self._source

    def now(self) -> datetime:
        """Current wall time as an aware UTC datetime.

        Deterministic mode peeks without ticking; record/replay modes route
        through the journaled reading stream so both stay aligned.
        """
        source = self._require()
        if isinstance(source, VirtualTimeSource):
            return datetime.fromtimestamp(source.peek_wall(), tz=timezone.utc)
        return datetime.fromtimestamp(source.wall(), tz=timezone.utc)

    def advance(self, seconds: float) -> None:
        """Move the timeline forward by ``seconds``."""
        self._require().advance(seconds)

    def set(self, when: datetime | int | float | str) -> None:
        """Jump the wall clock to ``when`` (datetime, epoch seconds, or ISO string)."""
        self._require().set_wall(parse_start_time(when))

    # freezegun muscle memory
    move_to = set


def parse_start_time(value: datetime | int | float | str) -> float:
    """Normalize a user-supplied start time to epoch seconds (UTC)."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.timestamp()
    if isinstance(value, bool):
        raise TypeError(f"cannot interpret {value!r} as a start time")
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    raise TypeError(f"cannot interpret {value!r} as a start time")


def install_time_patches(patches: PatchSet, source: TimeSource) -> None:
    """Point the ``time`` module's clock functions at ``source``.

    ``localtime``/``gmtime``/``ctime``/``strftime``/``asctime`` read the C-level
    clock internally when called without an argument, so they get wrappers that
    inject the virtual time; with an explicit argument they are pure conversions
    and pass straight through to the originals.
    """
    mod = _time_module

    patches.setattr(mod, "time", lambda: source.wall())
    patches.setattr(mod, "time_ns", lambda: int(source.wall() * 1e9))
    patches.setattr(mod, "monotonic", lambda: source.monotonic())
    patches.setattr(mod, "monotonic_ns", lambda: int(source.monotonic() * 1e9))
    patches.setattr(mod, "perf_counter", lambda: source.perf_counter())
    patches.setattr(mod, "perf_counter_ns", lambda: int(source.perf_counter() * 1e9))
    patches.setattr(mod, "sleep", lambda seconds: source.sleep(seconds))

    def localtime(secs: float | None = None):
        return REAL_LOCALTIME(source.wall() if secs is None else secs)

    def gmtime(secs: float | None = None):
        return REAL_GMTIME(source.wall() if secs is None else secs)

    def ctime(secs: float | None = None) -> str:
        return REAL_CTIME(source.wall() if secs is None else secs)

    # Unlike localtime/gmtime/ctime, the real strftime/asctime reject an
    # explicit None — only an *omitted* argument means "current time" — so
    # these two use a sentinel to preserve that TypeError.
    _omitted = object()

    def strftime(fmt: str, t=_omitted) -> str:
        return REAL_STRFTIME(fmt, REAL_LOCALTIME(source.wall()) if t is _omitted else t)

    def asctime(t=_omitted) -> str:
        return REAL_ASCTIME(REAL_LOCALTIME(source.wall()) if t is _omitted else t)

    patches.setattr(mod, "localtime", localtime)
    patches.setattr(mod, "gmtime", gmtime)
    patches.setattr(mod, "ctime", ctime)
    patches.setattr(mod, "strftime", strftime)
    patches.setattr(mod, "asctime", asctime)
