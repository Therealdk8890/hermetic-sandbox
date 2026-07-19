"""The sandbox itself: one context manager (and decorator) that composes the
clock, randomness, network, filesystem and environment controls, keyed to a
single seed — plus record/replay of the intercepted nondeterminism.

Modes
-----
- **deterministic** (default): everything derived from ``seed``.
- **record** (``record=path``): nothing is determinized — real values flow
  through and are journaled, so a failing CI run can be replayed later.
- **replay** (``replay=path``): the journal's values are fed back in order;
  its recorded configuration (clock/rng/network/fs) overrides the arguments
  so the queues line up with the recorded code path.

Sandboxes are process-global (they patch module state) and therefore do not
nest; sequential reuse of one instance — including as a decorator — creates
fresh state per entry.
"""

from __future__ import annotations

import functools
import inspect
import os
import random as _random_module
import threading
import time as _time_module
import uuid as _uuid_module
import warnings
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from . import _datetimes
from ._clock import (
    DEFAULT_NOW,
    DEFAULT_SPIN_LIMIT,
    DEFAULT_TICK,
    REAL_MONOTONIC,
    REAL_PERF_COUNTER,
    REAL_SLEEP,
    REAL_TIME,
    Clock,
    RecordingTimeSource,
    ReplayTimeSource,
    TimeSource,
    VirtualTimeSource,
    install_time_patches,
    parse_start_time,
)
from ._env import install_env_patches
from ._errors import SandboxActiveError, SandboxError
from ._fs import FsIsolation, install_fs_patches
from ._journal import JournalReader, JournalWriter
from ._net import NetworkPolicy, install_network_patches
from ._patch import PatchSet
from ._random import (
    REAL_OS_URANDOM,
    DeterministicEntropy,
    RecordingEntropy,
    ReplayEntropy,
    derive_seed,
    deserialize_random_state,
    entropy_seed,
    install_rng_patches,
    serialize_random_state,
    snapshot_and_restore_random_state,
)

_active_lock = threading.Lock()
_active_handle: "SandboxHandle | None" = None


def current() -> "SandboxHandle | None":
    """The handle of the currently active sandbox, or None."""
    return _active_handle


class Real:
    """Escape hatches to the un-patched world (``sb.real``)."""

    time = staticmethod(REAL_TIME)
    monotonic = staticmethod(REAL_MONOTONIC)
    perf_counter = staticmethod(REAL_PERF_COUNTER)
    sleep = staticmethod(REAL_SLEEP)
    urandom = staticmethod(REAL_OS_URANDOM)

    @staticmethod
    def uuid4() -> _uuid_module.UUID:
        return _uuid_module.UUID(bytes=REAL_OS_URANDOM(16), version=4)


class SandboxHandle:
    """What ``with hermetic.sandbox(...) as sb`` gives you."""

    real = Real()

    def __init__(
        self,
        *,
        seed: int | None,
        mode: str,
        clock: Clock,
        fs: FsIsolation | None,
        policy: NetworkPolicy | None,
        journal_path: Path | None,
        replay_warnings: list[str],
    ) -> None:
        self.seed = seed
        self.mode = mode
        self.clock = clock
        self.fs = fs
        self.journal_path = journal_path
        self.replay_warnings = replay_warnings
        self._policy = policy

    def allow_network(self, entry: str) -> None:
        """Add ``"host"`` or ``"host:port"`` to the network allowlist at runtime."""
        if self._policy is None:
            raise SandboxError(
                "network is not patched in this sandbox (network='off'), "
                "so there is no allowlist to extend"
            )
        self._policy.allow(entry)

    def __repr__(self) -> str:
        return f"<hermetic sandbox mode={self.mode} seed={self.seed}>"


class _EnterState:
    """Everything created by one __enter__, torn down by the matching __exit__."""

    def __init__(self) -> None:
        self.patches = PatchSet()
        self.handle: SandboxHandle | None = None
        self.writer: JournalWriter | None = None


class Sandbox:
    """Configured sandbox; context manager and decorator. See :func:`hermetic.sandbox`."""

    def __init__(
        self,
        seed: int | None = None,
        *,
        now: Any = DEFAULT_NOW,
        tick: float = DEFAULT_TICK,
        clock: str = "virtual",
        rng: str = "all",
        network: str | Iterable[str] = "block",
        allow_loopback: bool = True,
        allow_unix: bool = True,
        fs: str = "off",
        chdir: bool = True,
        env: Mapping[str, str | None] | None = None,
        scrub_env: bool = False,
        record: str | os.PathLike[str] | None = None,
        replay: str | os.PathLike[str] | None = None,
        strict_replay: bool = True,
        deep_datetime: bool = True,
        spin_limit: int = DEFAULT_SPIN_LIMIT,
        test_id: str | None = None,
    ) -> None:
        if clock not in ("virtual", "off"):
            raise SandboxError(f"clock must be 'virtual' or 'off', not {clock!r}")
        if rng not in ("all", "seed", "off"):
            raise SandboxError(f"rng must be 'all', 'seed' or 'off', not {rng!r}")
        if fs == "fake":
            raise SandboxError(
                "fs='fake' is not part of hermetic v0.1 — compose pyfakefs with "
                "fs='off' instead (see README)"
            )
        if fs not in ("off", "isolate"):
            raise SandboxError(f"fs must be 'off' or 'isolate', not {fs!r}")
        if record is not None and replay is not None:
            raise SandboxError("record= and replay= are mutually exclusive")
        self._network_mode, self._allowlist = _normalize_network(network)
        self.seed = seed
        self.now = now
        self.tick = tick
        self.clock_mode = clock
        self.rng_mode = rng
        self.allow_loopback = allow_loopback
        self.allow_unix = allow_unix
        self.fs_mode = fs
        self.chdir = chdir
        self.env = dict(env) if env else None
        self.scrub_env = scrub_env
        self.record = record
        self.replay = replay
        self.strict_replay = strict_replay
        self.deep_datetime = deep_datetime
        self.spin_limit = spin_limit
        self.test_id = test_id
        self._state: _EnterState | None = None

    # -- context manager --

    def __enter__(self) -> SandboxHandle:
        global _active_handle
        state = _EnterState()
        with _active_lock:
            if _active_handle is not None:
                raise SandboxActiveError(
                    "a hermetic sandbox is already active in this process; "
                    "sandboxes do not nest"
                )
            if self._state is not None:
                raise SandboxActiveError("this sandbox instance is already entered")
            try:
                handle = self._enter(state)
            except BaseException:
                _silent_undo(state.patches)
                raise
            state.handle = handle
            self._state = state
            _active_handle = handle
        for message in handle.replay_warnings:
            warnings.warn(message, stacklevel=2)
        return handle

    def _enter(self, state: _EnterState) -> SandboxHandle:
        patches = state.patches
        mode = "replay" if self.replay else "record" if self.record else "deterministic"

        # Resolve journal paths before any chdir can change what they mean.
        reader: JournalReader | None = None
        replay_warnings: list[str] = []
        if mode == "replay":
            reader = JournalReader.load(self.replay)  # type: ignore[arg-type]
            replay_warnings = reader.faithfulness_warnings()
            _warn_on_test_mismatch(reader, replay_warnings)
            config = dict(reader.config)
        else:
            config = None  # set below for record

        # Effective settings: replay uses the journal's recorded configuration
        # for everything that shapes the recorded code path.
        if reader is not None:
            clock_mode = config.get("clock", "virtual")
            rng_mode = config.get("rng", "all")
            tick = config.get("tick", DEFAULT_TICK)
            now_epoch = config.get("now", parse_start_time(DEFAULT_NOW))
            network_mode, allowlist = _normalize_network(config.get("network", "block"))
            fs_mode = config.get("fs", "off")
            chdir = config.get("chdir", True)
            allow_loopback = config.get("allow_loopback", self.allow_loopback)
            allow_unix = config.get("allow_unix", self.allow_unix)
            scrub_env = config.get("scrub_env", self.scrub_env)
            # Journal seed first (keyed the recorded run's fallbacks), then the
            # caller's, then a fresh one — so strict_replay=False fallbacks are
            # reproducible whenever any seed is known.
            seed = config.get("seed")
            if seed is None:
                seed = self.seed
            if seed is None:
                seed = entropy_seed() & 0xFFFFFFFF
        else:
            clock_mode = self.clock_mode
            rng_mode = self.rng_mode
            tick = self.tick
            now_epoch = parse_start_time(self.now)
            network_mode, allowlist = self._network_mode, list(self._allowlist)
            fs_mode = self.fs_mode
            chdir = self.chdir
            allow_loopback = self.allow_loopback
            allow_unix = self.allow_unix
            scrub_env = self.scrub_env
            seed = self.seed
            if seed is None and mode == "deterministic":
                seed = entropy_seed() & 0xFFFFFFFF

        if (
            mode == "deterministic"
            and rng_mode == "all"
            and network_mode == "block"
            and allowlist
        ):
            warnings.warn(
                "hermetic: rng='all' makes os.urandom deterministic while the "
                "network allowlist permits real connections — a real TLS handshake "
                "fed deterministic 'entropy' is a debugging (and hygiene) hazard. "
                "Consider rng='seed' for tests that talk to real services.",
                stacklevel=3,
            )

        if mode == "record":
            config = {
                "clock": clock_mode,
                "now": now_epoch,
                "tick": tick,
                "rng": rng_mode,
                "network": allowlist if network_mode == "block" and allowlist else network_mode,
                "allow_loopback": allow_loopback,
                "allow_unix": allow_unix,
                "fs": fs_mode,
                "chdir": chdir,
                "scrub_env": scrub_env,
                # The caller's seed (the pytest plugin always derives one) keys
                # replay fallbacks; record mode itself determinizes nothing.
                "seed": seed,
            }
            state.writer = JournalWriter(self.record, config, test_id=self.test_id)  # type: ignore[arg-type]

        # 1. Environment (registered first → blanket restore runs last; the
        # tzset registered before it therefore runs after it on teardown,
        # re-syncing the C timezone globals with the restored environment).
        if reader is not None and hasattr(_time_module, "tzset"):
            patches.add_undo(_time_module.tzset)
        install_env_patches(patches, self.env, scrub_env)
        if reader is not None:
            _apply_recorded_tz(patches, reader)

        # 2. Filesystem.
        isolation: FsIsolation | None = None
        if fs_mode == "isolate":
            isolation = install_fs_patches(patches, chdir=chdir)

        # 3. Randomness.
        entropy = None
        state_for_global = None
        seed_for_global = None
        if rng_mode != "off":
            if mode == "deterministic":
                seed_for_global = seed
                if rng_mode == "all":
                    entropy = DeterministicEntropy(derive_seed(seed, "urandom"))
            elif mode == "record":
                # Not determinized; capture the state so replay can restore it.
                assert state.writer is not None
                state.writer.set_random_state(
                    serialize_random_state(_random_module.getstate())
                )
                snapshot_and_restore_random_state(patches)
                if rng_mode == "all":
                    entropy = RecordingEntropy(state.writer.record_event)
            else:  # replay
                if reader.random_state is not None:
                    state_for_global = deserialize_random_state(reader.random_state)
                if rng_mode == "all":
                    entropy = ReplayEntropy(
                        list(reader.events.get("urandom", [])),
                        DeterministicEntropy(derive_seed(seed, "urandom")),
                        self.strict_replay,
                        _fallback_warner(),
                    )
            install_rng_patches(
                patches, rng_mode, entropy, seed_for_global, state_for_global
            )

        # 4. Clock (+ datetime).
        source: TimeSource | None = None
        if clock_mode == "virtual":
            if mode == "deterministic":
                source = VirtualTimeSource(now_epoch, tick, self.spin_limit)
            elif mode == "record":
                assert state.writer is not None
                source = RecordingTimeSource(state.writer.record_event)
            else:
                source = ReplayTimeSource(
                    {
                        name: list(reader.events.get(name, []))
                        for name in ("time.time", "time.monotonic", "time.perf_counter")
                    },
                    VirtualTimeSource(now_epoch, tick, self.spin_limit),
                    self.strict_replay,
                    _fallback_warner(),
                )
            install_time_patches(patches, source)
            _datetimes.install_datetime_patches(patches, self.deep_datetime)
            _datetimes.set_active_source(patches, source)

        # 5. Network.
        policy: NetworkPolicy | None = None
        if network_mode == "block":
            policy = NetworkPolicy(allowlist, allow_loopback, allow_unix)
            install_network_patches(patches, policy)

        return SandboxHandle(
            seed=seed,
            mode=mode,
            clock=Clock(source),
            fs=isolation,
            policy=policy,
            journal_path=state.writer.path if state.writer else None,
            replay_warnings=replay_warnings,
        )

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        global _active_handle
        state = self._state
        if state is None:
            raise SandboxError("sandbox exited without being entered")
        write_error: BaseException | None = None
        if state.writer is not None:
            try:
                state.writer.write()
            except BaseException as exc:  # noqa: BLE001 - reported below
                write_error = exc
        try:
            state.patches.undo_all()
        except BaseException:
            if exc_type is None:
                raise
            # The test is already failing; don't let teardown mask its error.
            warnings.warn(
                "hermetic: an error occurred while tearing down the sandbox "
                "(suppressed to preserve the original test failure)",
                stacklevel=2,
            )
        finally:
            with _active_lock:
                _active_handle = None
                self._state = None
        if write_error is not None:
            if exc_type is None:
                raise SandboxError(
                    f"hermetic: failed to write journal: {write_error}"
                ) from write_error
            warnings.warn(
                f"hermetic: failed to write journal: {write_error}", stacklevel=2
            )

    # -- decorator --

    def __call__(self, fn: Callable) -> Callable:
        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                with self:
                    return await fn(*args, **kwargs)
            return async_wrapper

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            with self:
                return fn(*args, **kwargs)
        return wrapper


def _normalize_network(value: str | Iterable[str]) -> tuple[str, list[str]]:
    if isinstance(value, str):
        if value == "block":
            return "block", []
        if value in ("off", "allow"):
            return "off", []
        raise SandboxError(
            f"network must be 'block', 'off', or an iterable of allowlist "
            f"entries, not {value!r}"
        )
    return "block", [str(entry) for entry in value]


def _silent_undo(patches: PatchSet) -> None:
    try:
        patches.undo_all()
    except BaseException:
        pass


def _fallback_warner() -> Callable[[str], None]:
    warned: set[str] = set()

    def warn(source: str) -> None:
        if source not in warned:
            warned.add(source)
            warnings.warn(
                f"hermetic replay: journal exhausted for {source!r}; falling back "
                "to deterministic values (strict_replay=False)",
                stacklevel=3,
            )
    return warn


def _warn_on_test_mismatch(reader: JournalReader, out: list[str]) -> None:
    running = os.environ.get("PYTEST_CURRENT_TEST", "")
    if reader.test and running and reader.test not in running:
        out.append(
            f"hermetic replay: this journal was recorded for {reader.test!r} but "
            f"is being replayed in {running.split(' ')[0]!r} — values will almost "
            "certainly be fed to the wrong consumers"
        )


def _apply_recorded_tz(patches: PatchSet, reader: JournalReader) -> None:
    """Make local-time conversions match the recording machine (POSIX only)."""
    if not hasattr(_time_module, "tzset"):
        return
    recorded_tz = reader.fingerprint.get("tz_env")
    if recorded_tz == os.environ.get("TZ"):
        return
    previous = os.environ.get("TZ")

    def undo() -> None:
        if previous is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = previous
        _time_module.tzset()

    if recorded_tz is None:
        # Recorded machine had no TZ override; we can't know its zone files.
        return
    os.environ["TZ"] = recorded_tz
    _time_module.tzset()
    patches.add_undo(undo)
