"""hermetic — one context manager that makes a block of code deterministic.

Frozen time, seeded randomness (uuid4/secrets included), blocked network and
optionally an isolated filesystem — all keyed to a single seed you can replay.
Plus record/replay: capture the nondeterminism from a failing CI run as a
journal artifact and feed it back locally.

    import hermetic

    with hermetic.sandbox(seed=42) as sb:
        ...                      # deterministic

    with hermetic.sandbox(record="journal.json.gz"):
        ...                      # real values, journaled

    with hermetic.sandbox(replay="journal.json.gz"):
        ...                      # the recorded run, again

Not a security boundary: code inside the sandbox can trivially escape it
(ctypes, subprocess, C extensions). It is a determinism tool for tests.
"""

from __future__ import annotations

import os
from typing import Any, Iterable, Mapping

from ._clock import DEFAULT_NOW, DEFAULT_SPIN_LIMIT, DEFAULT_TICK
from ._errors import (
    NetworkBlockedError,
    ReplayError,
    ReplayExhausted,
    ReplayMismatch,
    SandboxActiveError,
    SandboxError,
)
from ._sandbox import Sandbox, SandboxHandle, current

__version__ = "0.1.0"

__all__ = [
    "sandbox",
    "current",
    "Sandbox",
    "SandboxHandle",
    "SandboxError",
    "SandboxActiveError",
    "NetworkBlockedError",
    "ReplayError",
    "ReplayExhausted",
    "ReplayMismatch",
    "__version__",
]


def sandbox(
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
) -> Sandbox:
    """Create a hermetic sandbox (context manager and decorator).

    Args:
        seed: Master seed for every determinized subsystem. ``None`` draws a
            fresh seed from real entropy in deterministic mode; it is exposed
            as ``sb.seed`` so a failure can always be reproduced. In record
            mode nothing is determinized, so ``sb.seed`` stays ``None`` unless
            a seed is passed (the journal file is the repro artifact; a passed
            seed is recorded and keys ``strict_replay=False`` fallbacks).
        now: Virtual wall-clock start (ISO string, datetime, or epoch seconds).
        tick: Auto-advance (seconds) applied to ``monotonic``/``perf_counter``
            per reading so elapsed-time code makes progress. Wall time stays
            frozen except for ``time.sleep``/``sb.clock.advance``. ``0`` freezes
            everything.
        clock: ``"virtual"`` or ``"off"`` (leave all clocks real — required for
            asyncio tests that await sleeps/timeouts; see README).
        rng: ``"all"`` (seed ``random`` + deterministic ``os.urandom``, covering
            ``uuid.uuid4`` and ``secrets``), ``"seed"`` (only the global
            ``random`` instance), or ``"off"``.
        network: ``"block"`` (default), ``"off"`` (leave the network alone), or
            an iterable of allowlist entries like ``"api.example.com:443"``.
        allow_loopback: Permit localhost/127.0.0.0/8/::1 while blocking.
        allow_unix: Permit unix-domain sockets while blocking.
        fs: ``"off"`` (default) or ``"isolate"`` (fresh tempdir for
            cwd/HOME/TMPDIR, deleted on exit).
        chdir: When isolating, also move the working directory (default True).
        env: Environment overrides; a value of ``None`` unsets the variable.
            The full environment is restored on exit either way.
        scrub_env: Drop everything but a minimal safe allowlist first.
        record: Write a journal of the intercepted nondeterminism to this path
            (gzip when it ends in ``.gz``). Real values flow through.
        replay: Feed a recorded journal back. The journal's configuration
            overrides ``clock``/``rng``/``network``/``fs`` so queues line up.
        strict_replay: Raise :class:`ReplayExhausted`/:class:`ReplayMismatch`
            when the code path diverges from the journal; ``False`` warns and
            falls back to deterministic values.
        deep_datetime: Also rewrite ``from datetime import datetime`` references
            in already-imported modules (freezegun-style scan).
        spin_limit: Clock readings allowed without a ``sleep``/``advance``
            before the spin detector raises (0 disables).

    Returns:
        A :class:`Sandbox` — use ``with sandbox(...) as sb:`` or stack it as a
        decorator. ``sb`` is a :class:`SandboxHandle` with ``.seed``,
        ``.clock`` (advance/set), ``.fs`` paths, ``.real`` escape hatches and
        ``.allow_network()``.
    """
    return Sandbox(
        seed,
        now=now,
        tick=tick,
        clock=clock,
        rng=rng,
        network=network,
        allow_loopback=allow_loopback,
        allow_unix=allow_unix,
        fs=fs,
        chdir=chdir,
        env=env,
        scrub_env=scrub_env,
        record=record,
        replay=replay,
        strict_replay=strict_replay,
        deep_datetime=deep_datetime,
        spin_limit=spin_limit,
    )
