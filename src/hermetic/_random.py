"""Entropy sources and randomness patches.

Two distinct bindings must both be patched for full coverage (verified on
CPython 3.10–3.13):

- ``os.urandom`` — read at call time by ``uuid.uuid4`` and direct callers.
- ``random._urandom`` — ``random.py`` does ``from os import urandom as _urandom``
  at import, and ``random.SystemRandom`` (and therefore everything in
  ``secrets``) draws through that module-global binding, *not* ``os.urandom``.

What cannot be intercepted from Python and is documented as out of scope:
OpenSSL's internal CSPRNG (TLS randomness), C callers of ``_PyOS_URandom``,
``os.getrandom``, and code reading ``/dev/urandom`` directly.
"""

from __future__ import annotations

import hashlib
import os as _os_module
import random as _random_module
from typing import Callable

from ._errors import ReplayExhausted, ReplayMismatch
from ._patch import PatchSet

REAL_OS_URANDOM = _os_module.urandom
REAL_RANDOM_URANDOM = _random_module._urandom  # type: ignore[attr-defined]


def derive_seed(master: int, label: str) -> int:
    """Derive an independent 64-bit stream seed from the master seed."""
    digest = hashlib.sha256(f"hermetic:{master}:{label}".encode()).digest()
    return int.from_bytes(digest[:8], "big")


def entropy_seed() -> int:
    """A fresh master seed from real entropy (used when seed=None)."""
    return int.from_bytes(REAL_OS_URANDOM(8), "big")


class EntropySource:
    """Interface behind the patched ``os.urandom`` / ``random._urandom``."""

    def bytes(self, n: int) -> bytes:
        raise NotImplementedError


class DeterministicEntropy(EntropySource):
    """PRNG-backed byte stream, keyed to a seed derived from the master seed."""

    def __init__(self, seed: int) -> None:
        self._rng = _random_module.Random(seed)

    def bytes(self, n: int) -> bytes:
        return self._rng.randbytes(n)


class RecordingEntropy(EntropySource):
    """Real entropy, with every draw journaled (hex)."""

    def __init__(self, record_event: Callable[[str, object], None]) -> None:
        self._record = record_event

    def bytes(self, n: int) -> bytes:
        value = REAL_OS_URANDOM(n)
        self._record("urandom", value.hex())
        return value


class ReplayEntropy(EntropySource):
    """Feeds back journaled draws in order."""

    def __init__(
        self,
        values: list[str],
        fallback: DeterministicEntropy,
        strict: bool,
        on_fallback: Callable[[str], None],
        on_event: Callable[[str], None] | None = None,
    ) -> None:
        self._values = iter(values)
        self._total = len(values)
        self._consumed = 0
        self._fallback = fallback
        self._strict = strict
        self._on_fallback = on_fallback
        self._on_event = on_event

    def bytes(self, n: int) -> bytes:
        if self._on_event is not None:
            self._on_event("urandom")
        try:
            recorded = bytes.fromhex(next(self._values))
        except StopIteration:
            if self._strict:
                raise ReplayExhausted("urandom", self._consumed) from None
            self._on_fallback("urandom")
            return self._fallback.bytes(n)
        self._consumed += 1
        if len(recorded) != n:
            if self._strict:
                raise ReplayMismatch(
                    f"hermetic: replay diverged — urandom draw #{self._consumed} "
                    f"requested {n} byte(s) but the journal recorded "
                    f"{len(recorded)}. The code path differs from the recorded run."
                )
            self._on_fallback("urandom")
            return self._fallback.bytes(n)
        return recorded

    def assert_consumed(self) -> None:
        """Fail strict replay when recorded entropy draws were skipped."""
        if self._strict and self._consumed != self._total:
            raise ReplayMismatch(
                "hermetic: replay ended before consuming all recorded urandom "
                f"draws ({self._total - self._consumed} remain)"
            )


def snapshot_and_restore_random_state(patches: PatchSet) -> tuple:
    """Snapshot the global ``random`` state and restore it on teardown."""
    state = _random_module.getstate()
    patches.add_undo(lambda: _random_module.setstate(state))
    return state


def install_rng_patches(
    patches: PatchSet,
    mode: str,
    entropy: EntropySource | None,
    seed_for_global: int | None,
    state_for_global: tuple | None = None,
) -> None:
    """Apply the requested randomness controls.

    - The global ``random`` instance is always snapshotted/restored; it is then
      either seeded (deterministic mode), set to a journaled state (replay), or
      left alone (record mode captures its state instead).
    - ``entropy`` (when given, i.e. rng="all") backs both urandom bindings.
    """
    if mode == "off":
        return
    snapshot_and_restore_random_state(patches)
    if seed_for_global is not None:
        _random_module.seed(seed_for_global)
    if state_for_global is not None:
        _random_module.setstate(state_for_global)
    if entropy is not None:
        patches.setattr(_os_module, "urandom", lambda n: entropy.bytes(n))
        patches.setattr(_random_module, "_urandom", lambda n: entropy.bytes(n))


def serialize_random_state(state: tuple) -> list:
    """random.getstate() → JSON-safe structure."""
    version, internal, gauss_next = state
    return [version, list(internal), gauss_next]


def deserialize_random_state(data: list) -> tuple:
    """JSON structure → tuple accepted by random.setstate()."""
    if not isinstance(data, list) or len(data) != 3:
        raise ReplayMismatch("hermetic: journal random_state is malformed")
    version, internal, gauss_next = data
    return (version, tuple(internal), gauss_next)
