"""Exception types for hermetic."""

from __future__ import annotations


class SandboxError(Exception):
    """Base class for all hermetic errors."""


class SandboxActiveError(SandboxError):
    """A sandbox is already active in this process; sandboxes do not nest."""


class NetworkBlockedError(SandboxError, ConnectionRefusedError):
    """A network operation was blocked by the sandbox.

    Inherits ConnectionRefusedError so code with broad ``except OSError`` /
    ``except ConnectionError`` handlers degrades the way a real refused
    connection would, while still being catchable as a hermetic error.
    """

    def __init__(self, address: object, reason: str = "network is blocked inside hermetic.sandbox()"):
        self.address = address
        super().__init__(
            f"hermetic: blocked connection to {address!r} ({reason}). "
            "Pass network='off' or an allowlist like network=['api.example.com:443'] "
            "to permit it."
        )


class ReplayError(SandboxError):
    """Base class for record/replay divergence errors."""


class ReplayExhausted(ReplayError):
    """The code under replay consumed more values from a source than were recorded."""

    def __init__(self, source: str, consumed: int):
        self.source = source
        self.consumed = consumed
        super().__init__(
            f"hermetic: replay journal exhausted for source {source!r} after "
            f"{consumed} value(s). The code path diverged from the recorded run "
            "(it asked for more nondeterminism than was captured). "
            "Pass strict_replay=False to fall back to deterministic values instead."
        )


class ReplayMismatch(ReplayError):
    """The journal does not match this test/config (wrong journal, wrong version, ...)."""
