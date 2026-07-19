"""Virtual ``datetime.datetime`` / ``datetime.date`` (the freezegun trick).

``datetime.datetime`` is a C type whose classmethods cannot be monkeypatched,
so the sandbox swaps the class in the ``datetime`` module for a subclass whose
``now``/``utcnow``/``today`` read the active :class:`~hermetic._clock.TimeSource`.

Two properties keep this safe:

- The fakes *delegate to real behavior whenever no sandbox is active*, so a
  module that grabbed a reference to :class:`FakeDatetime` during a sandbox
  keeps working after the sandbox exits.
- A metaclass ``__instancecheck__`` accepts real instances, so
  ``isinstance(real_dt, datetime.datetime)`` stays true while the swap is in
  place (C code and pre-swap modules still produce real instances).

With ``deep_datetime=True`` (the default) the sandbox also rewrites references
in already-imported modules that did ``from datetime import datetime`` — the
same ``sys.modules`` scan freezegun performs — and restores them on exit.
"""

from __future__ import annotations

import datetime as _datetime_module
import sys
from datetime import timezone

from ._clock import TimeSource
from ._patch import PatchSet

real_datetime = _datetime_module.datetime
real_date = _datetime_module.date

# The active time source. Set/cleared by the sandbox; None means "delegate to
# real behavior" (which is what makes stale references to the fakes harmless).
_active_source: TimeSource | None = None


def set_active_source(patches: PatchSet, source: TimeSource) -> None:
    global _active_source
    previous = _active_source
    _active_source = source

    def undo() -> None:
        global _active_source
        _active_source = previous

    patches.add_undo(undo)


# The special-cased checks apply ONLY to the fake classes themselves; user
# subclasses defined while the swap is active (class Stamp(datetime.datetime))
# inherit these metaclasses for the life of the process, and must get normal
# type semantics or isinstance dispatch against them is silently corrupted.
class _FakeDateMeta(type):
    def __instancecheck__(cls, obj: object) -> bool:
        if cls is FakeDate:
            return isinstance(obj, real_date)
        return type.__instancecheck__(cls, obj)

    def __subclasscheck__(cls, subclass: type) -> bool:
        if cls is FakeDate:
            return issubclass(subclass, real_date)
        return type.__subclasscheck__(cls, subclass)


class _FakeDatetimeMeta(_FakeDateMeta):
    def __instancecheck__(cls, obj: object) -> bool:
        if cls is FakeDatetime:
            return isinstance(obj, real_datetime)
        return type.__instancecheck__(cls, obj)

    def __subclasscheck__(cls, subclass: type) -> bool:
        if cls is FakeDatetime:
            return issubclass(subclass, real_datetime)
        return type.__subclasscheck__(cls, subclass)


# The inactive branches bind the real classmethod descriptors to cls (C
# classmethods have no __func__) so user subclasses keep constructing
# themselves, exactly like the real classes would.
class FakeDate(real_date, metaclass=_FakeDateMeta):
    @classmethod
    def today(cls):
        source = _active_source
        if source is None:
            return real_date.__dict__["today"].__get__(None, cls)()
        # Same semantics as the real today(): the wall timestamp interpreted in
        # the process's local timezone (which the journal fingerprint records).
        return cls.fromtimestamp(source.wall())


class FakeDatetime(real_datetime, metaclass=_FakeDatetimeMeta):
    @classmethod
    def now(cls, tz=None):
        source = _active_source
        if source is None:
            return real_datetime.__dict__["now"].__get__(None, cls)(tz)
        return cls.fromtimestamp(source.wall(), tz)

    @classmethod
    def utcnow(cls):
        source = _active_source
        if source is None:
            return real_datetime.__dict__["utcnow"].__get__(None, cls)()
        return cls.fromtimestamp(source.wall(), timezone.utc).replace(tzinfo=None)

    @classmethod
    def today(cls):
        return cls.now()


# Modules that must never have their datetime references rewritten: ourselves
# (we hold the real classes), and the datetime machinery itself.
_SCAN_SKIP_TOPLEVEL = {"hermetic", "datetime", "_datetime", "_strptime"}


def install_datetime_patches(patches: PatchSet, deep: bool) -> None:
    """Swap datetime/date in the ``datetime`` module (and, if ``deep``, in every
    already-imported module that holds a direct reference)."""
    patches.setattr(_datetime_module, "datetime", FakeDatetime)
    patches.setattr(_datetime_module, "date", FakeDate)
    if not deep:
        return
    for name, module in list(sys.modules.items()):
        if module is None or name.partition(".")[0] in _SCAN_SKIP_TOPLEVEL:
            continue
        try:
            attrs = list(vars(module).items())
        except TypeError:
            continue
        for attr, value in attrs:
            if value is real_datetime:
                patches.setattr(module, attr, FakeDatetime)
            elif value is real_date:
                patches.setattr(module, attr, FakeDate)
