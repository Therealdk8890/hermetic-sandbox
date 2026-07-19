"""An ordered, reversible patch stack.

Every mutation the sandbox makes to the process (module attributes, environment,
cwd, ...) is registered here so that teardown restores everything in exact
reverse order, and a failure halfway through setup rolls back the part that was
already applied.
"""

from __future__ import annotations

from typing import Any, Callable

_MISSING = object()


class PatchSet:
    """Collects undo actions and runs them in reverse order."""

    def __init__(self) -> None:
        self._undo: list[Callable[[], None]] = []

    def setattr(self, obj: Any, name: str, value: Any) -> None:
        """Set ``obj.name = value``, remembering the original for undo."""
        original = getattr(obj, name, _MISSING)
        if original is _MISSING:
            def undo() -> None:
                try:
                    delattr(obj, name)
                except AttributeError:
                    pass
        else:
            def undo() -> None:
                setattr(obj, name, original)
        setattr(obj, name, value)
        self._undo.append(undo)

    def setitem(self, mapping: Any, key: Any, value: Any) -> None:
        """Set ``mapping[key] = value``, remembering the original for undo."""
        original = mapping.get(key, _MISSING)
        if original is _MISSING:
            def undo() -> None:
                mapping.pop(key, None)
        else:
            def undo() -> None:
                mapping[key] = original
        mapping[key] = value
        self._undo.append(undo)

    def delitem(self, mapping: Any, key: Any) -> None:
        """Delete ``mapping[key]`` (if present), remembering the original for undo."""
        original = mapping.get(key, _MISSING)
        if original is _MISSING:
            return
        def undo() -> None:
            mapping[key] = original
        del mapping[key]
        self._undo.append(undo)

    def add_undo(self, undo: Callable[[], None]) -> None:
        """Register an arbitrary undo callback (e.g. restoring cwd)."""
        self._undo.append(undo)

    def undo_all(self) -> None:
        """Run all undo actions in reverse order.

        Every action runs even if earlier ones raise; the first exception is
        re-raised at the end so teardown bugs are not silently swallowed.
        """
        first_error: BaseException | None = None
        while self._undo:
            undo = self._undo.pop()
            try:
                undo()
            except BaseException as exc:  # noqa: BLE001 - teardown must keep going
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            raise first_error
