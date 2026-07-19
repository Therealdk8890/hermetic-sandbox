"""pytest integration for hermetic.

Surfaces
--------
- ``@pytest.mark.hermetic(**sandbox_kwargs)`` — the marker *configures* a
  sandbox for the test (``off=True`` opts a test out under ``--hermetic-all``).
- ``hermetic_sandbox`` fixture — *accesses* the active sandbox handle, creating
  a default-configured one only when no marker/option did. Marker + fixture
  compose instead of colliding.
- ``--hermetic-seed=N`` — session base seed. Each test's effective seed is
  ``derive(nodeid) XOR base``, so one base seed reproduces any test regardless
  of ordering or xdist distribution (the base propagates to workers).
- ``--hermetic-all`` (or ``hermetic_all = true`` ini) — sandbox every test.
- ``--hermetic-record=DIR`` — journal every sandboxed test; only failing
  attempts are kept (sticky: a later passing retry never deletes them), plus an
  ``index.json`` manifest. Point your CI artifact upload at DIR.
- ``--hermetic-replay=PATH`` — re-run the journaled test with the recorded
  nondeterminism fed back. Other collected tests are deselected automatically.

Failing sandboxed tests get a copy-pasteable repro command in the terminal
summary.
"""

from __future__ import annotations

import hashlib
import os
import shlex
import warnings
from pathlib import Path
from typing import Any

import pytest

from ._errors import SandboxError
from ._journal import JournalReader, write_private_json
from ._random import entropy_seed
from ._sandbox import Sandbox, current

_STASH_STATE = "_hermetic_state"


def _derive_item_seed(base: int, nodeid: str) -> int:
    digest = hashlib.sha256(nodeid.encode()).digest()
    return int.from_bytes(digest[:8], "big") ^ base


class _PluginState:
    def __init__(self, config: pytest.Config) -> None:
        self.config = config
        seed_option = config.getoption("hermetic_seed")
        workerinput = getattr(config, "workerinput", None)
        if seed_option is not None:
            self.base_seed = int(seed_option)
        elif workerinput is not None and "hermetic_base_seed" in workerinput:
            self.base_seed = int(workerinput["hermetic_base_seed"])
        else:
            self.base_seed = entropy_seed() & 0xFFFFFFFF
        self.all_tests = bool(
            config.getoption("hermetic_all") or config.getini("hermetic_all")
        )
        record_dir = config.getoption("hermetic_record")
        self.record_arg = str(record_dir) if record_dir else None
        self.record_dir = Path(record_dir).resolve() if record_dir else None
        replay_path = config.getoption("hermetic_replay")
        self.replay_path = Path(replay_path).resolve() if replay_path else None
        self.replay_reader: JournalReader | None = None
        if self.record_dir is not None and self.replay_path is not None:
            raise pytest.UsageError(
                "--hermetic-record and --hermetic-replay are mutually exclusive"
            )
        if self.replay_path is not None:
            try:
                self.replay_reader = JournalReader.load(self.replay_path)
            except SandboxError as exc:
                raise pytest.UsageError(f"--hermetic-replay: {exc}") from exc
        # nodeid -> attempt counter (rerun plugins re-run the same nodeid)
        self.attempts: dict[str, int] = {}
        # nodeid -> (pending journal path, attempt) awaiting keep/discard
        self.pending: dict[str, tuple[Path, int]] = {}
        # nodeid -> whether any phase of the current attempt failed
        self.attempt_failed: dict[str, bool] = {}
        # entries for index.json / terminal summary
        self.kept: list[dict[str, Any]] = []
        # nodeid -> effective seed, for repro hints
        self.seeds: dict[str, int] = {}
        # A sandbox entered before fixture setup and exited after fixture teardown.
        self.active: dict[str, Sandbox] = {}
        # The first setup/call exception, passed to Sandbox.__exit__ so teardown
        # failures in hermetic itself do not mask the test's original failure.
        self.phase_exc: dict[
            str, tuple[type[BaseException], BaseException, Any]
        ] = {}
        # Marker/config validation historically failed in the call phase. Keep
        # that public pytest outcome while moving valid sandboxes into setup.
        self.deferred_call_errors: dict[str, SandboxError] = {}


def _state(config: pytest.Config) -> _PluginState:
    return config.stash[_state_key]


_state_key = pytest.StashKey[_PluginState]()


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("hermetic")
    group.addoption(
        "--hermetic-seed", dest="hermetic_seed", type=int, default=None,
        help="Base seed for hermetic sandboxes (per-test seed derives from it).",
    )
    group.addoption(
        "--hermetic-all", dest="hermetic_all", action="store_true", default=False,
        help="Run every test inside a hermetic sandbox.",
    )
    group.addoption(
        "--hermetic-record", dest="hermetic_record", default=None, metavar="DIR",
        help="Record nondeterminism journals for sandboxed tests into DIR "
             "(failing attempts are kept; upload DIR as a CI artifact).",
    )
    group.addoption(
        "--hermetic-replay", dest="hermetic_replay", default=None, metavar="PATH",
        help="Replay a recorded journal in its test (other tests are deselected).",
    )
    parser.addini(
        "hermetic_all", "Run every test inside a hermetic sandbox.",
        type="bool", default=False,
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "hermetic(**sandbox_kwargs): run this test inside hermetic.sandbox(). "
        "Use off=True to opt out under --hermetic-all.",
    )
    config.stash[_state_key] = _PluginState(config)


@pytest.hookimpl(optionalhook=True)
def pytest_configure_node(node) -> None:
    # xdist: give every worker the same base seed so repro commands hold.
    node.workerinput["hermetic_base_seed"] = str(_state(node.config).base_seed)


def pytest_report_header(config: pytest.Config) -> list[str]:
    state = _state(config)
    parts = [f"hermetic: base seed {state.base_seed}"]
    if state.all_tests:
        parts.append("sandboxing all tests")
    if state.record_dir is not None:
        parts.append(f"recording journals to {state.record_dir}")
    if state.replay_reader is not None:
        parts.append(f"replaying {state.replay_path}")
    return [", ".join(parts)]


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    state = _state(config)
    reader = state.replay_reader
    if reader is None:
        return
    if reader.test:
        selected = [item for item in items if item.nodeid == reader.test]
        if not selected:
            raise pytest.UsageError(
                f"--hermetic-replay: journal was recorded for {reader.test!r}, "
                "which was not collected. Was the test renamed since the recording? "
                f"(journal git sha: {reader.fingerprint.get('git_sha')})"
            )
        deselected = [item for item in items if item.nodeid != reader.test]
        if deselected:
            config.hook.pytest_deselected(items=deselected)
            items[:] = selected
    elif len(items) != 1:
        raise pytest.UsageError(
            "--hermetic-replay: the journal does not name a test; select exactly "
            f"one test on the command line ({len(items)} collected)"
        )
    for item in items:
        marker = item.get_closest_marker("hermetic")
        if marker is not None and marker.kwargs.get("off", False):
            raise pytest.UsageError(
                f"--hermetic-replay: {item.nodeid!r} is marked "
                "hermetic(off=True); a replay cannot opt out of the sandbox"
            )


def _resolve_kwargs(item: pytest.Item, *, for_fixture: bool) -> dict[str, Any] | None:
    """Sandbox kwargs for this item, or None when it should not be sandboxed.

    The marker configures; ``off=True`` opts out (even when the fixture is
    requested transitively under --hermetic-all). Unmarked items are sandboxed
    when --hermetic-all/replay is active, or when the fixture itself asks.
    """
    marker = item.get_closest_marker("hermetic")
    state = _state(item.config)
    if marker is None:
        if state.all_tests or state.replay_reader is not None or for_fixture:
            return {}
        return None
    if marker.args:
        raise SandboxError(
            "@pytest.mark.hermetic takes keyword arguments only, "
            "e.g. hermetic(seed=7, network='off')"
        )
    kwargs = dict(marker.kwargs)
    if kwargs.pop("off", False):
        if state.replay_reader is not None:
            raise pytest.UsageError(
                f"--hermetic-replay: {item.nodeid!r} is marked "
                "hermetic(off=True); a replay cannot opt out of the sandbox"
            )
        return None
    for reserved in ("record", "replay", "test_id"):
        if reserved in kwargs:
            raise SandboxError(
                f"@pytest.mark.hermetic does not accept {reserved!r}; use the "
                f"--hermetic-{reserved} command line option"
                if reserved != "test_id"
                else "@pytest.mark.hermetic does not accept 'test_id'"
            )
    return kwargs


def _build_sandbox(item: pytest.Item, *, for_fixture: bool = False) -> Sandbox | None:
    state = _state(item.config)
    kwargs = _resolve_kwargs(item, for_fixture=for_fixture)
    if kwargs is None:
        return None
    seed = kwargs.pop("seed", None)
    if seed is None:
        seed = _derive_item_seed(state.base_seed, item.nodeid)
    state.seeds[item.nodeid] = seed

    record: Path | None = None
    replay: Path | None = None
    if state.replay_reader is not None:
        replay = state.replay_path
    elif state.record_dir is not None:
        attempt = state.attempts.get(item.nodeid, 0) + 1
        state.attempts[item.nodeid] = attempt
        digest = hashlib.sha256(item.nodeid.encode()).hexdigest()[:16]
        name = f".pending-journal-{digest}-a{attempt}.json.gz"
        record = state.record_dir / name
        state.pending[item.nodeid] = (record, attempt)
        state.attempt_failed[item.nodeid] = False
    return Sandbox(
        seed,
        record=record,
        replay=replay,
        test_id=item.nodeid,
        **kwargs,
    )


def _requests_fixture(item: pytest.Item) -> bool:
    return "hermetic_sandbox" in getattr(item, "fixturenames", ())


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item: pytest.Item) -> None:
    """Enter before pytest starts fixture setup.

    Using the setup/teardown hooks instead of wrapping only ``pytest_runtest_call``
    keeps one event stream across fixture setup, the test body, and fixture
    teardown. It also creates a fresh sandbox for each protocol attempt, which
    is important for rerun plugins.
    """
    state = _state(item.config)
    if current() is not None:
        # Preserve the prior behavior for callers that deliberately run pytest
        # while an application-owned sandbox is already active.
        return
    if item.nodeid in state.active:
        raise SandboxError(
            f"hermetic: sandbox state for {item.nodeid!r} leaked from a prior attempt"
        )
    state.phase_exc.pop(item.nodeid, None)
    try:
        box = _build_sandbox(item, for_fixture=_requests_fixture(item))
    except SandboxError as exc:
        state.deferred_call_errors[item.nodeid] = exc
        return
    if box is None:
        return
    box.__enter__()
    state.active[item.nodeid] = box


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_call(item: pytest.Item) -> None:
    deferred = _state(item.config).deferred_call_errors.pop(item.nodeid, None)
    if deferred is not None:
        raise deferred


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_teardown(item: pytest.Item, nextitem: pytest.Item | None):
    """Exit after every fixture and teardown hook has finished."""
    state = _state(item.config)
    box = state.active.get(item.nodeid)
    teardown_failed = False
    try:
        try:
            result = yield
        except BaseException as exc:
            teardown_failed = not isinstance(exc, pytest.skip.Exception)
            if box is not None:
                # Sandbox.__exit__ suppresses its own cleanup/write errors when
                # a test error already exists, preserving the teardown failure.
                box.__exit__(type(exc), exc, exc.__traceback__)
            raise
        else:
            if box is not None:
                prior = state.phase_exc.get(item.nodeid)
                try:
                    if prior is None:
                        box.__exit__(None, None, None)
                    else:
                        box.__exit__(*prior)
                except BaseException:
                    teardown_failed = True
                    raise
            return result
    finally:
        state.active.pop(item.nodeid, None)
        if teardown_failed and item.nodeid in state.attempt_failed:
            state.attempt_failed[item.nodeid] = True
        # The writer exits above (or in the fallback fixture during ``yield``).
        # Only now may a pending path be renamed or deleted.
        if item.nodeid in state.pending:
            _finalize_pending(state, item.nodeid)
        state.phase_exc.pop(item.nodeid, None)
        state.deferred_call_errors.pop(item.nodeid, None)


@pytest.fixture
def hermetic_sandbox(request: pytest.FixtureRequest):
    """The active hermetic sandbox handle for this test.

    The runtest lifecycle hook normally enters the marker-configured sandbox
    before fixture setup, so this fixture only exposes that existing handle.
    The fallback keeps direct/nonstandard fixture execution usable. A test
    marked ``hermetic(off=True)`` is honored outside replay and receives None.
    """
    handle = current()
    if handle is not None:
        yield handle
        return
    box = _build_sandbox(request.node, for_fixture=True)
    if box is None:
        yield None
        return
    with box as handle:
        yield handle


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo):
    report = yield
    state = _state(item.config)
    if call.excinfo is not None and report.when != "teardown":
        state.phase_exc[item.nodeid] = (
            call.excinfo.type,
            call.excinfo.value,
            call.excinfo.tb,
        )
    if item.nodeid in state.pending:
        if report.failed:
            state.attempt_failed[item.nodeid] = True
    return report


def _finalize_pending(state: _PluginState, nodeid: str) -> None:
    pending_path, attempt = state.pending.pop(nodeid)
    failed = state.attempt_failed.pop(nodeid, False)
    if not pending_path.exists():
        return
    if not failed:
        try:
            pending_path.unlink()
        except OSError:
            pass
        return
    final = pending_path.with_name(pending_path.name.removeprefix(".pending-"))
    try:
        os.replace(pending_path, final)
    except OSError:
        return
    state.kept.append({"file": final.name, "test": nodeid, "attempt": attempt})


@pytest.hookimpl(optionalhook=True)
def pytest_testnodedown(node, error) -> None:
    # xdist master: merge repro bookkeeping shipped back from each worker,
    # otherwise the terminal summary has no seeds/journals to report.
    workeroutput = getattr(node, "workeroutput", None)
    if workeroutput is None:
        return
    state = _state(node.config)
    state.seeds.update(workeroutput.get("hermetic_seeds", {}))
    state.kept.extend(workeroutput.get("hermetic_kept", []))


def pytest_terminal_summary(terminalreporter, exitstatus, config) -> None:
    state = _state(config)
    # Errored-in-setup tests need their repro commands just as much as failures.
    failed_reports = terminalreporter.stats.get("failed", []) + terminalreporter.stats.get(
        "error", []
    )
    lines: list[str] = []
    all_flag = " --hermetic-all" if state.all_tests else ""
    journal_by_test: dict[str, dict[str, Any]] = {}
    for entry in state.kept:
        existing = journal_by_test.get(entry["test"])
        if existing is None or entry["attempt"] > existing["attempt"]:
            journal_by_test[entry["test"]] = entry
    for report in failed_reports:
        nodeid = report.nodeid
        if nodeid in journal_by_test and state.record_dir is not None:
            journal = state.record_dir / journal_by_test[nodeid]["file"]
            from ._security import inspect_journal

            security = inspect_journal(journal, current_env=os.environ)
            if security.has_credentials:
                lines.append(
                    "hermetic: replay command omitted because journal metadata "
                    "may contain a credential"
                )
            else:
                lines.append(
                    "python -m hermetic replay "
                    f"{shlex.quote(state.record_arg or str(state.record_dir))} "
                    f"--test {shlex.quote(nodeid)}"
                )
        elif nodeid in state.seeds and state.replay_reader is None:
            lines.append(
                f"pytest {shlex.quote(nodeid)}{all_flag} "
                f"--hermetic-seed={state.base_seed}"
            )
    if lines:
        terminalreporter.section("hermetic repro commands")
        for line in lines:
            terminalreporter.line(line)


@pytest.hookimpl(tryfirst=True)
def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    state = _state(session.config)
    # A reraised interruption can bypass pytest_runtest_teardown. Restore the
    # process and keep any journal that was successfully written.
    for nodeid, box in list(state.active.items()):
        interrupted = RuntimeError(
            f"pytest session ended before hermetic teardown completed for {nodeid!r}"
        )
        if nodeid in state.attempt_failed:
            state.attempt_failed[nodeid] = True
        try:
            box.__exit__(RuntimeError, interrupted, None)
        except BaseException as exc:  # noqa: BLE001 - session cleanup must continue
            warnings.warn(
                f"hermetic: failed to close interrupted sandbox for {nodeid!r}: {exc}",
                stacklevel=2,
            )
        finally:
            state.active.pop(nodeid, None)
    for nodeid in list(state.pending):
        state.attempt_failed[nodeid] = True
        _finalize_pending(state, nodeid)
        state.phase_exc.pop(nodeid, None)
        state.deferred_call_errors.pop(nodeid, None)

    if getattr(session.config, "workerinput", None) is not None:
        # xdist worker: ship repro bookkeeping to the master.
        workeroutput = getattr(session.config, "workeroutput", None)
        if workeroutput is not None:
            workeroutput["hermetic_seeds"] = dict(state.seeds)
            workeroutput["hermetic_kept"] = list(state.kept)
        return
    if state.record_dir is None:
        return
    # Master (or single) process: build the manifest from journals on disk so
    # xdist workers' journals are included.
    entries = []
    for path in sorted(state.record_dir.glob("*.json*")):
        if path.name.startswith(".pending-") or path.name == "index.json":
            continue
        try:
            reader = JournalReader.load(path)
        except SandboxError:
            continue
        entries.append({"file": path.name, "test": reader.test})
    if entries:
        index = state.record_dir / "index.json"
        write_private_json(index, {"journals": entries})
