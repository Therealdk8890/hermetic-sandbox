"""End-to-end coverage for pytest setup/call/teardown sandboxing."""

import gzip
import json
import re

import pytest


pytestmark = pytest.mark.usefixtures("monkeypatch")


def _journals(record_dir):
    return sorted(record_dir.glob("journal-*.json.gz"))


def _payload(path):
    return json.loads(gzip.decompress(path.read_bytes()))


def test_one_journal_covers_setup_call_and_teardown(pytester):
    pytester.makepyfile(
        """
        import time
        import pytest
        import hermetic

        @pytest.fixture
        def lifecycle():
            assert hermetic.current() is not None
            time.time()
            yield
            assert hermetic.current() is not None
            time.time()

        @pytest.mark.hermetic
        def test_target(lifecycle):
            assert hermetic.current() is not None
            time.time()
            assert False, "deliberate call failure"
        """
    )
    record_dir = pytester.path / "journals"
    result = pytester.runpytest(f"--hermetic-record={record_dir}")

    result.assert_outcomes(failed=1)
    journals = _journals(record_dir)
    assert len(journals) == 1
    assert re.fullmatch(r"journal-[0-9a-f]{16}-a1\.json\.gz", journals[0].name)
    assert not list(record_dir.glob(".pending-*"))
    assert _payload(journals[0])["counts"]["time.time"] >= 3
    result.stdout.fnmatch_lines(["*python -m hermetic replay*--test*"])
    replayed = pytester.runpytest(f"--hermetic-replay={journals[0]}")
    replayed.assert_outcomes(failed=1)


def test_setup_failure_keeps_journal_and_replay_command(pytester):
    pytester.makepyfile(
        """
        import time
        import pytest
        import hermetic

        @pytest.fixture
        def broken_setup():
            assert hermetic.current() is not None
            time.time()
            raise RuntimeError("setup flake")

        @pytest.mark.hermetic
        def test_target(broken_setup):
            pass
        """
    )
    record_dir = pytester.path / "journals"
    result = pytester.runpytest(f"--hermetic-record={record_dir}")

    result.assert_outcomes(errors=1)
    journals = _journals(record_dir)
    assert len(journals) == 1
    assert _payload(journals[0])["counts"]["time.time"] >= 1
    result.stdout.fnmatch_lines(["*python -m hermetic replay*--test*"])
    replayed = pytester.runpytest(f"--hermetic-replay={journals[0]}")
    replayed.assert_outcomes(errors=1)


def test_teardown_failure_keeps_journal_and_replay_command(pytester):
    pytester.makepyfile(
        """
        import time
        import pytest
        import hermetic

        @pytest.fixture
        def broken_teardown():
            assert hermetic.current() is not None
            yield
            assert hermetic.current() is not None
            time.time()
            raise RuntimeError("teardown flake")

        @pytest.mark.hermetic
        def test_target(broken_teardown):
            pass
        """
    )
    record_dir = pytester.path / "journals"
    result = pytester.runpytest(f"--hermetic-record={record_dir}")

    result.assert_outcomes(passed=1, errors=1)
    journals = _journals(record_dir)
    assert len(journals) == 1
    assert _payload(journals[0])["counts"]["time.time"] >= 1
    result.stdout.fnmatch_lines(["*python -m hermetic replay*--test*"])
    replayed = pytester.runpytest(f"--hermetic-replay={journals[0]}")
    replayed.assert_outcomes(passed=1, errors=1)


def test_hermetic_all_is_active_during_fixture_setup_and_teardown(pytester):
    pytester.makepyfile(
        """
        import time
        import pytest
        import hermetic

        @pytest.fixture
        def lifecycle():
            assert hermetic.current() is not None
            assert time.time() == 1577836800.0
            yield
            assert hermetic.current() is not None
            assert time.time() == 1577836800.0

        def test_target(lifecycle):
            assert hermetic.current() is not None
            assert time.time() == 1577836800.0
        """
    )
    result = pytester.runpytest("--hermetic-all", "--hermetic-seed=7")
    result.assert_outcomes(passed=1)


def test_fixture_reuses_lifecycle_handle(pytester):
    pytester.makepyfile(
        """
        import pytest
        import hermetic

        @pytest.fixture
        def dependency(hermetic_sandbox):
            assert hermetic.current() is hermetic_sandbox
            yield hermetic_sandbox
            assert hermetic.current() is hermetic_sandbox

        def test_target(dependency, hermetic_sandbox):
            assert dependency is hermetic_sandbox
            assert hermetic.current() is hermetic_sandbox
        """
    )
    result = pytester.runpytest()
    result.assert_outcomes(passed=1)


def test_replay_rejects_off_marker_instead_of_running_unsandboxed(pytester):
    source = pytester.makepyfile(
        """
        import pytest

        @pytest.mark.hermetic
        def test_target():
            assert False, "record me"
        """
    )
    record_dir = pytester.path / "journals"
    recorded = pytester.runpytest(f"--hermetic-record={record_dir}")
    recorded.assert_outcomes(failed=1)
    journal = _journals(record_dir)[0]

    source.write_text(
        """
import pytest

@pytest.mark.hermetic(off=True)
def test_target():
    assert False, "must not run outside replay"
"""
    )
    replayed = pytester.runpytest(f"--hermetic-replay={journal}")

    assert replayed.ret == pytest.ExitCode.USAGE_ERROR
    replayed.stderr.fnmatch_lines(["*cannot opt out of the sandbox*"])
