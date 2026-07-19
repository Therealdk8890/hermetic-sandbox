"""The pytest plugin, exercised through pytester."""

import json

import pytest

pytestmark = pytest.mark.usefixtures("monkeypatch")


def test_marker_makes_test_deterministic(pytester):
    pytester.makepyfile(
        """
        import random, uuid, pytest

        @pytest.mark.hermetic
        def test_values(tmp_path_factory):
            out = tmp_path_factory.getbasetemp().parent / "values.txt"
            with open(out, "a") as fh:
                fh.write(f"{random.random()}:{uuid.uuid4().hex}\\n")
        """
    )
    first = pytester.runpytest("--hermetic-seed=123")
    first.assert_outcomes(passed=1)
    second = pytester.runpytest("--hermetic-seed=123")
    second.assert_outcomes(passed=1)
    values = (pytester.path / "..").resolve()
    lines = set()
    for path in values.rglob("values.txt"):
        lines.update(path.read_text().splitlines())
    assert len(lines) == 1  # both runs produced identical values


def test_base_seed_printed_in_header(pytester):
    pytester.makepyfile("def test_ok(): pass")
    result = pytester.runpytest("--hermetic-seed=99")
    result.stdout.fnmatch_lines(["*hermetic: base seed 99*"])


def test_fixture_provides_handle_and_composes_with_marker(pytester):
    pytester.makepyfile(
        """
        import pytest, hermetic

        @pytest.mark.hermetic(seed=5, network="off")
        def test_marker_and_fixture(hermetic_sandbox):
            assert hermetic_sandbox.seed == 5
            assert hermetic.current() is hermetic_sandbox

        def test_fixture_alone(hermetic_sandbox):
            assert hermetic_sandbox.mode == "deterministic"
        """
    )
    result = pytester.runpytest()
    result.assert_outcomes(passed=2)


def test_hermetic_all_sandboxes_unmarked_tests(pytester):
    pytester.makepyfile(
        """
        import time, pytest

        def test_frozen():
            assert time.time() == 1577836800.0

        @pytest.mark.hermetic(off=True)
        def test_opted_out():
            assert time.time() > 1.7e9
        """
    )
    result = pytester.runpytest("--hermetic-all")
    result.assert_outcomes(passed=2)


def test_record_keeps_journal_only_for_failures(pytester):
    pytester.makepyfile(
        """
        import random, pytest

        @pytest.mark.hermetic
        def test_passes():
            random.random()

        @pytest.mark.hermetic
        def test_fails():
            random.random()
            assert False, "deliberate"
        """
    )
    record_dir = pytester.path / "journals"
    result = pytester.runpytest(f"--hermetic-record={record_dir}")
    result.assert_outcomes(passed=1, failed=1)
    journals = [p for p in record_dir.iterdir() if p.name != "index.json"]
    assert len(journals) == 1
    assert "test_fails" in journals[0].name
    assert not journals[0].name.startswith(".pending-")
    index = json.loads((record_dir / "index.json").read_text())
    assert index["journals"][0]["test"].endswith("::test_fails")


def test_failure_prints_repro_command(pytester):
    pytester.makepyfile(
        """
        import pytest

        @pytest.mark.hermetic
        def test_fails():
            assert False
        """
    )
    result = pytester.runpytest("--hermetic-seed=77")
    result.stdout.fnmatch_lines(["*hermetic repro commands*", "*--hermetic-seed=77*"])


def test_record_failure_prints_replay_command(pytester):
    pytester.makepyfile(
        """
        import pytest

        @pytest.mark.hermetic
        def test_fails():
            assert False
        """
    )
    record_dir = pytester.path / "journals"
    result = pytester.runpytest(f"--hermetic-record={record_dir}")
    result.stdout.fnmatch_lines(["*--hermetic-replay=*"])


def test_replay_reproduces_recorded_failure(pytester):
    pytester.makepyfile(
        """
        import random, pytest

        @pytest.mark.hermetic(rng="seed")
        def test_flaky_style():
            value = random.random()
            out = __file__ + ".observed"
            with open(out, "a") as fh:
                fh.write(f"{value}\\n")
            assert False, f"value was {value}"
        """
    )
    record_dir = pytester.path / "journals"
    record = pytester.runpytest(f"--hermetic-record={record_dir}")
    record.assert_outcomes(failed=1)
    journal = next(p for p in record_dir.iterdir() if p.name != "index.json")

    replay = pytester.runpytest(f"--hermetic-replay={journal}")
    replay.assert_outcomes(failed=1)
    observed = (pytester.path / "test_replay_reproduces_recorded_failure.py.observed")
    values = observed.read_text().splitlines()
    assert len(values) == 2
    assert values[0] == values[1]  # the replay saw the recorded random stream


def test_replay_deselects_other_tests(pytester):
    pytester.makepyfile(
        """
        import pytest

        @pytest.mark.hermetic
        def test_target():
            assert False

        def test_other():
            pass
        """
    )
    record_dir = pytester.path / "journals"
    pytester.runpytest(f"--hermetic-record={record_dir}")
    journal = next(p for p in record_dir.iterdir() if p.name != "index.json")
    result = pytester.runpytest(f"--hermetic-replay={journal}")
    result.assert_outcomes(failed=1, deselected=1)


def test_replay_missing_test_is_usage_error(pytester):
    pytester.makepyfile(
        """
        import pytest

        @pytest.mark.hermetic
        def test_will_be_renamed():
            assert False
        """
    )
    record_dir = pytester.path / "journals"
    pytester.runpytest(f"--hermetic-record={record_dir}")
    journal = next(p for p in record_dir.iterdir() if p.name != "index.json")
    pytester.makepyfile(
        """
        def test_renamed():
            pass
        """
    )
    result = pytester.runpytest(f"--hermetic-replay={journal}")
    assert result.ret != 0
    result.stderr.fnmatch_lines(["*was not collected*"])


def test_retry_does_not_delete_failure_journal(pytester):
    # Simulates a rerun plugin: the same nodeid runs twice; the first (failing)
    # attempt's journal must survive the second (passing) attempt.
    pytester.makepyfile(
        """
        import pytest

        COUNT = {"n": 0}

        @pytest.mark.hermetic
        @pytest.mark.parametrize("attempt", [1, 2])
        def test_flaky(attempt):
            assert attempt == 2
        """
    )
    record_dir = pytester.path / "journals"
    result = pytester.runpytest(f"--hermetic-record={record_dir}")
    result.assert_outcomes(passed=1, failed=1)
    kept = [p.name for p in record_dir.iterdir() if p.name != "index.json"]
    assert len(kept) == 1
    assert "attempt" in kept[0] or "test_flaky" in kept[0]


def test_hermetic_all_repro_command_includes_the_flag(pytester):
    pytester.makepyfile(
        """
        def test_fails():
            assert False
        """
    )
    result = pytester.runpytest("--hermetic-all", "--hermetic-seed=55")
    result.stdout.fnmatch_lines(["*--hermetic-all --hermetic-seed=55*"])


def test_fixture_only_test_is_recorded(pytester):
    pytester.makepyfile(
        """
        import random

        def test_fails(hermetic_sandbox):
            random.random()
            assert False
        """
    )
    record_dir = pytester.path / "journals"
    result = pytester.runpytest(f"--hermetic-record={record_dir}")
    result.assert_outcomes(failed=1)
    journals = [p for p in record_dir.iterdir() if p.name != "index.json"]
    assert len(journals) == 1
    result.stdout.fnmatch_lines(["*--hermetic-replay=*"])


def test_off_marker_wins_over_fixture_request(pytester):
    pytester.makepyfile(
        """
        import time, pytest

        @pytest.mark.hermetic(off=True)
        def test_opted_out(hermetic_sandbox):
            assert hermetic_sandbox is None
            assert time.time() > 1.7e9  # not sandboxed
        """
    )
    result = pytester.runpytest("--hermetic-all")
    result.assert_outcomes(passed=1)


def test_marker_rejects_record_kwarg(pytester):
    pytester.makepyfile(
        """
        import pytest

        @pytest.mark.hermetic(record="x.json")
        def test_bad():
            pass
        """
    )
    result = pytester.runpytest()
    result.assert_outcomes(failed=1)
    result.stdout.fnmatch_lines(["*does not accept 'record'*"])
