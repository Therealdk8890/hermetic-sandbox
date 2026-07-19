"""Fail-closed replay integrity and private journal persistence."""

from __future__ import annotations

import json
import os
import random
import stat
import threading
import time

import pytest

import hermetic
from hermetic import ReplayMismatch
from hermetic._journal import JournalReader, JournalWriter


def test_strict_replay_rejects_unconsumed_clock_events(tmp_path):
    journal = tmp_path / "run.json"
    with hermetic.sandbox(record=journal):
        time.time()
        time.time()

    with pytest.raises(ReplayMismatch, match="before consuming all recorded events"):
        with hermetic.sandbox(replay=journal):
            time.time()


def test_strict_replay_rejects_cross_source_reordering(tmp_path):
    journal = tmp_path / "run.json"
    with hermetic.sandbox(record=journal):
        time.time()
        os.urandom(4)

    with pytest.raises(ReplayMismatch, match="global event"):
        with hermetic.sandbox(replay=journal):
            os.urandom(4)
            time.time()


def test_strict_replay_rejects_unconsumed_entropy(tmp_path):
    journal = tmp_path / "run.json"
    with hermetic.sandbox(record=journal):
        os.urandom(4)
        os.urandom(8)

    with pytest.raises(ReplayMismatch, match="before consuming all recorded events"):
        with hermetic.sandbox(replay=journal):
            os.urandom(4)


def test_strict_replay_rejects_different_random_call_path(tmp_path):
    journal = tmp_path / "run.json"
    with hermetic.sandbox(record=journal):
        random.random()
        random.random()

    with pytest.raises(ReplayMismatch, match="different global random state"):
        with hermetic.sandbox(replay=journal):
            random.random()


def test_recorded_deep_datetime_configuration_wins(tmp_path):
    journal = tmp_path / "run.json"
    with hermetic.sandbox(record=journal, deep_datetime=False):
        recorded = time.time()

    # The caller's default deep_datetime=True must not alter the recorded mode.
    with hermetic.sandbox(replay=journal):
        assert time.time() == recorded

    data = json.loads(journal.read_text())
    assert data["config"]["deep_datetime"] is False


def test_strict_replay_refuses_fatal_environment_mismatch(tmp_path):
    journal = tmp_path / "run.json"
    with hermetic.sandbox(record=journal):
        recorded = time.time()
    data = json.loads(journal.read_text())
    data["fingerprint"]["python"] = "2.7.18"
    journal.write_text(json.dumps(data))

    with pytest.raises(ReplayMismatch, match="Python version"):
        with hermetic.sandbox(replay=journal):
            time.time()

    with pytest.warns(UserWarning, match="Python version"):
        with hermetic.sandbox(replay=journal, strict_replay=False):
            assert time.time() == recorded


def test_cross_source_thread_recording_is_rejected(tmp_path):
    journal = tmp_path / "run.json"
    with hermetic.sandbox(record=journal):
        time.time()
        thread = threading.Thread(target=lambda: os.urandom(4))
        thread.start()
        thread.join()

    reader = JournalReader.load(journal)
    assert reader.concurrency_unfaithful == ["time.time", "urandom"]
    with pytest.raises(ReplayMismatch, match="events recorded across threads"):
        with hermetic.sandbox(replay=journal):
            pass


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_journal_is_private(tmp_path):
    journal = tmp_path / "run.json"
    with hermetic.sandbox(record=journal):
        time.time()
    assert stat.S_IMODE(journal.stat().st_mode) == 0o600


def test_preplanted_temp_symlink_is_not_followed(tmp_path):
    journal = tmp_path / "run.json"
    target = tmp_path / "target.txt"
    target.write_text("do not overwrite")
    predictable = journal.with_name(
        f".{journal.name}.part-{os.getpid()}-{threading.get_ident()}"
    )
    try:
        predictable.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")

    with hermetic.sandbox(record=journal):
        time.time()

    assert target.read_text() == "do not overwrite"
    assert journal.is_file()
    assert not journal.is_symlink()


def test_v2_journal_omits_unneeded_host_and_environment_metadata(tmp_path, monkeypatch):
    monkeypatch.setenv("INTERNAL_SECRET_NAME", "not-written")
    writer = JournalWriter(tmp_path / "run.json", config={})
    payload = writer.as_dict()
    assert payload["version"] == 2
    assert "env" not in payload
    assert "hostname" not in payload["fingerprint"]
    assert "cpu_count" not in payload["fingerprint"]
