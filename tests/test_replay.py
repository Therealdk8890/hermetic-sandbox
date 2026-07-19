"""Record/replay: round trips, divergence handling, journal integrity."""

import datetime
import gzip
import json
import os
import random
import secrets
import threading
import time
import uuid

import pytest

import hermetic
import hermetic._journal as journal_module
from hermetic import ReplayExhausted, ReplayMismatch
from hermetic._journal import (
    JournalReader,
    JournalWriter,
    collect_fingerprint,
    write_private_json,
)


def _observable():
    return {
        "wall": time.time(),
        "mono_delta": time.monotonic() - time.monotonic(),
        "dt": datetime.datetime.now().isoformat(),
        "rand": [random.random() for _ in range(3)],
        "uuid": uuid.uuid4().hex,
        "token": secrets.token_hex(8),
    }


def test_record_replay_round_trip(tmp_path):
    journal = tmp_path / "run.json.gz"
    with hermetic.sandbox(record=journal):
        recorded = _observable()
    with pytest.warns(UserWarning) if _hash_randomized() else _nullcontext():
        with hermetic.sandbox(replay=journal):
            replayed = _observable()
    assert recorded == replayed


def _hash_randomized():
    import sys

    return bool(sys.flags.hash_randomization) and not os.environ.get("PYTHONHASHSEED")


class _nullcontext:
    def __enter__(self):
        return None

    def __exit__(self, *args):
        return False


def test_replay_uses_journal_config_not_caller_args(tmp_path):
    journal = tmp_path / "run.json"
    with hermetic.sandbox(record=journal):
        recorded = time.time()
    # caller asks for clock="off" — the journal recorded clock="virtual", which wins
    with hermetic.sandbox(replay=journal, clock="off"):
        assert time.time() == recorded


def test_strict_replay_exhaustion_raises(tmp_path):
    journal = tmp_path / "run.json"
    with hermetic.sandbox(record=journal):
        secrets.token_bytes(4)
    with pytest.raises(ReplayExhausted):
        with hermetic.sandbox(replay=journal):
            secrets.token_bytes(4)
            secrets.token_bytes(4)


def test_nonstrict_replay_falls_back_with_warning(tmp_path):
    journal = tmp_path / "run.json"
    with hermetic.sandbox(record=journal):
        time.time()
    with pytest.warns(UserWarning, match="falling back"):
        with hermetic.sandbox(replay=journal, strict_replay=False):
            time.time()
            time.time()
            time.time()


def test_urandom_length_mismatch_is_divergence(tmp_path):
    journal = tmp_path / "run.json"
    with hermetic.sandbox(record=journal):
        os.urandom(4)
    with pytest.raises(ReplayMismatch):
        with hermetic.sandbox(replay=journal):
            os.urandom(16)


def test_journal_is_gzip_when_gz_suffix(tmp_path):
    journal = tmp_path / "run.json.gz"
    with hermetic.sandbox(record=journal):
        time.time()
    assert journal.read_bytes()[:2] == b"\x1f\x8b"
    data = json.loads(gzip.decompress(journal.read_bytes()))
    assert data["format"] == "hermetic-journal"


def test_journal_records_neither_env_names_nor_values(tmp_path):
    os.environ["HERMETIC_JOURNAL_SECRET"] = "do-not-leak"
    try:
        journal = tmp_path / "run.json"
        with hermetic.sandbox(record=journal):
            pass
        text = journal.read_text()
        assert "HERMETIC_JOURNAL_SECRET" not in text
        assert "do-not-leak" not in text
    finally:
        os.environ.pop("HERMETIC_JOURNAL_SECRET", None)


def test_journal_no_partial_files_left(tmp_path):
    journal = tmp_path / "run.json"
    with hermetic.sandbox(record=journal):
        time.time()
    leftovers = [p for p in tmp_path.iterdir() if p.name != "run.json"]
    assert leftovers == []


@pytest.mark.parametrize("kind", ["journal", "index"])
def test_windows_journal_and_index_writes_enforce_current_user_acl(
    kind, tmp_path, monkeypatch
):
    destination = tmp_path / (
        "journal.json.gz" if kind == "journal" else "index.json"
    )
    enforced = []

    def enforce(path):
        enforced.append((path, path.stat().st_size))
        return path

    monkeypatch.setattr(journal_module, "_IS_WINDOWS", True)
    monkeypatch.setattr(journal_module, "ensure_private_path", enforce)
    if kind == "journal":
        JournalWriter(destination, config={}).write()
    else:
        write_private_json(destination, {"journals": []})

    assert len(enforced) == 2
    temporary, published = enforced
    assert temporary[0] != destination
    assert temporary[1] == 0
    assert published[0] == destination
    assert published[1] > 0


def test_journal_counts_and_random_state(tmp_path):
    journal = tmp_path / "run.json"
    with hermetic.sandbox(record=journal):
        time.time()
        time.time()
        random.random()
    data = json.loads(journal.read_text())
    assert data["counts"]["time.time"] == 2
    assert data["random_state"] is not None
    assert data["test"] is None


def test_event_cap_sets_overflow_flag(tmp_path):
    writer = JournalWriter(tmp_path / "j.json", config={}, event_cap=3)
    for index in range(5):
        writer.record_event("time.time", float(index))
    payload = writer.as_dict()
    assert payload["counts"]["time.time"] == 3
    assert payload["overflow"] == ["time.time"]


def test_multithreaded_recording_is_stamped_unfaithful(tmp_path):
    writer = JournalWriter(tmp_path / "j.json", config={})
    writer.record_event("time.time", 1.0)
    thread = threading.Thread(target=writer.record_event, args=("time.time", 2.0))
    thread.start()
    thread.join()
    assert writer.as_dict()["concurrency_unfaithful"] == ["time.time"]


def test_corrupt_journal_raises_replay_mismatch(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"format": "hermetic-journal", "version": 1, truncated')
    with pytest.raises(ReplayMismatch, match="corrupt"):
        JournalReader.load(bad)


def test_wrong_format_raises_replay_mismatch(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"format": "something-else"}')
    with pytest.raises(ReplayMismatch):
        JournalReader.load(bad)


def test_unsupported_version_error_does_not_render_metadata(tmp_path):
    secret_shaped_version = "sk-proj-" + ("A" * 32)
    bad = tmp_path / "unsupported.json"
    bad.write_text(
        json.dumps(
            {
                "format": "hermetic-journal",
                "version": secret_shaped_version,
            }
        )
    )
    with pytest.raises(ReplayMismatch) as failure:
        JournalReader.load(bad)
    assert "unsupported journal version" in str(failure.value)
    assert secret_shaped_version not in str(failure.value)


def test_fingerprint_mismatch_warnings():
    recorded = collect_fingerprint()
    recorded["python"] = "2.7.18"
    recorded["tz_env"] = "America/New_York" if not os.environ.get("TZ") else None
    from hermetic._journal import fingerprint_warnings

    messages = fingerprint_warnings(recorded, collect_fingerprint())
    assert any("Python version" in message for message in messages)


def test_test_file_fingerprint_normalizes_checkout_line_endings(tmp_path):
    lf = tmp_path / "lf.py"
    crlf = tmp_path / "crlf.py"
    lf.write_bytes(b"def test_example():\n    assert True\n")
    crlf.write_bytes(b"def test_example():\r\n    assert True\r\n")

    assert journal_module._test_file_sha(  # type: ignore[attr-defined]
        f"{lf}::test_example",
        str(tmp_path),
    ) == journal_module._test_file_sha(  # type: ignore[attr-defined]
        f"{crlf}::test_example",
        str(tmp_path),
    )


def test_clock_control_works_in_record_mode_and_replays(tmp_path):
    journal = tmp_path / "run.json"
    with hermetic.sandbox(record=journal) as sb:
        before = time.time()
        sb.clock.advance(3600)
        after = time.time()
        assert after - before >= 3600
        sb.clock.set("2030-01-01T00:00:00+00:00")
        jumped = datetime.datetime.now(datetime.timezone.utc).year
        assert jumped == 2030
    with hermetic.sandbox(replay=journal) as sb:
        assert time.time() == before
        sb.clock.advance(3600)  # no-op on replay: already baked into readings
        assert time.time() == after
        sb.clock.set("2030-01-01T00:00:00+00:00")
        assert datetime.datetime.now(datetime.timezone.utc).year == 2030


def test_journal_records_caller_seed_for_fallbacks(tmp_path):
    journal = tmp_path / "run.json"
    with hermetic.sandbox(seed=987654, record=journal):
        time.time()
    data = json.loads(journal.read_text())
    assert data["config"]["seed"] == 987654


def test_replay_warns_when_recording_allowed_network(tmp_path):
    journal = tmp_path / "run.json"
    with hermetic.sandbox(record=journal, network="off"):
        time.time()
    with pytest.warns(UserWarning, match="network"):
        with hermetic.sandbox(replay=journal):
            time.time()
