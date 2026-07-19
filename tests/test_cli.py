"""End-user journal discovery and replay command behavior."""

from __future__ import annotations

import base64
import gzip
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from hermetic._envelope import EnvelopeError, is_sealed_file, seal_file, unseal_file
from hermetic.cli import main


def _write_journal(
    path: Path,
    *,
    test: str | None,
    hash_seed: str | None = "314159",
    sensitive: bool = False,
    hostname: str | None = None,
) -> Path:
    events = {"urandom": ["0011223344556677"]} if sensitive else {}
    payload = {
        "format": "hermetic-journal",
        "version": 1,
        "test": test,
        "config": {
            "clock": "virtual",
            "rng": "off",
            "network": "block",
            "fs": "off",
            "seed": 7,
        },
        "fingerprint": {
            "python": sys.version.split()[0],
            "implementation": "CPython",
            "hostname": hostname,
            "hash_seed_env": hash_seed,
            "hash_randomization": True,
        },
        "random_state": None,
        "events": events,
        "counts": {source: len(values) for source, values in events.items()},
        "overflow": [],
        "concurrency_unfaithful": [],
        "env": {"mode": "names", "names": []},
    }
    encoded = json.dumps(payload).encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    contents = gzip.compress(encoded, mtime=0) if path.suffix == ".gz" else encoded
    path.write_bytes(contents)
    return path


def _key(fill: int) -> str:
    return base64.urlsafe_b64encode(bytes([fill]) * 32).decode()


def _write_index(directory: Path, journals: list[Path]) -> Path:
    index = directory / "index.json"
    index.write_text(
        json.dumps(
            {
                "journals": [
                    {"file": str(path.relative_to(directory))}
                    for path in journals
                ]
            }
        )
    )
    return index


def test_replay_from_relocated_directory_uses_portable_path_and_hash_seed(
    tmp_path, monkeypatch
):
    runner_artifact = tmp_path / "runner" / "hermetic-journals"
    original = _write_journal(
        runner_artifact / "nested" / "failure.json.gz",
        test="tests/test_checkout.py::test_flaky",
        hash_seed="8675309",
    )
    _write_index(runner_artifact, [original])

    downloaded = tmp_path / "checkout" / "downloaded journals"
    shutil.copytree(runner_artifact, downloaded)
    shutil.rmtree(tmp_path / "runner")
    monkeypatch.chdir(tmp_path / "checkout")

    calls = []

    def fake_run(command, *, env, check):
        calls.append((command, env, check))
        return SimpleNamespace(returncode=7)

    monkeypatch.setattr("hermetic.cli.subprocess.run", fake_run)
    status = main(["replay", str(downloaded), "--", "-q", "--maxfail=1"])

    assert status == 7
    assert len(calls) == 1
    command, environment, check = calls[0]
    assert command[:3] == [sys.executable, "-m", "pytest"]
    assert command[3].startswith("--hermetic-replay=")
    replay_path = Path(command[3].split("=", 1)[1])
    assert replay_path == downloaded / "nested" / "failure.json.gz"
    assert "runner" not in str(replay_path)
    assert "tests/test_checkout.py::test_flaky" in command
    assert command[-2:] == ["-q", "--maxfail=1"]
    assert environment["PYTHONHASHSEED"] == "8675309"
    assert check is False


def test_explicit_index_moves_with_its_journals(tmp_path, monkeypatch):
    artifact = tmp_path / "artifact"
    journal = _write_journal(
        artifact / "nested" / "failure.json.gz",
        test="tests/test_api.py::test_failure",
    )
    index = _write_index(artifact, [journal])
    moved = tmp_path / "download" / "artifact"
    moved.parent.mkdir()
    shutil.move(artifact, moved)

    observed = {}

    def fake_run(command, *, env, check):
        observed["command"] = command
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("hermetic.cli.subprocess.run", fake_run)
    assert main(["replay", str(moved / index.name)]) == 0
    replay_option = next(
        argument
        for argument in observed["command"]
        if argument.startswith("--hermetic-replay=")
    )
    assert Path(replay_option.split("=", 1)[1]) == moved / "nested" / "failure.json.gz"


def test_index_cannot_escape_downloaded_artifact(tmp_path, monkeypatch, capsys):
    outside = _write_journal(
        tmp_path / "outside.json",
        test="tests/test_outside.py::test_outside",
    )
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    index = artifact / "index.json"
    calls = []
    monkeypatch.setattr(
        "hermetic.cli.subprocess.run",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    for filename in ("../outside.json", str(outside.resolve())):
        index.write_text(json.dumps({"journals": [{"file": filename}]}))
        assert main(["replay", str(index)]) == 2
        message = capsys.readouterr().err
        assert "outside its artifact" in message
        assert calls == []


def test_replay_and_directory_seal_reject_symlinked_journals(
    tmp_path, monkeypatch, capsys
):
    outside = _write_journal(
        tmp_path / "outside.json.gz",
        test="tests/test_outside.py::test_outside",
        sensitive=True,
    )
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    link = artifact / "linked.json.gz"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks are unavailable")

    assert main(["replay", str(artifact)]) == 2
    assert "symlink" in capsys.readouterr().err

    monkeypatch.setenv("HERMETIC_JOURNAL_KEY", _key(7))
    output = tmp_path / "sealed"
    assert (
        main(
            [
                "journal",
                "seal",
                str(artifact),
                "--output",
                str(output),
            ]
        )
        == 2
    )
    assert "symlink" in capsys.readouterr().err
    assert not output.exists()


def test_multiple_journals_list_choices_and_test_selects_one(
    tmp_path, monkeypatch, capsys
):
    artifact = tmp_path / "journals"
    first = _write_journal(
        artifact / "first.json.gz",
        test="tests/test_one.py::test_one",
    )
    second = _write_journal(
        artifact / "deeper" / "second.json",
        test="tests/test_two.py::test_two",
    )

    calls = []

    def fake_run(command, *, env, check):
        calls.append(command)
        return SimpleNamespace(returncode=5)

    monkeypatch.setattr("hermetic.cli.subprocess.run", fake_run)

    assert main(["replay", str(artifact)]) == 2
    message = capsys.readouterr().err
    assert "multiple replay journals found" in message
    assert "tests/test_one.py::test_one" in message
    assert "tests/test_two.py::test_two" in message
    assert str(first.name) in message
    assert str(second.relative_to(artifact)) in message
    assert calls == []

    status = main(
        [
            "replay",
            str(artifact),
            "--test",
            "tests/test_two.py::test_two",
            "--",
            "-x",
            "-vv",
        ]
    )
    assert status == 5
    assert len(calls) == 1
    command = calls[0]
    assert f"--hermetic-replay={second.resolve()}" in command
    assert f"--hermetic-replay={first.resolve()}" not in command
    assert command[-2:] == ["-x", "-vv"]


def test_replay_refuses_credential_nodeid_without_rendering_it(
    tmp_path, capsys
):
    credential = "sk-proj-" + ("Z" * 32)
    journal = _write_journal(
        tmp_path / "credential.json.gz",
        test=f"tests/test_api.py::test_api[{credential}]",
    )

    assert main(["replay", str(journal)]) == 2
    message = capsys.readouterr().err
    assert "metadata may contain a credential" in message
    assert credential not in message


def test_test_selector_names_the_test_for_an_unnamed_journal(tmp_path, monkeypatch):
    journal = _write_journal(tmp_path / "context-manager.json", test=None)
    observed = {}

    def fake_run(command, *, env, check):
        observed["command"] = command
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("hermetic.cli.subprocess.run", fake_run)
    selector = "tests/test_context.py::test_recorded"
    assert main(["replay", str(journal), "--test", selector]) == 0
    assert selector in observed["command"]


def test_recorded_unset_hash_seed_is_unset_for_pytest(tmp_path, monkeypatch):
    journal = _write_journal(
        tmp_path / "failure.json",
        test="tests/test_hash.py::test_hash_order",
        hash_seed=None,
    )
    monkeypatch.setenv("PYTHONHASHSEED", "local-value")
    observed = {}

    def fake_run(command, *, env, check):
        observed["environment"] = env
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("hermetic.cli.subprocess.run", fake_run)
    assert main(["replay", str(journal)]) == 0
    assert "PYTHONHASHSEED" not in observed["environment"]


def test_python_module_cli_replays_after_artifact_directory_relocation(tmp_path):
    runner_artifact = tmp_path / "runner" / "journals"
    journal = _write_journal(
        runner_artifact / "failure.json.gz",
        test="test_target.py::test_failure",
        hash_seed="0",
    )
    _write_index(runner_artifact, [journal])

    checkout = tmp_path / "checkout"
    downloaded = checkout / "downloaded journals"
    checkout.mkdir()
    shutil.copytree(runner_artifact, downloaded)
    shutil.rmtree(tmp_path / "runner")
    (checkout / "test_target.py").write_text(
        "def test_failure():\n"
        "    assert False, 'replayed failure'\n"
    )

    repo_src = Path(__file__).parents[1] / "src"
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join(
        [str(repo_src), environment.get("PYTHONPATH", "")]
    ).rstrip(os.pathsep)
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "hermetic",
            "replay",
            str(downloaded),
            "--",
            "-q",
        ],
        cwd=checkout,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 1
    assert "replayed failure" in completed.stdout
    assert "from failure.json.gz" in completed.stderr
    assert "runner" not in completed.stderr


def test_journal_seal_encrypts_sensitive_replay_data_with_private_output(
    tmp_path, monkeypatch, capsys
):
    key_value = _key(31)
    monkeypatch.setenv("SEALING_KEY", key_value)
    journal = _write_journal(
        tmp_path / "failure.json.gz",
        test="tests/test_secret.py::test_token",
        sensitive=True,
    )
    plaintext = journal.read_bytes()
    sealed = tmp_path / "upload" / "failure.sealed"

    assert (
        main(
            [
                "journal",
                "seal",
                str(journal),
                "--output",
                str(sealed),
                "--key-env",
                "SEALING_KEY",
            ]
        )
        == 0
    )

    assert is_sealed_file(sealed)
    assert plaintext not in sealed.read_bytes()
    if os.name != "nt":
        assert stat.S_IMODE(sealed.stat().st_mode) == 0o600
    restored = tmp_path / "restored.json.gz"
    unseal_file(sealed, restored, key_env="SEALING_KEY")
    assert restored.read_bytes() == plaintext
    output = capsys.readouterr().err
    assert str(sealed) in output
    assert key_value not in output


def test_journal_seal_blocks_credentials_and_malformed_metadata(
    tmp_path, monkeypatch, capsys
):
    key_value = _key(12)
    monkeypatch.setenv("HERMETIC_JOURNAL_KEY", key_value)
    credential = "sk-proj-" + ("A" * 32)
    credential_journal = _write_journal(
        tmp_path / "credential.json",
        test="tests/test_api.py::test_api",
        hostname=credential,
    )
    credential_output = tmp_path / "credential.sealed"

    assert (
        main(
            [
                "journal",
                "seal",
                str(credential_journal),
                "--output",
                str(credential_output),
            ]
        )
        == 2
    )
    message = capsys.readouterr().err
    assert "upload blocked" in message
    assert credential not in message
    assert key_value not in message
    assert not credential_output.exists()

    malformed = tmp_path / "malformed.json"
    malformed.write_text('{"format":"hermetic-journal","version":1}')
    malformed_output = tmp_path / "malformed.sealed"
    assert (
        main(
            [
                "journal",
                "seal",
                str(malformed),
                "--output",
                str(malformed_output),
            ]
        )
        == 2
    )
    assert "upload blocked" in capsys.readouterr().err
    assert not malformed_output.exists()


def test_journal_seal_blocks_custom_key_copied_into_metadata(
    tmp_path, monkeypatch, capsys
):
    key_value = _key(13)
    monkeypatch.setenv("ODD_NAME", key_value)
    journal = _write_journal(
        tmp_path / "copied-key.json",
        test="tests/test_metadata.py::test_metadata",
        hostname=key_value,
    )
    output = tmp_path / "copied-key.sealed"

    assert (
        main(
            [
                "journal",
                "seal",
                str(journal),
                "--output",
                str(output),
                "--key-env",
                "ODD_NAME",
            ]
        )
        == 2
    )
    message = capsys.readouterr().err
    assert "credential=1" in message
    assert key_value not in message
    assert not output.exists()


def test_journal_seal_preserves_existing_secret_scan_values(
    tmp_path, monkeypatch, capsys
):
    existing_secret = "opaque-existing-environment-secret"
    custom_key = _key(24)
    monkeypatch.setenv("HERMETIC_API_KEY", existing_secret)
    monkeypatch.setenv("ODD_NAME", custom_key)
    journal = _write_journal(
        tmp_path / "existing-secret.json",
        test="tests/test_metadata.py::test_existing_secret",
        hostname=existing_secret,
    )
    output = tmp_path / "existing-secret.sealed"

    assert (
        main(
            [
                "journal",
                "seal",
                str(journal),
                "--output",
                str(output),
                "--key-env",
                "ODD_NAME",
            ]
        )
        == 2
    )
    message = capsys.readouterr().err
    assert "credential=1" in message
    assert existing_secret not in message
    assert custom_key not in message
    assert not output.exists()


def test_cli_never_prints_key_mistaken_for_key_env_name(
    tmp_path, monkeypatch, capsys
):
    journal = _write_journal(
        tmp_path / "journal.json",
        test="tests/test_key.py::test_key",
        sensitive=True,
    )
    output = tmp_path / "journal.sealed"
    key_as_name = _key(0).rstrip("=")
    monkeypatch.delenv(key_as_name, raising=False)

    assert (
        main(
            [
                "journal",
                "seal",
                str(journal),
                "--output",
                str(output),
                "--key-env",
                key_as_name,
            ]
        )
        == 2
    )
    assert key_as_name not in capsys.readouterr().err
    assert not output.exists()


def test_journal_seal_directory_is_opaque_and_replays_by_recorded_test(
    tmp_path, monkeypatch, capsys
):
    key_value = _key(14)
    monkeypatch.setenv("HERMETIC_JOURNAL_KEY", key_value)
    source = tmp_path / "raw journals"
    first = _write_journal(
        source / "tests-test_one.py-test_one.json.gz",
        test="tests/test_one.py::test_one",
        sensitive=True,
    )
    second = _write_journal(
        source / "nested" / "tests-test_two.py-test_two.json.gz",
        test="tests/test_two.py::test_two",
        sensitive=True,
    )
    _write_index(source, [first, second])
    output = tmp_path / "sealed upload"

    assert (
        main(
            [
                "journal",
                "seal",
                str(source),
                "--output",
                str(output),
            ]
        )
        == 0
    )

    sealed_files = sorted(output.iterdir())
    assert len(sealed_files) == 2
    assert all(path.is_file() and path.suffix == ".sealed" for path in sealed_files)
    assert all(is_sealed_file(path) for path in sealed_files)
    assert not (output / "index.json").exists()
    assert "test_one" not in " ".join(path.name for path in sealed_files)
    assert "test_two" not in " ".join(path.name for path in sealed_files)
    if os.name != "nt":
        assert stat.S_IMODE(output.stat().st_mode) == 0o700
        assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in sealed_files)

    calls = []

    def fake_run(command, *, env, check):
        calls.append(command)
        replay_option = next(
            argument
            for argument in command
            if argument.startswith("--hermetic-replay=")
        )
        assert Path(replay_option.split("=", 1)[1]).read_bytes() == second.read_bytes()
        assert "HERMETIC_JOURNAL_KEY" not in env
        return SimpleNamespace(returncode=4)

    monkeypatch.setattr("hermetic.cli.subprocess.run", fake_run)
    assert (
        main(
            [
                "replay",
                str(output),
                "--test",
                "tests/test_two.py::test_two",
            ]
        )
        == 4
    )
    assert len(calls) == 1
    message = capsys.readouterr().err
    assert "hermetic-replay-" not in message
    assert key_value not in message


def test_journal_seal_directory_is_fail_closed_and_leaves_no_partial_set(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setenv("HERMETIC_JOURNAL_KEY", _key(15))
    source = tmp_path / "raw"
    _write_journal(
        source / "good.json.gz",
        test="tests/test_good.py::test_good",
        sensitive=True,
    )
    credential = "github_pat_" + ("B" * 32)
    _write_journal(
        source / "credential.json.gz",
        test="tests/test_bad.py::test_bad",
        sensitive=True,
        hostname=credential,
    )
    output = tmp_path / "sealed"

    assert (
        main(
            [
                "journal",
                "seal",
                str(source),
                "--output",
                str(output),
            ]
        )
        == 2
    )
    message = capsys.readouterr().err
    assert "upload blocked" in message
    assert credential not in message
    assert not output.exists()
    assert not list(tmp_path.glob(".sealed.stage-*"))

    malformed_source = tmp_path / "malformed raw"
    _write_journal(
        malformed_source / "good.json",
        test="tests/test_good.py::test_good",
        sensitive=True,
    )
    (malformed_source / "bad.json").write_text('{"format":"hermetic-journal"}')
    malformed_output = tmp_path / "malformed sealed"
    assert (
        main(
            [
                "journal",
                "seal",
                str(malformed_source),
                "--output",
                str(malformed_output),
            ]
        )
        == 2
    )
    assert not malformed_output.exists()
    assert not list(tmp_path.glob(".malformed sealed.stage-*"))


def test_journal_seal_directory_removes_staging_after_encryption_failure(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("HERMETIC_JOURNAL_KEY", _key(16))
    source = tmp_path / "raw"
    _write_journal(
        source / "one.json",
        test="tests/test_one.py::test_one",
        sensitive=True,
    )
    _write_journal(
        source / "two.json",
        test="tests/test_two.py::test_two",
        sensitive=True,
    )
    output = tmp_path / "sealed"
    calls = {"count": 0}

    def fail_second(source_path, destination, *, key_env):
        calls["count"] += 1
        if calls["count"] == 2:
            raise EnvelopeError("simulated encryption failure")
        return seal_file(source_path, destination, key_env=key_env)

    monkeypatch.setattr("hermetic.cli.seal_file", fail_second)
    assert (
        main(
            [
                "journal",
                "seal",
                str(source),
                "--output",
                str(output),
            ]
        )
        == 2
    )
    assert calls["count"] == 2
    assert not output.exists()
    assert not list(tmp_path.glob(".sealed.stage-*"))


def test_replay_sealed_directory_uses_private_temp_and_removes_key(
    tmp_path, monkeypatch, capsys
):
    key_value = _key(44)
    monkeypatch.setenv("REPLAY_JOURNAL_KEY", key_value)
    monkeypatch.setenv("HERMETIC_JOURNAL_KEY", _key(45))
    monkeypatch.setenv("hermetic_journal_key", _key(46))
    artifact = tmp_path / "downloaded artifact"
    journal = _write_journal(
        tmp_path / "source" / "failure.json.gz",
        test="tests/test_checkout.py::test_flaky",
        hash_seed="101",
        sensitive=True,
    )
    plaintext = journal.read_bytes()
    sealed = artifact / "nested" / "failure.any-extension"
    seal_file(journal, sealed, key_env="REPLAY_JOURNAL_KEY")
    shutil.rmtree(tmp_path / "source")

    observed = {}

    def fake_run(command, *, env, check):
        replay_option = next(
            argument
            for argument in command
            if argument.startswith("--hermetic-replay=")
        )
        decrypted = Path(replay_option.split("=", 1)[1])
        observed["decrypted"] = decrypted
        assert decrypted.exists()
        assert decrypted.read_bytes() == plaintext
        if os.name != "nt":
            assert stat.S_IMODE(decrypted.stat().st_mode) == 0o600
        forwarded_names = {name.casefold() for name in env}
        assert "replay_journal_key" not in forwarded_names
        assert "hermetic_journal_key" not in forwarded_names
        assert env["PYTHONHASHSEED"] == "101"
        assert check is False
        return SimpleNamespace(returncode=6)

    monkeypatch.setattr("hermetic.cli.subprocess.run", fake_run)
    status = main(
        [
            "replay",
            str(artifact),
            "--key-env",
            "REPLAY_JOURNAL_KEY",
            "--",
            "-q",
        ]
    )

    assert status == 6
    assert not observed["decrypted"].exists()
    message = capsys.readouterr().err
    assert "nested/failure.any-extension" in message
    assert "hermetic-replay-" not in message
    assert key_value not in message


def test_sealed_replay_cleans_temp_after_pytest_exception(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMETIC_JOURNAL_KEY", _key(18))
    journal = _write_journal(
        tmp_path / "failure.json",
        test="tests/test_cleanup.py::test_cleanup",
        sensitive=True,
    )
    sealed = tmp_path / "failure.sealed"
    seal_file(journal, sealed)
    observed = {}

    def interrupted(command, *, env, check):
        replay_option = next(
            argument
            for argument in command
            if argument.startswith("--hermetic-replay=")
        )
        observed["decrypted"] = Path(replay_option.split("=", 1)[1])
        assert observed["decrypted"].exists()
        raise RuntimeError("simulated pytest launcher failure")

    monkeypatch.setattr("hermetic.cli.subprocess.run", interrupted)
    with pytest.raises(RuntimeError, match="simulated"):
        main(["replay", str(sealed)])
    assert not observed["decrypted"].exists()


def test_sealed_replay_wrong_key_is_safe_error(tmp_path, monkeypatch, capsys):
    correct_key = _key(21)
    wrong_key = _key(22)
    monkeypatch.setenv("HERMETIC_JOURNAL_KEY", correct_key)
    journal = _write_journal(
        tmp_path / "failure.json",
        test="tests/test_auth.py::test_auth",
        sensitive=True,
    )
    sealed = tmp_path / "failure.sealed"
    seal_file(journal, sealed)

    monkeypatch.setenv("HERMETIC_JOURNAL_KEY", wrong_key)
    assert main(["replay", str(sealed)]) == 2
    message = capsys.readouterr().err
    assert "authentication failed" in message
    assert correct_key not in message
    assert wrong_key not in message


def test_python_module_cli_replays_sealed_journal_end_to_end(tmp_path, monkeypatch):
    key_value = _key(29)
    monkeypatch.setenv("END_TO_END_JOURNAL_KEY", key_value)
    journal = _write_journal(
        tmp_path / "source" / "failure.json.gz",
        test="test_target.py::test_failure",
        hash_seed="0",
        sensitive=True,
    )
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    sealed = checkout / "downloaded.sealed"
    seal_file(journal, sealed, key_env="END_TO_END_JOURNAL_KEY")
    shutil.rmtree(tmp_path / "source")
    (checkout / "test_target.py").write_text(
        "import os\n"
        "\n"
        "def test_failure():\n"
        "    assert 'END_TO_END_JOURNAL_KEY' not in os.environ\n"
        "    assert False, 'sealed replay reached the recorded test'\n"
    )

    repo_src = Path(__file__).parents[1] / "src"
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join(
        [str(repo_src), environment.get("PYTHONPATH", "")]
    ).rstrip(os.pathsep)
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "hermetic",
            "replay",
            str(sealed),
            "--key-env",
            "END_TO_END_JOURNAL_KEY",
            "--",
            "-q",
        ],
        cwd=checkout,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    combined = completed.stdout + completed.stderr
    assert completed.returncode == 1
    assert "sealed replay reached the recorded test" in completed.stdout
    assert "hermetic-replay-" not in combined
    assert key_value not in combined


def test_journal_inspect_uses_security_report_and_blocks_unsafe_upload(
    tmp_path, monkeypatch, capsys
):
    journal = tmp_path / "failure.json.gz"
    journal.write_bytes(b"security implementation owns parsing")
    observed = {}

    class FakeReport:
        def to_dict(self, *, encrypted):
            observed["to_dict_encrypted"] = encrypted
            return {
                "valid": True,
                "upload_safe": False,
                "findings": [{"kind": "credential", "location": "events.urandom"}],
            }

        def is_upload_safe(self, *, encrypted):
            observed["safe_encrypted"] = encrypted
            return False

    def inspect_journal(path):
        observed["path"] = path
        return FakeReport()

    fake_security = SimpleNamespace(inspect_journal=inspect_journal)
    monkeypatch.setitem(sys.modules, "hermetic._security", fake_security)

    assert main(["journal", "inspect", str(journal)]) == 1
    output = json.loads(capsys.readouterr().out)
    assert output["valid"] is True
    assert output["upload_safe"] is False
    assert observed == {
        "path": journal,
        "to_dict_encrypted": False,
        "safe_encrypted": False,
    }
