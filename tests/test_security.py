"""Secret-safe journal inspection and fail-closed upload policy."""

from __future__ import annotations

import gzip
import json
import os

import hermetic
import pytest

from hermetic._security import (
    JournalUploadBlocked,
    inspect_journal,
    require_upload_safe,
)


def _journal(**overrides):
    data = {
        "format": "hermetic-journal",
        "version": 2,
        "created_at": 1_700_000_000.0,
        "test": "tests/test_checkout.py::test_total",
        "config": {
            "clock": "virtual",
            "now": 1_577_836_800.0,
            "tick": 1e-6,
            "rng": "off",
            "network": "block",
            "allow_loopback": True,
            "allow_unix": True,
            "fs": "off",
            "chdir": True,
            "scrub_env": False,
            "deep_datetime": True,
            "spin_limit": 1_000_000,
            "seed": None,
        },
        "fingerprint": {
            "python": "3.13.5",
            "implementation": "CPython",
            "platform": "test-platform",
            "hostname": "test-runner",
            "cpu_count": 4,
            "tz_env": None,
            "tzname": ["UTC", "UTC"],
            "locale": "C",
            "hash_seed_env": "0",
            "hash_randomization": True,
            "git_sha": "a" * 40,
        },
        "random_state": None,
        "random_state_after": None,
        "events": {"time.time": [1_700_000_000.0]},
        "sequence": ["time.time"],
        "counts": {"time.time": 1},
        "overflow": [],
        "concurrency_unfaithful": [],
    }
    data.update(overrides)
    return data


def _serialized_report(report, *, encrypted=False):
    return json.dumps(report.to_dict(encrypted=encrypted), sort_keys=True)


def test_clean_metadata_only_journal_is_upload_safe():
    report = inspect_journal(_journal())

    assert report.valid
    assert not report.has_credentials
    assert not report.contains_sensitive_replay_data
    assert report.sensitive_paths == ()
    assert report.is_upload_safe()
    assert report.upload_blockers() == ()


def test_legacy_version_one_without_sequence_remains_supported():
    data = _journal(version=1)
    data.pop("sequence")
    data.pop("random_state_after")

    report = inspect_journal(data)

    assert report.valid
    assert report.is_upload_safe()


def test_urandom_is_sensitive_and_requires_encryption():
    data = _journal(
        events={
            "time.time": [1_700_000_000.0],
            "urandom": ["ab" * 32],
        },
        sequence=["time.time", "urandom"],
        counts={"time.time": 1, "urandom": 1},
    )

    report = inspect_journal(data)

    assert report.valid
    assert report.sensitive_paths == ("$.events.urandom",)
    assert not report.is_upload_safe()
    assert report.is_upload_safe(encrypted=True)
    assert report.to_dict()["upload"]["allowed"] is False
    assert report.to_dict(encrypted=True)["upload"]["allowed"] is True


def test_random_state_variants_are_sensitive_replay_data():
    state = [3, [1, 2, 3], None]
    report = inspect_journal(
        _journal(random_state=state, random_state_after=[3, [4, 5, 6], 0.5])
    )

    assert report.sensitive_paths == ("$.random_state", "$.random_state_after")
    assert {finding.detector for finding in report.sensitive_findings} == {
        "predictive-random-state"
    }
    assert not report.is_upload_safe()
    assert report.is_upload_safe(encrypted=True)


def test_empty_entropy_queue_and_null_states_are_not_sensitive():
    report = inspect_journal(
        _journal(events={"urandom": []}, sequence=[], counts={"urandom": 0}, random_state_after=None)
    )

    assert not report.contains_sensitive_replay_data
    assert report.is_upload_safe()


@pytest.mark.parametrize(
    ("value", "detector"),
    [
        ("ghp_" + "A" * 36, "github-token"),
        ("github_pat_" + "B" * 40, "github-token"),
        ("glpat-" + "C" * 24, "gitlab-token"),
        ("AKIA" + "D" * 16, "aws-access-key"),
        ("sk_live_" + "E" * 24, "stripe-secret"),
        ("whsec_" + "F" * 24, "stripe-secret"),
        ("xoxb-" + "1234567890-" + "G" * 24, "slack-token"),
        ("AIza" + "H" * 35, "google-api-key"),
        ("sk-proj-" + "I" * 30, "openai-api-key"),
        ("pypi-" + "J" * 30, "pypi-token"),
        ("npm_" + "K" * 30, "npm-token"),
        ("eyJaaaaaa.bbbbbbbb.cccccccc", "jwt"),
        ("Bearer " + "L" * 24, "bearer-token"),
        ("https://build-user:build-password@example.test/path", "credentialed-url"),
        ("api_key=" + "M" * 24, "credential-assignment"),
        (
            "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----",
            "private-key",
        ),
    ],
)
def test_common_credential_patterns_are_detected_without_echoing(value, detector):
    report = inspect_journal(_journal(test=f"tests/test_api.py::test_call[{value}]"))

    assert report.valid
    assert report.has_credentials
    assert not report.is_upload_safe()
    assert not report.is_upload_safe(encrypted=True)
    assert any(
        finding.path == "$.test" and finding.detector == detector
        for finding in report.credential_findings
    )
    rendered = _serialized_report(report, encrypted=True)
    assert value not in rendered
    assert value not in repr(report)


def test_credential_in_network_metadata_is_detected_at_safe_field_path():
    token = "sk_live_" + "N" * 24
    data = _journal()
    data["config"] = {**data["config"], "network": ["api.example.test:443", token]}

    report = inspect_journal(data)

    assert any(
        finding.path == "$.config.network[1]" and finding.detector == "stripe-secret"
        for finding in report.credential_findings
    )
    assert token not in _serialized_report(report)


def test_credential_in_unknown_mapping_key_is_detected_but_key_is_redacted():
    token = "ghp_" + "P" * 36
    data = _journal()
    data[token] = "metadata"

    report = inspect_journal(data)

    assert any(
        finding.path == "$.<redacted-key>" and finding.detector == "github-token"
        for finding in report.credential_findings
    )
    assert token not in _serialized_report(report)


def test_replay_entropy_is_classified_not_pattern_scanned():
    # A random byte stream may coincidentally contain a credential prefix. Its
    # safe handling comes from mandatory encryption, not pattern matching.
    token_bytes = ("ghp_" + "Q" * 36).encode().hex()
    report = inspect_journal(
        _journal(events={"urandom": [token_bytes]}, sequence=["urandom"], counts={"urandom": 1})
    )

    assert report.sensitive_paths == ("$.events.urandom",)
    assert not report.has_credentials
    assert report.is_upload_safe(encrypted=True)


def test_current_environment_secret_value_comparison_is_optional_and_value_free():
    secret = "custom-value-with-no-known-token-prefix"
    data = _journal(test=f"tests/test_service.py::test_case[{secret}]")

    unchecked = inspect_journal(data)
    checked = inspect_journal(
        data,
        current_env={
            "INTERNAL_SERVICE_PASSWORD": secret,
            "NORMAL_SETTING": "not-sensitive",
        },
    )

    assert not unchecked.has_credentials
    assert not unchecked.environment_comparison_performed
    assert checked.environment_comparison_performed
    assert any(
        finding.path == "$.test" and finding.detector == "current-env-secret-value"
        for finding in checked.credential_findings
    )
    rendered = _serialized_report(checked)
    assert secret not in rendered
    assert "INTERNAL_SERVICE_PASSWORD" not in rendered


def test_non_sensitive_environment_names_are_not_compared():
    value = "custom-value-with-no-known-token-prefix"
    report = inspect_journal(
        _journal(test=f"tests/test_service.py::test_case[{value}]"),
        current_env={"DISPLAY_NAME": value},
    )

    assert not report.has_credentials
    assert report.environment_comparison_performed


def test_environment_value_inside_longer_metadata_is_detected():
    secret = "opaque-internal-credential"
    report = inspect_journal(
        _journal(test=f"tests/test_service.py::test_case[prefix-{secret}-suffix]"),
        current_env={"SERVICE_AUTH": secret},
    )

    assert any(
        finding.detector == "current-env-secret-value"
        for finding in report.credential_findings
    )
    assert secret not in _serialized_report(report)


def test_known_schema_fields_are_validated_without_echoing_bad_values():
    bad_value = "definitely-not-a-network-mode"
    data = _journal(format="other-format", version=99, test=123)
    data["config"] = {
        **data["config"],
        "clock": "unknown",
        "rng": [],
        "network": bad_value,
        "fs": "memory",
        "tick": -1,
        "allow_loopback": "yes",
        "deep_datetime": "yes",
        "spin_limit": -1,
        "seed": 1.5,
    }
    data["fingerprint"] = {**data["fingerprint"], "tzname": "UTC"}
    data["events"] = {
        "urandom": ["not-hex"],
        "time.time": ["not-a-number"],
    }
    data["counts"] = {"urandom": -1}

    report = inspect_journal(data)

    assert not report.valid
    paths = {finding.path for finding in report.validation_findings}
    assert {
        "$.format",
        "$.version",
        "$.test",
        "$.config.clock",
        "$.config.rng",
        "$.config.network",
        "$.config.fs",
        "$.config.tick",
        "$.config.allow_loopback",
        "$.config.deep_datetime",
        "$.config.spin_limit",
        "$.config.seed",
        "$.fingerprint.tzname",
        "$.events.urandom[0]",
        "$.events.time.time[0]",
        "$.counts.urandom",
    }.issubset(paths)
    assert not report.is_upload_safe(encrypted=True)
    rendered = _serialized_report(report, encrypted=True)
    assert bad_value not in rendered
    assert "not-hex" not in rendered


def test_missing_required_fields_fail_closed():
    report = inspect_journal({"format": "hermetic-journal", "version": 1})

    assert not report.valid
    assert {
        "$.config",
        "$.fingerprint",
        "$.events",
    }.issubset({finding.path for finding in report.validation_findings})
    assert not report.is_upload_safe()


@pytest.mark.parametrize("field", ["config", "fingerprint", "events", "sequence"])
def test_required_object_or_sequence_fields_cannot_be_null(field):
    report = inspect_journal(_journal(**{field: None}))

    assert not report.valid
    assert any(
        finding.path == f"$.{field}" and finding.code == "invalid-type"
        for finding in report.validation_findings
    )


def test_version_two_requires_post_state_and_global_sequence():
    data = _journal()
    data.pop("random_state_after")
    data.pop("sequence")

    report = inspect_journal(data)

    assert not report.valid
    assert {"$.random_state_after", "$.sequence"}.issubset(
        {finding.path for finding in report.validation_findings}
    )


def test_sequence_must_be_a_list_of_strings():
    report = inspect_journal(_journal(sequence=["time.time", 42]))

    assert not report.valid
    assert any(
        finding.path == "$.sequence" and finding.code == "invalid-type"
        for finding in report.validation_findings
    )


def test_invalid_random_state_structure_is_both_invalid_and_sensitive():
    report = inspect_journal(_journal(random_state=["bad"]))

    assert not report.valid
    assert report.contains_sensitive_replay_data
    assert not report.is_upload_safe(encrypted=True)


def test_inspect_plain_json_and_gzip_paths(tmp_path):
    plain = tmp_path / "journal.json"
    compressed = tmp_path / "journal.json.gz"
    payload = json.dumps(_journal()).encode()
    plain.write_bytes(payload)
    compressed.write_bytes(gzip.compress(payload))
    plain.chmod(0o600)
    compressed.chmod(0o600)

    assert inspect_journal(plain).is_upload_safe()
    assert inspect_journal(compressed).is_upload_safe()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_plaintext_upload_rejects_overly_broad_file_permissions(tmp_path):
    journal = tmp_path / "journal.json"
    journal.write_text(json.dumps(_journal()))
    journal.chmod(0o644)

    report = inspect_journal(journal)

    assert "$file" in report.sensitive_paths
    assert not report.is_upload_safe(encrypted=False)
    assert report.is_upload_safe(encrypted=True)


def test_unreadable_or_invalid_input_returns_value_free_fail_closed_report(tmp_path):
    missing = tmp_path / ("ghp_" + "R" * 36) / "journal.json"
    invalid = tmp_path / "invalid.json"
    secret = "sk_live_" + "S" * 24
    invalid.write_text("{bad-json-" + secret)

    missing_report = inspect_journal(missing)
    invalid_report = inspect_journal(invalid)

    assert not missing_report.valid
    assert not invalid_report.valid
    assert missing_report.validation_findings[0].code == "read-error"
    assert invalid_report.validation_findings[0].code == "parse-error"
    assert str(missing) not in _serialized_report(missing_report)
    assert secret not in _serialized_report(invalid_report)


def test_require_upload_safe_returns_report_for_safe_journal():
    report = require_upload_safe(_journal())

    assert report.valid
    assert report.is_upload_safe()


def test_require_upload_safe_requires_encryption_for_replay_state():
    data = _journal(random_state=[3, [1, 2, 3], None])

    with pytest.raises(JournalUploadBlocked) as excinfo:
        require_upload_safe(data)

    assert "sensitive_replay=1" in str(excinfo.value)
    assert require_upload_safe(data, encrypted=True).is_upload_safe(encrypted=True)


def test_encryption_never_bypasses_metadata_credentials():
    token = "ghp_" + "T" * 36
    report = inspect_journal(_journal(test=f"test_api[{token}]"))

    with pytest.raises(JournalUploadBlocked) as excinfo:
        require_upload_safe(report, encrypted=True)

    assert token not in str(excinfo.value)
    assert excinfo.value.report is report


def test_report_is_json_serializable_and_contains_only_safe_summary_data():
    token = "sk_live_" + "U" * 24
    report = inspect_journal(
        _journal(
            test=f"test_api[{token}]",
            events={"urandom": ["cd" * 16]},
            sequence=["urandom"],
            counts={"urandom": 1},
        )
    )

    payload = report.to_dict()
    rendered = json.dumps(payload)

    assert payload["valid"] is True
    assert payload["has_credentials"] is True
    assert payload["contains_sensitive_replay_data"] is True
    assert payload["upload"]["allowed"] is False
    assert token not in rendered
    assert "cd" * 16 not in rendered


def test_replay_refuses_credential_metadata_without_rendering_value(tmp_path):
    secret = "sk-proj-" + "A" * 32
    data = _journal()
    data["fingerprint"]["platform"] = secret
    path = tmp_path / "journal.json"
    path.write_text(json.dumps(data))
    path.chmod(0o600)

    with pytest.raises(
        hermetic.ReplayMismatch,
        match="metadata may contain a credential",
    ) as caught:
        with hermetic.sandbox(replay=path):
            pass

    assert secret not in str(caught.value)
