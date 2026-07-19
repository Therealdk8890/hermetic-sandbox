"""Secret-safe journal inspection and fail-closed upload decisions.

Record/replay journals intentionally contain enough state to reproduce random
values.  Raw entropy and ``random`` states therefore have to be treated as
sensitive replay data even when they do not resemble a conventional credential.

This module does not redact replay data: doing so would make the journal
unfaithful.  Instead, it provides a small, zero-dependency audit API for a CLI or
uploader to:

* validate the known journal schema without echoing invalid values;
* identify replay-sensitive fields;
* detect common credential shapes in metadata;
* optionally find values copied from sensitive variables in the current
  environment; and
* make a fail-closed upload decision.

Findings contain only stable codes, safe field paths, detector names, and static
messages.  Matched values are never retained in, or rendered by, a report.
"""

from __future__ import annotations

import gzip
import json
import math
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

JOURNAL_FORMAT = "hermetic-journal"
SUPPORTED_JOURNAL_VERSIONS = frozenset({1, 2})

FindingCategory = Literal["validation", "credential", "sensitive"]
FindingSeverity = Literal["error", "warning"]


@dataclass(frozen=True)
class SecurityFinding:
    """One value-free journal security finding."""

    category: FindingCategory
    code: str
    path: str
    detector: str
    severity: FindingSeverity
    message: str

    def to_dict(self) -> dict[str, str]:
        """Return a JSON-safe representation that contains no matched value."""
        return {
            "category": self.category,
            "code": self.code,
            "path": self.path,
            "detector": self.detector,
            "severity": self.severity,
            "message": self.message,
        }


@dataclass(frozen=True)
class JournalSecurityReport:
    """Structured result of inspecting one journal.

    ``encrypted=True`` means that the caller has established client-side
    encryption for the transport.  It permits replay-sensitive data, but never
    bypasses schema or credential-metadata failures.
    """

    findings: tuple[SecurityFinding, ...]
    environment_comparison_performed: bool = False

    @property
    def validation_findings(self) -> tuple[SecurityFinding, ...]:
        return tuple(finding for finding in self.findings if finding.category == "validation")

    @property
    def credential_findings(self) -> tuple[SecurityFinding, ...]:
        return tuple(finding for finding in self.findings if finding.category == "credential")

    @property
    def sensitive_findings(self) -> tuple[SecurityFinding, ...]:
        return tuple(finding for finding in self.findings if finding.category == "sensitive")

    @property
    def valid(self) -> bool:
        return not self.validation_findings

    @property
    def has_credentials(self) -> bool:
        return bool(self.credential_findings)

    @property
    def sensitive_paths(self) -> tuple[str, ...]:
        return tuple(finding.path for finding in self.sensitive_findings)

    @property
    def contains_sensitive_replay_data(self) -> bool:
        return bool(self.sensitive_findings)

    def upload_blockers(self, *, encrypted: bool = False) -> tuple[SecurityFinding, ...]:
        """Findings that must block an upload under the supplied transport."""
        blockers = [
            finding
            for finding in self.findings
            if finding.category in ("validation", "credential")
            or (finding.category == "sensitive" and not encrypted)
        ]
        return tuple(blockers)

    def is_upload_safe(self, *, encrypted: bool = False) -> bool:
        """Whether a fail-closed uploader may transfer this journal."""
        return not self.upload_blockers(encrypted=encrypted)

    def to_dict(self, *, encrypted: bool = False) -> dict[str, Any]:
        """Return a stable, JSON-safe report containing no discovered values."""
        blockers = self.upload_blockers(encrypted=encrypted)
        return {
            "valid": self.valid,
            "has_credentials": self.has_credentials,
            "contains_sensitive_replay_data": self.contains_sensitive_replay_data,
            "sensitive_paths": list(self.sensitive_paths),
            "environment_comparison_performed": self.environment_comparison_performed,
            "findings": [finding.to_dict() for finding in self.findings],
            "upload": {
                "encrypted": encrypted,
                "allowed": not blockers,
                "blockers": [finding.to_dict() for finding in blockers],
            },
        }


class JournalUploadBlocked(Exception):
    """Raised when a journal does not satisfy the fail-closed upload policy."""

    def __init__(self, report: JournalSecurityReport) -> None:
        self.report = report
        validation = len(report.validation_findings)
        credentials = len(report.credential_findings)
        sensitive = len(report.sensitive_findings)
        super().__init__(
            "hermetic journal upload blocked "
            f"(validation={validation}, credential={credentials}, "
            f"sensitive_replay={sensitive})"
        )


@dataclass(frozen=True)
class _CredentialDetector:
    name: str
    pattern: re.Pattern[str]


def _pattern(expression: str, *, ignore_case: bool = False) -> re.Pattern[str]:
    flags = re.IGNORECASE if ignore_case else 0
    return re.compile(expression, flags)


_CREDENTIAL_DETECTORS = (
    _CredentialDetector(
        "private-key",
        _pattern(r"-----BEGIN (?:[A-Z0-9][A-Z0-9 ]* )?PRIVATE KEY-----"),
    ),
    _CredentialDetector(
        "github-token",
        _pattern(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b"),
    ),
    _CredentialDetector(
        "gitlab-token",
        _pattern(r"\bglpat-[A-Za-z0-9_-]{20,255}\b"),
    ),
    _CredentialDetector(
        "aws-access-key",
        _pattern(r"\b(?:AKIA|ASIA|A3T[A-Z0-9]|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b"),
    ),
    _CredentialDetector(
        "stripe-secret",
        _pattern(r"\b(?:[sr]k_(?:live|test)_[A-Za-z0-9]{16,}|whsec_[A-Za-z0-9]{16,})\b"),
    ),
    _CredentialDetector(
        "slack-token",
        _pattern(r"\bxox[baprs]-[A-Za-z0-9-]{10,255}\b"),
    ),
    _CredentialDetector(
        "google-api-key",
        _pattern(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ),
    _CredentialDetector(
        "openai-api-key",
        _pattern(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,255}\b"),
    ),
    _CredentialDetector(
        "pypi-token",
        _pattern(r"\bpypi-[A-Za-z0-9_-]{20,255}\b"),
    ),
    _CredentialDetector(
        "npm-token",
        _pattern(r"\bnpm_[A-Za-z0-9]{20,255}\b"),
    ),
    _CredentialDetector(
        "jwt",
        _pattern(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
    ),
    _CredentialDetector(
        "bearer-token",
        _pattern(r"\bBearer[ \t]+[A-Za-z0-9._~+/=-]{8,}", ignore_case=True),
    ),
    _CredentialDetector(
        "credentialed-url",
        _pattern(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@", ignore_case=True),
    ),
    _CredentialDetector(
        "credential-assignment",
        _pattern(
            r"(?:api[ _-]?key|secret|token|password|passwd|credential|"
            r"private[ _-]?key|access[ _-]?key|authorization|auth)"
            r"[\"']?[ \t]*(?:=|:)[ \t]*[\"']?[^\s,\"']{8,}",
            ignore_case=True,
        ),
    ),
)

_SENSITIVE_ENV_NAME = re.compile(
    r"(?:secret|token|password|passwd|api_?key|credential|private_?key|"
    r"access_?key|auth)",
    re.IGNORECASE,
)
_SAFE_PATH_SEGMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}\Z")


def _validation(path: str, code: str, message: str) -> SecurityFinding:
    return SecurityFinding(
        category="validation",
        code=code,
        path=path,
        detector="journal-schema",
        severity="error",
        message=message,
    )


def _credential(path: str, detector: str) -> SecurityFinding:
    return SecurityFinding(
        category="credential",
        code="credential-metadata",
        path=path,
        detector=detector,
        severity="error",
        message="credential-like data was detected in journal metadata",
    )


def _sensitive(path: str, detector: str) -> SecurityFinding:
    return SecurityFinding(
        category="sensitive",
        code="sensitive-replay-data",
        path=path,
        detector=detector,
        severity="warning",
        message="replay data requires encrypted transport",
    )


def _is_number(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_string_list(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _append_path(path: str, key: object) -> str:
    text = key if isinstance(key, str) else ""
    if _SAFE_PATH_SEGMENT.fullmatch(text) and not _detectors_for(text):
        return f"{path}.{text}"
    return f"{path}.<redacted-key>"


def _detectors_for(text: str) -> tuple[str, ...]:
    return tuple(
        detector.name
        for detector in _CREDENTIAL_DETECTORS
        if detector.pattern.search(text)
    )


def _validate_required_root(
    data: Mapping[str, Any],
    findings: list[SecurityFinding],
) -> None:
    for key in ("format", "version", "config", "fingerprint", "events"):
        if key not in data:
            findings.append(
                _validation(f"$.{key}", "missing-field", "required journal field is missing")
            )


def _validate_root(data: Mapping[str, Any]) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    _validate_required_root(data, findings)

    if "format" in data:
        if not isinstance(data["format"], str):
            findings.append(_validation("$.format", "invalid-type", "expected a string"))
        elif data["format"] != JOURNAL_FORMAT:
            findings.append(
                _validation("$.format", "invalid-value", "journal format is not supported")
            )

    if "version" in data:
        if not _is_int(data["version"]):
            findings.append(_validation("$.version", "invalid-type", "expected an integer"))
        elif data["version"] not in SUPPORTED_JOURNAL_VERSIONS:
            findings.append(
                _validation("$.version", "unsupported-version", "journal version is not supported")
            )
        elif data["version"] >= 2:
            for key in ("random_state_after", "sequence"):
                if key not in data:
                    findings.append(
                        _validation(
                            f"$.{key}",
                            "missing-field",
                            "required versioned journal field is missing",
                        )
                    )

    if "created_at" in data and not _is_number(data["created_at"]):
        findings.append(_validation("$.created_at", "invalid-type", "expected a finite number"))
    if "test" in data and data["test"] is not None and not isinstance(data["test"], str):
        findings.append(_validation("$.test", "invalid-type", "expected a string or null"))

    if "config" in data:
        _validate_config(data["config"], findings)
    if "fingerprint" in data:
        _validate_fingerprint(data["fingerprint"], findings)
    _validate_random_state(data, "random_state", findings)
    _validate_random_state(data, "random_state_after", findings)
    if "events" in data:
        _validate_events(data["events"], findings)
    if "sequence" in data:
        _validate_sequence(data["sequence"], findings)
    if "counts" in data:
        _validate_counts(data["counts"], findings)
    _validate_optional_string_list(data, "overflow", findings)
    _validate_optional_string_list(data, "concurrency_unfaithful", findings)
    if "env" in data:
        _validate_env(data["env"], findings)
    return findings


def _validate_config(value: object, findings: list[SecurityFinding]) -> None:
    if not isinstance(value, Mapping):
        findings.append(_validation("$.config", "invalid-type", "expected an object"))
        return

    required = ("clock", "rng", "network", "fs")
    for key in required:
        if key not in value:
            findings.append(
                _validation(
                    f"$.config.{key}",
                    "missing-field",
                    "required configuration field is missing",
                )
            )

    enum_fields = {
        "clock": {"virtual", "off"},
        "rng": {"all", "seed", "off"},
        "fs": {"off", "isolate"},
    }
    for key, allowed in enum_fields.items():
        if key not in value:
            continue
        item = value[key]
        if not isinstance(item, str):
            findings.append(_validation(f"$.config.{key}", "invalid-type", "expected a string"))
        elif item not in allowed:
            findings.append(
                _validation(f"$.config.{key}", "invalid-value", "configuration value is not supported")
            )

    if "network" in value:
        network = value["network"]
        if isinstance(network, str):
            if network not in {"block", "off", "allow"}:
                findings.append(
                    _validation(
                        "$.config.network",
                        "invalid-value",
                        "network configuration value is not supported",
                    )
                )
        elif not _is_string_list(network):
            findings.append(
                _validation(
                    "$.config.network",
                    "invalid-type",
                    "expected a mode string or a list of endpoint strings",
                )
            )

    for key in ("now", "tick"):
        if key in value and not _is_number(value[key]):
            findings.append(
                _validation(f"$.config.{key}", "invalid-type", "expected a finite number")
            )
    if "tick" in value and _is_number(value["tick"]) and value["tick"] < 0:
        findings.append(
            _validation("$.config.tick", "invalid-value", "expected a non-negative number")
        )
    for key in ("allow_loopback", "allow_unix", "chdir", "scrub_env", "deep_datetime"):
        if key in value and not isinstance(value[key], bool):
            findings.append(_validation(f"$.config.{key}", "invalid-type", "expected a boolean"))
    if "spin_limit" in value:
        spin_limit = value["spin_limit"]
        if not _is_int(spin_limit):
            findings.append(
                _validation("$.config.spin_limit", "invalid-type", "expected an integer")
            )
        elif spin_limit < 0:
            findings.append(
                _validation(
                    "$.config.spin_limit",
                    "invalid-value",
                    "expected a non-negative integer",
                )
            )
    if "seed" in value and value["seed"] is not None and not _is_int(value["seed"]):
        findings.append(
            _validation("$.config.seed", "invalid-type", "expected an integer or null")
        )


def _validate_fingerprint(value: object, findings: list[SecurityFinding]) -> None:
    if not isinstance(value, Mapping):
        findings.append(_validation("$.fingerprint", "invalid-type", "expected an object"))
        return

    string_or_null = (
        "python",
        "implementation",
        "platform",
        "hostname",
        "tz_env",
        "locale",
        "hash_seed_env",
        "git_sha",
        "git_diff_sha256",
        "test_file_sha256",
        "hermetic_version",
        "pytest_version",
    )
    for key in string_or_null:
        if key in value and value[key] is not None and not isinstance(value[key], str):
            findings.append(
                _validation(
                    f"$.fingerprint.{key}",
                    "invalid-type",
                    "expected a string or null",
                )
            )
    if "cpu_count" in value and value["cpu_count"] is not None and not _is_int(value["cpu_count"]):
        findings.append(
            _validation("$.fingerprint.cpu_count", "invalid-type", "expected an integer or null")
        )
    if "hash_randomization" in value and not isinstance(value["hash_randomization"], bool):
        findings.append(
            _validation("$.fingerprint.hash_randomization", "invalid-type", "expected a boolean")
        )
    if "tzname" in value and not _is_string_list(value["tzname"]):
        findings.append(
            _validation("$.fingerprint.tzname", "invalid-type", "expected a list of strings")
        )


def _validate_random_state(
    data: Mapping[str, Any],
    key: str,
    findings: list[SecurityFinding],
) -> None:
    if key not in data or data[key] is None:
        return
    value = data[key]
    path = f"$.{key}"
    if not isinstance(value, list):
        findings.append(_validation(path, "invalid-type", "expected a random-state list or null"))
        return
    if len(value) != 3:
        findings.append(
            _validation(path, "invalid-value", "random-state list has an invalid structure")
        )
        return
    version, internal, gauss_next = value
    if not _is_int(version):
        findings.append(
            _validation(f"{path}[0]", "invalid-type", "expected an integer state version")
        )
    if not isinstance(internal, list) or not all(_is_int(item) for item in internal):
        findings.append(
            _validation(f"{path}[1]", "invalid-type", "expected a list of state integers")
        )
    if gauss_next is not None and not _is_number(gauss_next):
        findings.append(
            _validation(f"{path}[2]", "invalid-type", "expected a finite number or null")
        )


def _validate_events(value: object, findings: list[SecurityFinding]) -> None:
    if not isinstance(value, Mapping):
        findings.append(_validation("$.events", "invalid-type", "expected an object"))
        return
    for source, queue in value.items():
        path = _append_path("$.events", source)
        if not isinstance(source, str):
            findings.append(_validation(path, "invalid-key-type", "expected a string event source"))
        if not isinstance(queue, list):
            findings.append(_validation(path, "invalid-type", "expected a list of event values"))
            continue
        if source == "urandom":
            for index, item in enumerate(queue):
                item_path = f"{path}[{index}]"
                if not isinstance(item, str):
                    findings.append(_validation(item_path, "invalid-type", "expected a hex string"))
                    continue
                if len(item) % 2 or re.fullmatch(r"[0-9a-fA-F]*", item) is None:
                    findings.append(
                        _validation(item_path, "invalid-value", "entropy value is not valid hex")
                    )
        elif source in ("time.time", "time.monotonic", "time.perf_counter"):
            for index, item in enumerate(queue):
                if not _is_number(item):
                    findings.append(
                        _validation(
                            f"{path}[{index}]",
                            "invalid-type",
                            "expected a finite numeric clock value",
                        )
                    )


def _validate_counts(value: object, findings: list[SecurityFinding]) -> None:
    if not isinstance(value, Mapping):
        findings.append(_validation("$.counts", "invalid-type", "expected an object"))
        return
    for source, count in value.items():
        path = _append_path("$.counts", source)
        if not isinstance(source, str):
            findings.append(_validation(path, "invalid-key-type", "expected a string source"))
        if not _is_int(count) or count < 0:
            findings.append(
                _validation(path, "invalid-value", "expected a non-negative integer count")
            )


def _validate_sequence(value: object, findings: list[SecurityFinding]) -> None:
    if not _is_string_list(value):
        findings.append(
            _validation("$.sequence", "invalid-type", "expected a list of event-source strings")
        )


def _validate_optional_string_list(
    data: Mapping[str, Any],
    key: str,
    findings: list[SecurityFinding],
) -> None:
    if key in data and not _is_string_list(data[key]):
        findings.append(
            _validation(f"$.{key}", "invalid-type", "expected a list of strings")
        )


def _validate_env(value: object, findings: list[SecurityFinding]) -> None:
    if not isinstance(value, Mapping):
        findings.append(_validation("$.env", "invalid-type", "expected an object"))
        return
    if "mode" in value and not isinstance(value["mode"], str):
        findings.append(_validation("$.env.mode", "invalid-type", "expected a string"))
    if "names" in value and not _is_string_list(value["names"]):
        findings.append(
            _validation("$.env.names", "invalid-type", "expected a list of strings")
        )


def _sensitive_findings(data: Mapping[str, Any]) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    for key, detector in (
        ("random_state", "predictive-random-state"),
        ("random_state_after", "predictive-random-state"),
    ):
        if key in data and data[key] is not None:
            findings.append(_sensitive(f"$.{key}", detector))
    events = data.get("events")
    if isinstance(events, Mapping) and events.get("urandom"):
        findings.append(_sensitive("$.events.urandom", "raw-entropy"))
    return findings


def _is_replay_sensitive_path(path: str) -> bool:
    return path in {
        "$.random_state",
        "$.random_state_after",
        "$.events.urandom",
    } or path.startswith(
        (
            "$.random_state[",
            "$.random_state.",
            "$.random_state_after[",
            "$.random_state_after.",
            "$.events.urandom[",
            "$.events.urandom.",
        )
    )


def _metadata_strings(value: object, path: str = "$"):
    """Yield ``(safe_path, string)`` while excluding replay-sensitive values."""
    if _is_replay_sensitive_path(path):
        return
    if isinstance(value, str):
        yield path, value
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            child = _append_path(path, key)
            if isinstance(key, str):
                yield child, key
            if not _is_replay_sensitive_path(child):
                yield from _metadata_strings(item, child)
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            yield from _metadata_strings(item, f"{path}[{index}]")


def _credential_findings(
    data: Mapping[str, Any],
    current_env: Mapping[str, str] | None,
) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    sensitive_env_values: tuple[str, ...] = ()
    if current_env is not None:
        values: list[str] = []
        seen_values: set[str] = set()
        for name, value in current_env.items():
            if not isinstance(name, str) or not isinstance(value, str) or not value:
                continue
            if not _SENSITIVE_ENV_NAME.search(name) or value in seen_values:
                continue
            seen_values.add(value)
            values.append(value)
        sensitive_env_values = tuple(values)

    seen: set[tuple[str, str]] = set()
    for path, text in _metadata_strings(data):
        for detector in _detectors_for(text):
            key = (path, detector)
            if key not in seen:
                seen.add(key)
                findings.append(_credential(path, detector))
        if sensitive_env_values and any(
            text == secret or (len(secret) >= 8 and secret in text)
            for secret in sensitive_env_values
        ):
            key = (path, "current-env-secret-value")
            if key not in seen:
                seen.add(key)
                findings.append(_credential(path, "current-env-secret-value"))
    return findings


def _deduplicate(findings: list[SecurityFinding]) -> tuple[SecurityFinding, ...]:
    unique: list[SecurityFinding] = []
    seen: set[tuple[str, str, str, str]] = set()
    for finding in findings:
        key = (finding.category, finding.code, finding.path, finding.detector)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return tuple(unique)


def _load_path(path: str | os.PathLike[str]) -> tuple[Mapping[str, Any] | None, SecurityFinding | None]:
    try:
        raw = Path(path).read_bytes()
    except (OSError, ValueError, TypeError):
        return None, _validation("$", "read-error", "journal could not be read")
    try:
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        data = json.loads(raw)
    except (OSError, EOFError, UnicodeDecodeError, ValueError):
        return None, _validation("$", "parse-error", "journal is not valid JSON or gzip")
    if not isinstance(data, Mapping):
        return None, _validation("$", "invalid-root", "expected a JSON object")
    return data, None


def inspect_journal(
    source: Mapping[str, Any] | str | os.PathLike[str],
    *,
    current_env: Mapping[str, str] | None = None,
) -> JournalSecurityReport:
    """Inspect a journal mapping or JSON/gzip path.

    Passing ``current_env=os.environ`` additionally detects metadata containing
    values from variables whose names look sensitive.  Neither those values nor
    their variable names are placed in the report.
    """
    environment_compared = current_env is not None
    path_findings: list[SecurityFinding] = []
    if isinstance(source, Mapping):
        data = source
    else:
        if os.name != "nt":
            try:
                if Path(source).stat().st_mode & 0o077:
                    path_findings.append(
                        _sensitive("$file", "unsafe-file-permissions")
                    )
            except (OSError, ValueError, TypeError):
                pass
        loaded_data, load_error = _load_path(source)
        if load_error is not None:
            return JournalSecurityReport(
                findings=(load_error,),
                environment_comparison_performed=environment_compared,
            )
        assert loaded_data is not None
        data = loaded_data

    findings = path_findings + _validate_root(data)
    findings.extend(_sensitive_findings(data))
    findings.extend(_credential_findings(data, current_env))
    return JournalSecurityReport(
        findings=_deduplicate(findings),
        environment_comparison_performed=environment_compared,
    )


def require_upload_safe(
    source: Mapping[str, Any] | str | os.PathLike[str] | JournalSecurityReport,
    *,
    encrypted: bool = False,
    current_env: Mapping[str, str] | None = None,
) -> JournalSecurityReport:
    """Return the report or raise :class:`JournalUploadBlocked`.

    This is the narrow API intended for upload implementations.  Encryption
    permits sensitive replay state, but malformed metadata or credential
    findings always remain blockers.
    """
    report = (
        source
        if isinstance(source, JournalSecurityReport)
        else inspect_journal(source, current_env=current_env)
    )
    if not report.is_upload_safe(encrypted=encrypted):
        raise JournalUploadBlocked(report)
    return report


__all__ = [
    "JournalSecurityReport",
    "JournalUploadBlocked",
    "SecurityFinding",
    "inspect_journal",
    "require_upload_safe",
]
