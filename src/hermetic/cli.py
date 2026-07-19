"""Command-line workflow for inspecting and replaying Hermetic journals."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from ._envelope import (
    DEFAULT_KEY_ENV,
    EnvelopeError,
    ensure_private_path,
    is_sealed_file,
    seal_file,
    unseal_file,
    validate_key_env_name,
)
from ._errors import SandboxError
from ._journal import JournalReader
from ._random import REAL_OS_URANDOM


class CliError(Exception):
    """An expected command-line usage or journal-discovery error."""


@dataclass(frozen=True)
class _ReplayJournal:
    path: Path
    replay_path: Path
    reader: JournalReader
    sealed: bool = False


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hermetic",
        description="Inspect and replay Hermetic test journals.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    replay = subparsers.add_parser(
        "replay",
        help="Replay a journal with this Python interpreter's pytest.",
        usage=(
            "%(prog)s PATH [--test SELECTOR] [--key-env NAME] "
            "[-- PYTEST_ARGS...]"
        ),
        epilog="Arguments after a bare -- are passed through to pytest.",
    )
    replay.add_argument(
        "path",
        type=Path,
        metavar="PATH",
        help="A journal, index.json, or directory containing journals.",
    )
    replay.add_argument(
        "--test",
        metavar="SELECTOR",
        help="Select a recorded pytest node id (or name an unnamed journal's test).",
    )
    replay.add_argument(
        "--key-env",
        default=DEFAULT_KEY_ENV,
        metavar="NAME",
        help=f"Read a sealed-journal key from NAME (default: {DEFAULT_KEY_ENV}).",
    )

    journal = subparsers.add_parser("journal", help="Work with journal artifacts.")
    journal_subparsers = journal.add_subparsers(
        dest="journal_command", required=True
    )
    inspect_parser = journal_subparsers.add_parser(
        "inspect",
        help="Inspect a journal for sensitive recorded material.",
    )
    inspect_parser.add_argument(
        "path",
        type=Path,
        metavar="PATH",
        help="The journal to inspect.",
    )
    seal_parser = journal_subparsers.add_parser(
        "seal",
        help="Encrypt upload-safe journals with AES-256-GCM.",
        usage="%(prog)s INPUT --output OUTPUT [--key-env NAME]",
    )
    seal_parser.add_argument(
        "input",
        type=Path,
        metavar="INPUT",
        help="A JSON/gzip journal or directory of journals to encrypt.",
    )
    seal_parser.add_argument(
        "--output",
        required=True,
        type=Path,
        metavar="OUTPUT",
        help="Destination envelope file or sealed-only directory.",
    )
    seal_parser.add_argument(
        "--key-env",
        default=DEFAULT_KEY_ENV,
        metavar="NAME",
        help=f"Read the encryption key from NAME (default: {DEFAULT_KEY_ENV}).",
    )
    return parser


def _split_pytest_args(argv: list[str]) -> tuple[list[str], list[str]]:
    """Split ``hermetic`` arguments from pytest arguments after a bare ``--``."""
    try:
        separator = argv.index("--")
    except ValueError:
        return argv, []
    return argv[:separator], argv[separator + 1 :]


def _load_journal(
    path: Path,
    *,
    original_path: Path | None = None,
    sealed: bool = False,
) -> _ReplayJournal:
    from ._security import inspect_journal

    security = inspect_journal(path, current_env=os.environ)
    display = original_path or path
    if not security.valid:
        if sealed:
            raise CliError(f"decrypted journal is invalid: {display}")
        raise CliError(f"journal schema validation failed: {display}")
    if security.has_credentials:
        raise CliError(
            "journal metadata may contain a credential; replay was refused "
            "before rendering metadata"
        )
    try:
        reader = JournalReader.load(path)
    except (SandboxError, OSError, EOFError) as exc:
        if sealed:
            raise CliError(f"decrypted journal is invalid: {display}") from None
        raise CliError(f"cannot load journal {display}: {exc}") from exc
    resolved = path.resolve()
    return _ReplayJournal(
        path=(original_path or path).resolve(),
        replay_path=resolved,
        reader=reader,
        sealed=sealed,
    )


def _is_regular_file(path: Path) -> bool:
    try:
        return stat.S_ISREG(path.stat(follow_symlinks=False).st_mode)
    except OSError:
        return False


def _safe_relative_index_path(index: Path, filename: str) -> Path:
    relative = Path(filename)
    if relative.is_absolute() or ".." in relative.parts:
        raise CliError("journal index contains a path outside its artifact")
    candidate = index.parent / relative
    current = index.parent
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise CliError("journal index contains a symlinked journal")
    try:
        resolved = candidate.resolve()
        root = index.parent.resolve()
    except OSError:
        raise CliError("journal index contains an unreadable path") from None
    if not resolved.is_relative_to(root):
        raise CliError("journal index contains a path outside its artifact")
    if not _is_regular_file(candidate):
        raise CliError("journal index contains a non-regular journal")
    return candidate


def _materialize_journal(
    path: Path,
    *,
    temporary_directory: Path,
    key_env: str,
    position: int,
) -> _ReplayJournal:
    if not is_sealed_file(path):
        return _load_journal(path)
    decrypted = temporary_directory / f"journal-{position}.replay"
    try:
        unseal_file(path, decrypted, key_env=key_env)
    except EnvelopeError as exc:
        raise CliError(f"cannot decrypt sealed journal {path}: {exc}") from None
    return _load_journal(decrypted, original_path=path, sealed=True)


def _journals_from_index(
    path: Path,
    *,
    temporary_directory: Path,
    key_env: str,
) -> list[_ReplayJournal]:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise CliError(f"cannot read journal index {path}: {exc}") from exc

    entries = data.get("journals") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise CliError(f"journal index {path} has no 'journals' list")

    journals: list[_ReplayJournal] = []
    errors: list[str] = []
    for position, entry in enumerate(entries):
        filename = entry.get("file") if isinstance(entry, dict) else None
        if not isinstance(filename, str) or not filename:
            errors.append("an index entry has no journal filename")
            continue
        try:
            journal_path = _safe_relative_index_path(path, filename)
            journals.append(
                _materialize_journal(
                    journal_path,
                    temporary_directory=temporary_directory,
                    key_env=key_env,
                    position=position,
                )
            )
        except CliError as exc:
            errors.append(str(exc))

    journals = _deduplicate(journals)
    if errors:
        raise CliError(
            "journal index contains invalid entries: "
            + "; ".join(sorted(set(errors)))
        )
    if not journals:
        raise CliError(f"journal index {path} contains no readable journals")
    return journals


def _journals_from_directory(
    path: Path,
    *,
    temporary_directory: Path,
    key_env: str,
) -> list[_ReplayJournal]:
    journals: list[_ReplayJournal] = []
    try:
        candidates = sorted(path.rglob("*"))
    except OSError:
        raise CliError(f"cannot search replay directory: {path}") from None
    for position, candidate in enumerate(candidates):
        if candidate.is_symlink():
            raise CliError("replay directory contains a symlink")
        if candidate.is_dir():
            continue
        if not _is_regular_file(candidate):
            raise CliError("replay directory contains a non-regular file")
        sealed = is_sealed_file(candidate)
        if candidate.name == "index.json" and not sealed:
            continue
        if not sealed and not (
            candidate.name.endswith(".json") or candidate.name.endswith(".json.gz")
        ):
            continue
        try:
            journals.append(
                _materialize_journal(
                    candidate,
                    temporary_directory=temporary_directory,
                    key_env=key_env,
                    position=position,
                )
            )
        except CliError:
            if sealed:
                raise
            # Artifact directories can contain manifests and unrelated JSON.
            continue
    journals = _deduplicate(journals)
    if not journals:
        raise CliError(f"no readable Hermetic journals found under {path}")
    return journals


def _deduplicate(journals: list[_ReplayJournal]) -> list[_ReplayJournal]:
    unique: dict[Path, _ReplayJournal] = {}
    for journal in journals:
        unique[journal.path] = journal
    return [unique[path] for path in sorted(unique)]


def _discover(
    path: Path,
    *,
    temporary_directory: Path,
    key_env: str,
) -> list[_ReplayJournal]:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise CliError("replay input must not be a symlink")
    resolved = expanded.resolve()
    if not resolved.exists():
        raise CliError(f"replay path does not exist: {path}")
    if resolved.is_dir():
        return _journals_from_directory(
            resolved,
            temporary_directory=temporary_directory,
            key_env=key_env,
        )
    if not _is_regular_file(resolved):
        raise CliError("replay input must be a regular file or directory")
    if is_sealed_file(resolved):
        return [
            _materialize_journal(
                resolved,
                temporary_directory=temporary_directory,
                key_env=key_env,
                position=0,
            )
        ]
    if resolved.name == "index.json":
        return _journals_from_index(
            resolved,
            temporary_directory=temporary_directory,
            key_env=key_env,
        )
    return [_load_journal(resolved)]


def _display_path(path: Path, source: Path) -> str:
    base = source.resolve()
    if not base.is_dir():
        base = base.parent
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


def _choices(journals: list[_ReplayJournal], source: Path) -> str:
    lines = []
    for journal in journals:
        test = journal.reader.test or "<journal does not name a test>"
        lines.append(f"  {test}\n    {_display_path(journal.path, source)}")
    return "\n".join(lines)


def _select(
    journals: list[_ReplayJournal],
    test_selector: str | None,
    source: Path,
) -> tuple[_ReplayJournal, str | None]:
    if test_selector is not None:
        matches = [
            journal for journal in journals if journal.reader.test == test_selector
        ]
        if len(matches) == 1:
            return matches[0], test_selector
        if len(matches) > 1:
            raise CliError(
                f"multiple journals record {test_selector!r}; pass one journal path:\n"
                f"{_choices(matches, source)}"
            )
        if len(journals) == 1 and journals[0].reader.test is None:
            return journals[0], test_selector
        raise CliError(
            f"no journal records test {test_selector!r}. Available journals:\n"
            f"{_choices(journals, source)}"
        )

    if len(journals) == 1:
        selected = journals[0]
        return selected, selected.reader.test
    raise CliError(
        "multiple replay journals found; pass one journal path or use "
        f"--test SELECTOR:\n{_choices(journals, source)}"
    )


def _replay(
    path: Path,
    test_selector: str | None,
    pytest_args: Sequence[str],
    key_env: str,
) -> int:
    try:
        validate_key_env_name(key_env)
    except EnvelopeError as exc:
        raise CliError(str(exc)) from None
    with tempfile.TemporaryDirectory(prefix="hermetic-replay-") as temporary:
        temporary_directory = Path(temporary)
        try:
            ensure_private_path(temporary_directory, directory=True)
        except EnvelopeError as exc:
            raise CliError(str(exc)) from None
        journals = _discover(
            path,
            temporary_directory=temporary_directory,
            key_env=key_env,
        )
        selected, selected_test = _select(journals, test_selector, path)

        command = [
            sys.executable,
            "-m",
            "pytest",
            f"--hermetic-replay={selected.replay_path}",
        ]
        if selected_test:
            command.append(selected_test)
        command.extend(pytest_args)

        environment = os.environ.copy()
        key_names = {DEFAULT_KEY_ENV.casefold(), key_env.casefold()}
        for name in list(environment):
            if name.casefold() in key_names:
                environment.pop(name, None)
        fingerprint = selected.reader.fingerprint
        if "hash_seed_env" in fingerprint:
            recorded_hash_seed = fingerprint.get("hash_seed_env")
            if recorded_hash_seed is None:
                environment.pop("PYTHONHASHSEED", None)
            else:
                environment["PYTHONHASHSEED"] = str(recorded_hash_seed)

        label = selected_test or "<journal does not name a test>"
        source = _display_path(selected.path, path)
        print(f"hermetic: replaying {label} from {source}", file=sys.stderr)
        completed = subprocess.run(command, env=environment, check=False)
        return completed.returncode


def _journal_inspect(path: Path) -> int:
    """Narrow adapter to the optional journal-security implementation."""
    expanded = path.expanduser()
    if expanded.is_symlink() or not _is_regular_file(expanded):
        raise CliError("journal inspection input must be a regular non-symlink file")
    try:
        from ._security import inspect_journal
    except ImportError:
        print(
            "hermetic: journal inspection is unavailable in this build",
            file=sys.stderr,
        )
        return 2

    report = inspect_journal(expanded)
    print(json.dumps(report.to_dict(encrypted=False), indent=2, sort_keys=True))
    return 0 if report.is_upload_safe(encrypted=False) else 1


def _security_environment(key_env: str) -> dict[str, str]:
    environment = dict(os.environ)
    if key_env in os.environ:
        # The scanner intentionally considers values only from secret-looking
        # variable names. Preserve that safety check even with a custom name.
        alias = "HERMETIC_ENVELOPE_API_KEY"
        existing = {name.casefold() for name in environment}
        while alias.casefold() in existing:
            alias += "_"
        environment[alias] = os.environ[key_env]
    return environment


def _require_encrypted_upload_safe(
    path: Path,
    *,
    key_env: str,
) -> None:
    try:
        from ._security import JournalUploadBlocked, require_upload_safe
    except ImportError:
        raise CliError("journal security inspection is unavailable in this build")

    try:
        require_upload_safe(
            path,
            encrypted=True,
            current_env=_security_environment(key_env),
        )
    except JournalUploadBlocked as exc:
        raise CliError(f"{path}: {exc}") from None


def _raw_journals_in(path: Path) -> list[Path]:
    try:
        candidates = sorted(
            {
                *path.rglob("*.json"),
                *path.rglob("*.json.gz"),
            }
        )
    except OSError:
        raise CliError(f"cannot search journal directory: {path}") from None
    journals = []
    for candidate in candidates:
        if candidate.name == "index.json":
            continue
        if not _is_regular_file(candidate):
            raise CliError(
                "journal directory contains a symlink or non-regular "
                "journal candidate"
            )
        journals.append(candidate)
    if not journals:
        raise CliError(f"no raw Hermetic journals found under {path}")
    return journals


def _opaque_sealed_name(directory: Path) -> Path:
    while True:
        candidate = directory / f"{REAL_OS_URANDOM(16).hex()}.sealed"
        if not candidate.exists():
            return candidate


def _seal_directory(path: Path, output: Path, key_env: str) -> Path:
    source = path.resolve()
    destination = output.expanduser().resolve()
    if destination == source or destination.is_relative_to(source):
        raise CliError("sealed output directory must be outside its input directory")
    if destination.exists():
        raise CliError(f"sealed output already exists: {output}")

    journals = _raw_journals_in(source)
    for journal in journals:
        _require_encrypted_upload_safe(journal, key_env=key_env)

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(
            tempfile.mkdtemp(
                prefix=f".{destination.name}.stage-",
                dir=destination.parent,
            )
        )
    except OSError:
        raise CliError(
            f"cannot create sealed output staging directory: {output}"
        ) from None

    published = False
    try:
        ensure_private_path(staging, directory=True)
        for journal in journals:
            seal_file(
                journal,
                _opaque_sealed_name(staging),
                key_env=key_env,
            )
        if destination.exists():
            raise CliError(f"sealed output already exists: {output}")
        os.replace(staging, destination)
        published = True
    except EnvelopeError as exc:
        raise CliError(str(exc)) from None
    except OSError:
        raise CliError(f"cannot publish sealed output directory: {output}") from None
    finally:
        if not published:
            shutil.rmtree(staging, ignore_errors=True)
    return output


def _journal_seal(path: Path, output: Path, key_env: str) -> int:
    try:
        validate_key_env_name(key_env)
    except EnvelopeError as exc:
        raise CliError(str(exc)) from None
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise CliError("journal input must not be a symlink")
    if expanded.is_dir():
        written = _seal_directory(expanded, output, key_env)
        print(
            f"hermetic: sealed journal directory written to {written}",
            file=sys.stderr,
        )
        return 0
    if not _is_regular_file(expanded):
        raise CliError("journal input must be a regular file or directory")

    _require_encrypted_upload_safe(expanded, key_env=key_env)
    try:
        written = seal_file(expanded, output, key_env=key_env)
    except EnvelopeError as exc:
        raise CliError(str(exc)) from None
    print(f"hermetic: sealed journal written to {written}", file=sys.stderr)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    command_argv, pytest_args = _split_pytest_args(raw_argv)
    parser = _parser()
    namespace = parser.parse_args(command_argv)

    try:
        if namespace.command == "replay":
            return _replay(
                namespace.path,
                namespace.test,
                pytest_args,
                namespace.key_env,
            )
        if pytest_args:
            raise CliError("pytest arguments after '--' are only valid with replay")
        if namespace.command == "journal" and namespace.journal_command == "inspect":
            return _journal_inspect(namespace.path)
        if namespace.command == "journal" and namespace.journal_command == "seal":
            return _journal_seal(
                namespace.input,
                namespace.output,
                namespace.key_env,
            )
    except CliError as exc:
        print(f"hermetic: {exc}", file=sys.stderr)
        return 2

    parser.error("unknown command")
    return 2
