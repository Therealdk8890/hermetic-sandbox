"""Authenticated encryption envelope for journal artifacts."""

from __future__ import annotations

import base64
import gzip
import inspect
import os
import stat
from pathlib import Path

import pytest

import hermetic
import hermetic._envelope as envelope_module
from hermetic._envelope import (
    HEADER,
    EnvelopeAuthenticationError,
    EnvelopeError,
    EnvelopeFormatError,
    EnvelopeKeyError,
    ensure_private_path,
    is_sealed_file,
    load_key_from_env,
    seal_file,
    unseal_file,
)


def _key(fill: int) -> str:
    return base64.urlsafe_b64encode(bytes([fill]) * 32).decode()


def test_gzip_journal_round_trip_is_randomized_and_private(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMETIC_JOURNAL_KEY", _key(17))
    plaintext = gzip.compress(
        b'{"format":"hermetic-journal","version":1,"events":{"urandom":["cafe"]}}',
        mtime=0,
    )
    source = tmp_path / "failure.json.gz"
    source.write_bytes(plaintext)
    first = tmp_path / "first.sealed"
    second = tmp_path / "second.sealed"

    assert seal_file(source, first) == first
    assert seal_file(source, second) == second
    assert is_sealed_file(first)
    assert first.read_bytes().startswith(HEADER)
    assert plaintext not in first.read_bytes()
    assert first.read_bytes() != second.read_bytes()
    if os.name != "nt":
        assert stat.S_IMODE(first.stat().st_mode) == 0o600
    assert not list(tmp_path.glob(".*.tmp"))

    restored = tmp_path / "restored.json.gz"
    assert unseal_file(first, restored) == restored
    assert restored.read_bytes() == plaintext
    if os.name != "nt":
        assert stat.S_IMODE(restored.stat().st_mode) == 0o600


def test_nonce_uses_real_entropy_inside_repeated_deterministic_sandboxes(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("HERMETIC_JOURNAL_KEY", _key(19))
    source = tmp_path / "journal.json"
    source.write_text('{"format":"hermetic-journal"}')
    first = tmp_path / "first.sealed"
    second = tmp_path / "second.sealed"

    with hermetic.sandbox(seed=12345, rng="all", clock="off", network="off"):
        seal_file(source, first)
    with hermetic.sandbox(seed=12345, rng="all", clock="off", network="off"):
        seal_file(source, second)

    assert first.read_bytes() != second.read_bytes()


def test_wrong_key_and_tampering_fail_authentication_without_key_values(
    tmp_path, monkeypatch
):
    first_key = _key(1)
    second_key = _key(2)
    monkeypatch.setenv("CUSTOM_JOURNAL_KEY", first_key)
    source = tmp_path / "journal.json"
    source.write_text('{"format":"hermetic-journal"}')
    sealed = tmp_path / "journal.sealed"
    seal_file(source, sealed, key_env="CUSTOM_JOURNAL_KEY")

    monkeypatch.setenv("CUSTOM_JOURNAL_KEY", second_key)
    with pytest.raises(EnvelopeAuthenticationError) as wrong:
        unseal_file(
            sealed,
            tmp_path / "wrong-key.json",
            key_env="CUSTOM_JOURNAL_KEY",
        )
    assert first_key not in str(wrong.value)
    assert second_key not in str(wrong.value)

    monkeypatch.setenv("CUSTOM_JOURNAL_KEY", first_key)
    modified = bytearray(sealed.read_bytes())
    modified[-1] ^= 1
    sealed.write_bytes(modified)
    with pytest.raises(EnvelopeAuthenticationError):
        unseal_file(
            sealed,
            tmp_path / "tampered.json",
            key_env="CUSTOM_JOURNAL_KEY",
        )


def test_format_header_and_truncation_are_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMETIC_JOURNAL_KEY", _key(9))
    not_sealed = tmp_path / "plain.json"
    not_sealed.write_bytes(b'{"format":"hermetic-journal"}')
    with pytest.raises(EnvelopeFormatError, match="not a supported"):
        unseal_file(not_sealed, tmp_path / "out.json")

    truncated = tmp_path / "truncated.sealed"
    truncated.write_bytes(HEADER + b"short")
    with pytest.raises(EnvelopeFormatError, match="truncated"):
        unseal_file(truncated, tmp_path / "out.json")

    source = tmp_path / "journal.json"
    source.write_text('{"format":"hermetic-journal"}')
    sealed = tmp_path / "header.sealed"
    seal_file(source, sealed)
    modified = sealed.read_bytes().replace(b'"version":1', b'"version":2', 1)
    sealed.write_bytes(modified)
    with pytest.raises(EnvelopeFormatError, match="not a supported"):
        unseal_file(sealed, tmp_path / "header-output.json")


def test_key_must_come_from_valid_environment_variable(monkeypatch):
    monkeypatch.delenv("MISSING_KEY", raising=False)
    with pytest.raises(EnvelopeKeyError) as missing:
        load_key_from_env("MISSING_KEY")
    assert "MISSING_KEY" not in str(missing.value)

    invalid_value = "this-is-not-a-32-byte-key"
    monkeypatch.setenv("BAD_KEY", invalid_value)
    with pytest.raises(EnvelopeKeyError) as invalid:
        load_key_from_env("BAD_KEY")
    assert invalid_value not in str(invalid.value)

    unpadded = _key(23).rstrip("=")
    monkeypatch.setenv("UNPADDED_KEY", unpadded)
    assert load_key_from_env("UNPADDED_KEY") == bytes([23]) * 32


@pytest.mark.parametrize(
    "name",
    ["", "9KEY", "KEY-NAME", "KEY NAME", "KEY\nforged-log-line"],
)
def test_key_environment_name_is_a_shell_identifier_and_never_rendered(
    name, monkeypatch
):
    monkeypatch.setenv("VALID_KEY", _key(8))
    with pytest.raises(EnvelopeKeyError) as failure:
        load_key_from_env(name)
    if name:
        assert name not in str(failure.value)
    assert "\n" not in str(failure.value)

    key_as_name = _key(8).rstrip("=")
    with pytest.raises(EnvelopeKeyError) as key_failure:
        load_key_from_env(key_as_name)
    assert key_as_name not in str(key_failure.value)


def test_input_and_output_must_be_different(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMETIC_JOURNAL_KEY", _key(4))
    journal = tmp_path / "journal.json"
    journal.write_text("{}")
    with pytest.raises(EnvelopeError, match="must differ"):
        seal_file(journal, journal)
    assert journal.read_text() == "{}"


def test_key_is_not_accepted_as_a_function_argument():
    assert "key" not in inspect.signature(seal_file).parameters
    assert "key" not in inspect.signature(unseal_file).parameters


def test_windows_acl_dispatch_is_fail_closed(tmp_path, monkeypatch):
    target = tmp_path / "private"
    target.mkdir()
    observed = []

    def apply(path, *, directory):
        observed.append((path, directory))
        raise EnvelopeError("could not enforce a private Windows ACL")

    monkeypatch.setattr(envelope_module, "_IS_WINDOWS", True)
    monkeypatch.setattr(envelope_module, "_apply_windows_private_acl", apply)
    with pytest.raises(EnvelopeError, match="private Windows ACL"):
        ensure_private_path(target, directory=True)
    assert observed == [(target, True)]


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows ACL APIs")
@pytest.mark.parametrize("directory", [False, True])
def test_native_windows_acl_is_applied_and_verified(
    directory, tmp_path
):
    target = tmp_path / ("private-directory" if directory else "private-file")
    if directory:
        target.mkdir()
    else:
        target.touch()
    assert ensure_private_path(target, directory=directory) == target


class _FakeWindowsFunction:
    def __init__(self, callback):
        self._callback = callback

    def __call__(self, *args):
        return self._callback(*args)


class _FakeWindowsAclApi:
    def __init__(self, *, invalid_postcondition=False):
        import ctypes
        from ctypes import wintypes
        from types import SimpleNamespace

        class AceHeader(ctypes.Structure):
            _fields_ = [
                ("ace_type", wintypes.BYTE),
                ("ace_flags", wintypes.BYTE),
                ("ace_size", wintypes.WORD),
            ]

        class AccessAllowedAce(ctypes.Structure):
            _fields_ = [
                ("header", AceHeader),
                ("mask", wintypes.DWORD),
                ("sid_start", wintypes.DWORD),
            ]

        self.ctypes = ctypes
        self.wintypes = wintypes
        self.access_allowed_ace = AccessAllowedAce
        self.invalid_postcondition = invalid_postcondition
        self.sid = ctypes.create_string_buffer(12)
        ctypes.memset(self.sid, 1, 12)
        self.acl = ctypes.create_string_buffer(1)
        self.descriptor = ctypes.create_string_buffer(1)
        self.ace = None
        self.ace_flags = None
        self.access_mask = None
        self.security_information = None
        self.closed_handles = []
        self.freed_descriptors = []

        self.advapi32 = SimpleNamespace(
            OpenProcessToken=_FakeWindowsFunction(self.open_process_token),
            GetTokenInformation=_FakeWindowsFunction(self.get_token_information),
            IsValidSid=_FakeWindowsFunction(lambda sid: 1),
            GetLengthSid=_FakeWindowsFunction(lambda sid: 12),
            InitializeAcl=_FakeWindowsFunction(lambda acl, size, revision: 1),
            AddAccessAllowedAceEx=_FakeWindowsFunction(self.add_access_ace),
            SetNamedSecurityInfoW=_FakeWindowsFunction(self.set_named_security),
            GetNamedSecurityInfoW=_FakeWindowsFunction(self.get_named_security),
            GetSecurityDescriptorControl=_FakeWindowsFunction(
                self.get_descriptor_control
            ),
            GetAclInformation=_FakeWindowsFunction(self.get_acl_information),
            GetAce=_FakeWindowsFunction(self.get_ace),
            EqualSid=_FakeWindowsFunction(lambda left, right: 1),
        )
        self.kernel32 = SimpleNamespace(
            GetCurrentProcess=_FakeWindowsFunction(lambda: 1),
            CloseHandle=_FakeWindowsFunction(self.close_handle),
            LocalFree=_FakeWindowsFunction(self.local_free),
        )

    def load(self, name, *, use_last_error):
        assert use_last_error is True
        return self.advapi32 if name == "advapi32" else self.kernel32

    def open_process_token(self, process, access, output):
        assert access == 0x0008
        token = self.ctypes.cast(
            output,
            self.ctypes.POINTER(self.wintypes.HANDLE),
        )
        token.contents.value = 0x1234
        return 1

    def get_token_information(
        self,
        token,
        information_class,
        buffer,
        buffer_size,
        required_size,
    ):
        assert information_class == 1
        size = self.ctypes.cast(
            required_size,
            self.ctypes.POINTER(self.wintypes.DWORD),
        )
        size.contents.value = 16
        if buffer is None:
            return 0
        user = self.ctypes.cast(
            buffer,
            self.ctypes.POINTER(self.wintypes.LPVOID),
        )
        user.contents.value = self.ctypes.addressof(self.sid)
        return 1

    def add_access_ace(self, acl, revision, flags, mask, sid):
        assert revision == 2
        self.ace_flags = flags
        self.access_mask = mask
        ace_size = (
            self.ctypes.sizeof(self.access_allowed_ace)
            - self.ctypes.sizeof(self.wintypes.DWORD)
            + 12
        )
        self.ace = self.ctypes.create_string_buffer(ace_size)
        ace = self.ctypes.cast(
            self.ace,
            self.ctypes.POINTER(self.access_allowed_ace),
        ).contents
        ace.header.ace_type = 0
        ace.header.ace_flags = flags
        ace.header.ace_size = ace_size
        ace.mask = mask
        self.ctypes.memmove(
            self.ctypes.addressof(self.ace)
            + self.access_allowed_ace.sid_start.offset,
            self.sid,
            12,
        )
        return 1

    def set_named_security(
        self,
        path,
        object_type,
        security_information,
        owner,
        group,
        acl,
        sacl,
    ):
        assert object_type == 1
        self.security_information = security_information
        return 0

    def get_named_security(
        self,
        path,
        object_type,
        security_information,
        owner,
        group,
        acl,
        sacl,
        descriptor,
    ):
        acl_pointer = self.ctypes.cast(
            acl,
            self.ctypes.POINTER(self.wintypes.LPVOID),
        )
        acl_pointer.contents.value = self.ctypes.addressof(self.acl)
        descriptor_pointer = self.ctypes.cast(
            descriptor,
            self.ctypes.POINTER(self.wintypes.LPVOID),
        )
        descriptor_pointer.contents.value = self.ctypes.addressof(
            self.descriptor
        )
        return 0

    def get_descriptor_control(self, descriptor, control, revision):
        control_pointer = self.ctypes.cast(
            control,
            self.ctypes.POINTER(self.wintypes.WORD),
        )
        control_pointer.contents.value = 0x1000
        return 1

    def get_acl_information(self, acl, information, size, information_class):
        assert information_class == 2
        values = self.ctypes.cast(
            information,
            self.ctypes.POINTER(self.wintypes.DWORD),
        )
        values[0] = 2 if self.invalid_postcondition else 1
        return 1

    def get_ace(self, acl, index, output):
        assert index == 0
        assert self.ace is not None
        pointer = self.ctypes.cast(
            output,
            self.ctypes.POINTER(self.wintypes.LPVOID),
        )
        pointer.contents.value = self.ctypes.addressof(self.ace)
        return 1

    def close_handle(self, handle):
        self.closed_handles.append(handle.value)
        return 1

    def local_free(self, descriptor):
        self.freed_descriptors.append(descriptor.value)
        return None


@pytest.mark.parametrize(("directory", "expected_flags"), [(False, 0), (True, 3)])
def test_windows_native_acl_uses_protected_single_user_flags(
    directory, expected_flags, tmp_path, monkeypatch
):
    import ctypes

    fake = _FakeWindowsAclApi()
    monkeypatch.setattr(ctypes, "WinDLL", fake.load, raising=False)
    target = tmp_path / "private"
    envelope_module._apply_windows_private_acl(
        target,
        directory=directory,
    )

    assert fake.ace_flags == expected_flags
    assert fake.access_mask == 0x001F01FF
    assert fake.security_information == 0x80000004
    assert fake.closed_handles == [0x1234]
    assert fake.freed_descriptors == [ctypes.addressof(fake.descriptor)]


def test_windows_native_acl_cleans_resources_on_failed_verification(
    tmp_path, monkeypatch
):
    import ctypes

    fake = _FakeWindowsAclApi(invalid_postcondition=True)
    monkeypatch.setattr(ctypes, "WinDLL", fake.load, raising=False)
    with pytest.raises(EnvelopeError, match="private Windows ACL"):
        envelope_module._apply_windows_private_acl(
            tmp_path / "private",
            directory=False,
        )

    assert fake.closed_handles == [0x1234]
    assert fake.freed_descriptors == [ctypes.addressof(fake.descriptor)]


def test_atomic_write_surfaces_failure_to_remove_temporary_output(
    tmp_path, monkeypatch
):
    destination = tmp_path / "output.sealed"
    real_unlink = Path.unlink

    def fail_replace(source, target):
        raise OSError("simulated replace failure")

    def fail_temporary_unlink(path, *args, **kwargs):
        if path.name.startswith(".output.sealed.") and path.suffix == ".tmp":
            raise OSError("simulated cleanup failure")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(envelope_module.os, "replace", fail_replace)
    monkeypatch.setattr(Path, "unlink", fail_temporary_unlink)
    with pytest.raises(EnvelopeError, match="temporary journal output"):
        envelope_module._atomic_private_write(destination, b"ciphertext")
