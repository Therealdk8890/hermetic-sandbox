"""Authenticated client-side encryption for replay journal artifacts.

The envelope deliberately treats a journal as opaque bytes.  A JSON or gzip
journal therefore round-trips without changing replay semantics, while the
fixed format/version/cipher header is authenticated as AES-GCM associated data.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import tempfile
from pathlib import Path

from ._random import REAL_OS_URANDOM

DEFAULT_KEY_ENV = "HERMETIC_JOURNAL_KEY"
HEADER = (
    b'{"cipher":"AES-256-GCM","format":"hermetic-sealed-journal","version":1}\n'
)
NONCE_SIZE = 12
TAG_SIZE = 16
_URLSAFE_BASE64 = re.compile(r"[A-Za-z0-9_-]+={0,2}\Z")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_IS_WINDOWS = os.name == "nt"


class EnvelopeError(Exception):
    """Base class for safe-to-render envelope failures."""


class EnvelopeDependencyError(EnvelopeError):
    """The optional cryptography dependency is not installed."""


class EnvelopeKeyError(EnvelopeError):
    """The configured environment variable does not contain a valid key."""


class EnvelopeFormatError(EnvelopeError):
    """The input is not a supported sealed-journal envelope."""


class EnvelopeAuthenticationError(EnvelopeError):
    """The envelope was modified or decrypted with the wrong key."""


def _aesgcm_types():
    try:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise EnvelopeDependencyError(
            "journal encryption requires hermetic-sandbox[secure]"
        ) from exc
    return AESGCM, InvalidTag


def validate_key_env_name(name: str) -> str:
    """Validate a shell-compatible variable name before it can reach output."""
    if _ENV_NAME.fullmatch(name) is None:
        raise EnvelopeKeyError("the journal key environment variable name is invalid")
    return name


def load_key_from_env(name: str = DEFAULT_KEY_ENV) -> bytes:
    """Read and decode one 32-byte URL-safe-base64 key from ``name``.

    Error messages intentionally describe only the variable and requirement;
    the configured value is never included.
    """
    validate_key_env_name(name)
    value = os.environ.get(name)
    if value is None:
        raise EnvelopeKeyError(
            "journal encryption key environment variable is not set"
        )
    if _URLSAFE_BASE64.fullmatch(value) is None:
        raise EnvelopeKeyError(
            "journal encryption key must be URL-safe base64"
        )
    encoded = value.encode("ascii")
    encoded += b"=" * (-len(encoded) % 4)
    try:
        key = base64.b64decode(encoded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        raise EnvelopeKeyError(
            "journal encryption key must be URL-safe base64"
        ) from None
    if len(key) != 32:
        raise EnvelopeKeyError(
            "journal encryption key must decode to exactly 32 bytes"
        )
    return key


def is_sealed_file(path: str | os.PathLike[str]) -> bool:
    """Return whether ``path`` begins with the supported envelope header."""
    try:
        with Path(path).open("rb") as stream:
            return stream.read(len(HEADER)) == HEADER
    except OSError:
        return False


def _seal_bytes(plaintext: bytes, key: bytes) -> bytes:
    AESGCM, _ = _aesgcm_types()
    # Hermetic intentionally patches os.urandom. Envelope nonces must remain
    # real CSPRNG output even if a caller seals from inside a sandbox.
    nonce = REAL_OS_URANDOM(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, HEADER)
    return HEADER + nonce + ciphertext


def _unseal_bytes(envelope: bytes, key: bytes) -> bytes:
    if not envelope.startswith(HEADER):
        raise EnvelopeFormatError(
            "file is not a supported Hermetic sealed journal"
        )
    payload = envelope[len(HEADER) :]
    if len(payload) < NONCE_SIZE + TAG_SIZE:
        raise EnvelopeFormatError("sealed journal is truncated")
    nonce = payload[:NONCE_SIZE]
    ciphertext = payload[NONCE_SIZE:]
    AESGCM, InvalidTag = _aesgcm_types()
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, HEADER)
    except InvalidTag:
        raise EnvelopeAuthenticationError(
            "sealed journal authentication failed (wrong key or modified file)"
        ) from None


def _read_bytes(path: Path, *, description: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError:
        raise EnvelopeError(f"{description} could not be read: {path}") from None


def _apply_windows_private_acl(path: Path, *, directory: bool) -> None:
    """Install and verify a protected one-ACE DACL for the process user."""
    token = None
    security_descriptor = None
    kernel32 = None
    try:
        import ctypes
        from ctypes import wintypes

        class SidAndAttributes(ctypes.Structure):
            _fields_ = [
                ("sid", wintypes.LPVOID),
                ("attributes", wintypes.DWORD),
            ]

        class TokenUser(ctypes.Structure):
            _fields_ = [("user", SidAndAttributes)]

        class Acl(ctypes.Structure):
            _fields_ = [
                ("revision", wintypes.BYTE),
                ("sbz1", wintypes.BYTE),
                ("size", wintypes.WORD),
                ("ace_count", wintypes.WORD),
                ("sbz2", wintypes.WORD),
            ]

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

        class AclSizeInformation(ctypes.Structure):
            _fields_ = [
                ("ace_count", wintypes.DWORD),
                ("bytes_in_use", wintypes.DWORD),
                ("bytes_free", wintypes.DWORD),
            ]

        win_dll = getattr(ctypes, "WinDLL", None)
        if win_dll is None:
            raise EnvelopeError("could not enforce a private Windows ACL")
        advapi32 = win_dll("advapi32", use_last_error=True)
        kernel32 = win_dll("kernel32", use_last_error=True)
        advapi32.OpenProcessToken.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.HANDLE),
        ]
        advapi32.OpenProcessToken.restype = wintypes.BOOL
        advapi32.GetTokenInformation.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        advapi32.GetTokenInformation.restype = wintypes.BOOL
        advapi32.IsValidSid.argtypes = [wintypes.LPVOID]
        advapi32.IsValidSid.restype = wintypes.BOOL
        advapi32.GetLengthSid.argtypes = [wintypes.LPVOID]
        advapi32.GetLengthSid.restype = wintypes.DWORD
        advapi32.InitializeAcl.argtypes = [
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        advapi32.InitializeAcl.restype = wintypes.BOOL
        advapi32.AddAccessAllowedAceEx.argtypes = [
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
        ]
        advapi32.AddAccessAllowedAceEx.restype = wintypes.BOOL
        advapi32.SetNamedSecurityInfoW.argtypes = [
            wintypes.LPWSTR,
            ctypes.c_int,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.LPVOID,
            wintypes.LPVOID,
            wintypes.LPVOID,
        ]
        advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
        advapi32.GetNamedSecurityInfoW.argtypes = [
            wintypes.LPWSTR,
            ctypes.c_int,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.LPVOID),
            ctypes.POINTER(wintypes.LPVOID),
            ctypes.POINTER(wintypes.LPVOID),
            ctypes.POINTER(wintypes.LPVOID),
            ctypes.POINTER(wintypes.LPVOID),
        ]
        advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
        advapi32.GetSecurityDescriptorControl.argtypes = [
            wintypes.LPVOID,
            ctypes.POINTER(wintypes.WORD),
            ctypes.POINTER(wintypes.DWORD),
        ]
        advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
        advapi32.GetAclInformation.argtypes = [
            wintypes.LPVOID,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.c_int,
        ]
        advapi32.GetAclInformation.restype = wintypes.BOOL
        advapi32.GetAce.argtypes = [
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.LPVOID),
        ]
        advapi32.GetAce.restype = wintypes.BOOL
        advapi32.EqualSid.argtypes = [wintypes.LPVOID, wintypes.LPVOID]
        advapi32.EqualSid.restype = wintypes.BOOL
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.LocalFree.argtypes = [wintypes.LPVOID]
        kernel32.LocalFree.restype = wintypes.LPVOID

        token_handle = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            0x0008,
            ctypes.byref(token_handle),
        ):
            raise EnvelopeError("could not enforce a private Windows ACL")
        token = token_handle

        token_size = wintypes.DWORD()
        advapi32.GetTokenInformation(
            token,
            1,
            None,
            0,
            ctypes.byref(token_size),
        )
        if token_size.value == 0:
            raise EnvelopeError("could not enforce a private Windows ACL")
        token_buffer = ctypes.create_string_buffer(token_size.value)
        if not advapi32.GetTokenInformation(
            token,
            1,
            token_buffer,
            token_size,
            ctypes.byref(token_size),
        ):
            raise EnvelopeError("could not enforce a private Windows ACL")
        sid = ctypes.cast(
            token_buffer,
            ctypes.POINTER(TokenUser),
        ).contents.user.sid
        if not sid or not advapi32.IsValidSid(sid):
            raise EnvelopeError("could not enforce a private Windows ACL")

        sid_length = advapi32.GetLengthSid(sid)
        if sid_length == 0:
            raise EnvelopeError("could not enforce a private Windows ACL")
        acl_size = (
            ctypes.sizeof(Acl)
            + ctypes.sizeof(AccessAllowedAce)
            - ctypes.sizeof(wintypes.DWORD)
            + sid_length
            + 3
        ) & ~3
        acl_buffer = ctypes.create_string_buffer(acl_size)
        acl = ctypes.cast(acl_buffer, wintypes.LPVOID)
        if not advapi32.InitializeAcl(acl, acl_size, 2):
            raise EnvelopeError("could not enforce a private Windows ACL")
        ace_flags = 0x03 if directory else 0
        file_all_access = 0x001F01FF
        if not advapi32.AddAccessAllowedAceEx(
            acl,
            2,
            ace_flags,
            file_all_access,
            sid,
        ):
            raise EnvelopeError("could not enforce a private Windows ACL")

        security_information = 0x00000004 | 0x80000000
        result = advapi32.SetNamedSecurityInfoW(
            str(path),
            1,
            security_information,
            None,
            None,
            acl,
            None,
        )
        if result != 0:
            raise EnvelopeError("could not enforce a private Windows ACL")

        actual_acl = wintypes.LPVOID()
        actual_descriptor = wintypes.LPVOID()
        result = advapi32.GetNamedSecurityInfoW(
            str(path),
            1,
            0x00000004,
            None,
            None,
            ctypes.byref(actual_acl),
            None,
            ctypes.byref(actual_descriptor),
        )
        if result != 0 or not actual_acl or not actual_descriptor:
            raise EnvelopeError("could not enforce a private Windows ACL")
        security_descriptor = actual_descriptor

        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not advapi32.GetSecurityDescriptorControl(
            security_descriptor,
            ctypes.byref(control),
            ctypes.byref(revision),
        ) or not (control.value & 0x1000):
            raise EnvelopeError("could not enforce a private Windows ACL")
        acl_info = AclSizeInformation()
        if not advapi32.GetAclInformation(
            actual_acl,
            ctypes.byref(acl_info),
            ctypes.sizeof(acl_info),
            2,
        ) or acl_info.ace_count != 1:
            raise EnvelopeError("could not enforce a private Windows ACL")
        ace_pointer = wintypes.LPVOID()
        if not advapi32.GetAce(actual_acl, 0, ctypes.byref(ace_pointer)):
            raise EnvelopeError("could not enforce a private Windows ACL")
        if ace_pointer.value is None:
            raise EnvelopeError("could not enforce a private Windows ACL")
        ace = ctypes.cast(
            ace_pointer,
            ctypes.POINTER(AccessAllowedAce),
        ).contents
        expected_ace_size = (
            ctypes.sizeof(AccessAllowedAce)
            - ctypes.sizeof(wintypes.DWORD)
            + sid_length
        )
        actual_sid = wintypes.LPVOID(
            ace_pointer.value + AccessAllowedAce.sid_start.offset
        )
        if (
            ace.header.ace_type != 0
            or ace.header.ace_flags != ace_flags
            or ace.header.ace_size != expected_ace_size
            or ace.mask != file_all_access
            or not advapi32.EqualSid(actual_sid, sid)
        ):
            raise EnvelopeError("could not enforce a private Windows ACL")
    except EnvelopeError:
        raise
    except Exception:
        raise EnvelopeError(
            "could not enforce a private Windows ACL"
        ) from None
    finally:
        if security_descriptor and kernel32 is not None:
            try:
                kernel32.LocalFree(security_descriptor)
            except Exception:
                pass
        if token and kernel32 is not None:
            try:
                kernel32.CloseHandle(token)
            except Exception:
                pass


def ensure_private_path(
    path: str | os.PathLike[str],
    *,
    directory: bool = False,
) -> Path:
    """Enforce owner-only access or fail before private data is written."""
    private_path = Path(path)
    try:
        if _IS_WINDOWS:
            _apply_windows_private_acl(private_path, directory=directory)
        else:
            os.chmod(private_path, 0o700 if directory else 0o600)
    except OSError:
        raise EnvelopeError("could not enforce private journal permissions") from None
    return private_path


def _atomic_private_write(path: Path, contents: bytes) -> Path:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
        )
    except OSError:
        raise EnvelopeError(
            f"sealed journal output could not be created: {path}"
        ) from None

    temporary = Path(temporary_name)
    write_failure: EnvelopeError | None = None
    cleanup_failure: EnvelopeError | None = None
    try:
        if os.name == "nt":
            _apply_windows_private_acl(temporary, directory=False)
        elif hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        else:
            ensure_private_path(temporary)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        ensure_private_path(path)
    except EnvelopeError as exc:
        write_failure = exc
    except OSError:
        write_failure = EnvelopeError(
            f"sealed journal output could not be written: {path}"
        )
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            cleanup_failure = EnvelopeError(
                "temporary journal output could not be removed"
            )
    if cleanup_failure is not None:
        raise cleanup_failure
    if write_failure is not None:
        raise write_failure
    return path


def seal_file(
    source: str | os.PathLike[str],
    destination: str | os.PathLike[str],
    *,
    key_env: str = DEFAULT_KEY_ENV,
) -> Path:
    """Encrypt ``source`` into an atomically-written mode-0600 envelope."""
    source_path = Path(source)
    destination_path = Path(destination)
    if source_path.resolve() == destination_path.resolve():
        raise EnvelopeError("sealed journal output must differ from its input")
    key = load_key_from_env(key_env)
    plaintext = _read_bytes(source_path, description="journal input")
    envelope = _seal_bytes(plaintext, key)
    return _atomic_private_write(destination_path, envelope)


def unseal_file(
    source: str | os.PathLike[str],
    destination: str | os.PathLike[str],
    *,
    key_env: str = DEFAULT_KEY_ENV,
) -> Path:
    """Decrypt ``source`` into an atomically-written mode-0600 file."""
    source_path = Path(source)
    destination_path = Path(destination)
    if source_path.resolve() == destination_path.resolve():
        raise EnvelopeError("decrypted journal output must differ from its input")
    key = load_key_from_env(key_env)
    envelope = _read_bytes(source_path, description="sealed journal")
    plaintext = _unseal_bytes(envelope, key)
    return _atomic_private_write(destination_path, plaintext)


__all__ = [
    "DEFAULT_KEY_ENV",
    "EnvelopeAuthenticationError",
    "EnvelopeDependencyError",
    "EnvelopeError",
    "EnvelopeFormatError",
    "EnvelopeKeyError",
    "HEADER",
    "ensure_private_path",
    "is_sealed_file",
    "load_key_from_env",
    "seal_file",
    "unseal_file",
    "validate_key_env_name",
]
