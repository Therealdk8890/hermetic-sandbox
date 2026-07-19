"""Network blocking: connect, DNS, loopback/unix rules, allowlists."""

import errno
import socket

import pytest

import hermetic
from hermetic import NetworkBlockedError


def test_connect_blocked_and_catchable_as_stdlib_errors():
    with hermetic.sandbox(seed=1):
        sock = socket.socket()
        try:
            with pytest.raises(NetworkBlockedError):
                sock.connect(("93.184.216.34", 80))
            with pytest.raises(ConnectionRefusedError):
                sock.connect(("93.184.216.34", 80))
            with pytest.raises(OSError):
                sock.connect(("93.184.216.34", 80))
        finally:
            sock.close()


def test_dns_resolution_blocked_before_any_query():
    with hermetic.sandbox(seed=1):
        with pytest.raises(NetworkBlockedError, match="DNS"):
            socket.getaddrinfo("hermetic-test.invalid.example.com", 443)


def test_wildcard_bind_lookup_still_allowed():
    with hermetic.sandbox(seed=1):
        assert socket.getaddrinfo(None, 0, family=socket.AF_INET)


def test_loopback_allowed_by_default():
    with hermetic.sandbox(seed=1):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        client = socket.socket()
        try:
            client.connect(("127.0.0.1", port))
        finally:
            client.close()
            listener.close()


def test_loopback_blocked_when_disallowed():
    with hermetic.sandbox(seed=1, allow_loopback=False):
        sock = socket.socket()
        try:
            with pytest.raises(NetworkBlockedError):
                sock.connect(("127.0.0.1", 9))
        finally:
            sock.close()


def test_allowlist_by_host_and_port():
    with hermetic.sandbox(seed=1, network=["localhost:12345"], allow_loopback=False):
        sock = socket.socket()
        try:
            # allowed host:port — passes hermetic, refused by the OS instead
            with pytest.raises(OSError) as excinfo:
                sock.connect(("localhost", 12345))
            assert not isinstance(excinfo.value, NetworkBlockedError)
        finally:
            sock.close()
        other = socket.socket()
        try:
            with pytest.raises(NetworkBlockedError):
                other.connect(("localhost", 54321))  # same host, other port
        finally:
            other.close()


def test_connect_ex_returns_econnrefused_for_blocked():
    with hermetic.sandbox(seed=1):
        sock = socket.socket()
        try:
            assert sock.connect_ex(("93.184.216.34", 80)) == errno.ECONNREFUSED
        finally:
            sock.close()


def test_udp_sendto_blocked():
    with hermetic.sandbox(seed=1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            with pytest.raises(NetworkBlockedError):
                sock.sendto(b"x", ("8.8.8.8", 53))
        finally:
            sock.close()


def _short_unix_path() -> str:
    # macOS caps AF_UNIX paths at 104 bytes; pytest tmp_path is too deep.
    import tempfile

    return tempfile.mktemp(prefix="hermetic-", suffix=".sock", dir="/tmp")


needs_af_unix = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"), reason="AF_UNIX not available on this platform"
)


@needs_af_unix
def test_unix_sockets_allowed_by_default():
    path = _short_unix_path()
    with hermetic.sandbox(seed=1):
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(path)
        server.listen(1)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.connect(path)
        finally:
            client.close()
            server.close()
            import os

            os.unlink(path)


@needs_af_unix
def test_unix_sockets_blocked_when_disallowed():
    path = _short_unix_path()
    with hermetic.sandbox(seed=1, allow_unix=False):
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            with pytest.raises(NetworkBlockedError):
                client.connect(path)
        finally:
            client.close()


def test_runtime_allow_network():
    with hermetic.sandbox(seed=1, allow_loopback=False) as sb:
        sock = socket.socket()
        try:
            with pytest.raises(NetworkBlockedError):
                sock.connect(("127.0.0.1", 9))
        finally:
            sock.close()
        sb.allow_network("127.0.0.1")
        sock = socket.socket()
        try:
            with pytest.raises(OSError) as excinfo:
                sock.connect(("127.0.0.1", 9))
            assert not isinstance(excinfo.value, NetworkBlockedError)
        finally:
            sock.close()


def test_network_off_leaves_socket_untouched():
    original = socket.socket.connect
    with hermetic.sandbox(seed=1, network="off") as sb:
        assert socket.socket.connect is original
        with pytest.raises(hermetic.SandboxError):
            sb.allow_network("example.com")


def test_socket_module_restored_after_exit():
    originals = (socket.socket.connect, socket.getaddrinfo)
    with hermetic.sandbox(seed=1):
        assert socket.getaddrinfo is not originals[1]
    assert (socket.socket.connect, socket.getaddrinfo) == originals


def test_error_message_names_the_fix():
    with hermetic.sandbox(seed=1):
        with pytest.raises(NetworkBlockedError, match="network="):
            socket.getaddrinfo("api.example.com", 443)


def test_bytes_hostnames_are_handled():
    with hermetic.sandbox(seed=1):
        assert socket.getaddrinfo(b"localhost", 80)  # allowed, no UnicodeError
        with pytest.raises(NetworkBlockedError):
            socket.getaddrinfo(b"blocked.example.com", 80)


def test_hostname_starting_with_127_is_not_loopback():
    with hermetic.sandbox(seed=1):
        with pytest.raises(NetworkBlockedError):
            socket.getaddrinfo("127.evil.example.com", 80)
        # real loopback IPs across 127.0.0.0/8 remain allowed
        sock = socket.socket()
        try:
            with pytest.raises(OSError) as excinfo:
                sock.settimeout(0.2)
                sock.connect(("127.255.0.1", 9))
            assert not isinstance(excinfo.value, NetworkBlockedError)
        finally:
            sock.close()
