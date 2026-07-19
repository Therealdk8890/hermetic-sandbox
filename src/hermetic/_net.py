"""Network blocking with a hostname allowlist.

Blocking only ``connect`` is not enough: ``socket.create_connection`` (and
asyncio) resolve DNS via ``socket.getaddrinfo`` *before* connecting — real
network I/O — and by connect time the address is an IP that no hostname
allowlist can match. So the policy is enforced in two places:

- ``socket.getaddrinfo``: blocked hostnames raise before any DNS query leaves
  the machine; resolutions of allowed hostnames are remembered so their IPs
  are accepted at connect time.
- ``socket.socket.connect`` / ``connect_ex`` / ``sendto``: the last line of
  defense, checking the literal address against the allowlist, the loopback
  rule, and previously registered resolutions.

Loopback and unix-domain sockets are allowed by default: both are "this
machine", not the network. ``connect_ex`` preserves its no-raise contract by
returning ``ECONNREFUSED`` for blocked destinations.
"""

from __future__ import annotations

import errno
import ipaddress
import socket as _socket_module
import threading
from typing import Iterable

from ._errors import NetworkBlockedError, SandboxError
from ._patch import PatchSet

REAL_CONNECT = _socket_module.socket.connect
REAL_CONNECT_EX = _socket_module.socket.connect_ex
REAL_SENDTO = _socket_module.socket.sendto
REAL_GETADDRINFO = _socket_module.getaddrinfo

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _normalize_host(host: object) -> str:
    if isinstance(host, bytes):
        raw_host = host
        # The idna codec only supports strict error handling; fall back to a
        # lossy ascii decode for inputs it rejects (IP literals, raw bytes).
        try:
            host = raw_host.decode("idna")
        except UnicodeError:
            host = raw_host.decode("ascii", errors="replace")
    text = str(host).strip().lower().strip("[]")
    return text


def _is_loopback(host: str) -> bool:
    # Only names/addresses that genuinely mean "this machine": a prefix match
    # like "127.evil.example.com" is a hostname, not a loopback IP.
    if host in _LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class NetworkPolicy:
    """Decides which endpoints are reachable inside the sandbox."""

    def __init__(
        self,
        allowlist: Iterable[str] = (),
        allow_loopback: bool = True,
        allow_unix: bool = True,
    ) -> None:
        self.allow_loopback = allow_loopback
        self.allow_unix = allow_unix
        self._entries: set[tuple[str, int | None]] = set()
        self._resolved_ips: dict[str, set[int | None]] = {}
        self._lock = threading.Lock()
        for entry in allowlist:
            self.allow(entry)

    def allow(self, entry: str) -> None:
        """Add ``"host"`` or ``"host:port"`` to the allowlist at runtime."""
        text = str(entry).strip().lower()
        if (
            not text
            or any(ord(char) < 32 or char.isspace() for char in text)
            or "://" in text
            or any(char in text for char in ("@", "/", "?", "#"))
        ):
            raise SandboxError(
                "hermetic: invalid network allowlist entry; expected a hostname, "
                "IP address, host:port, or [IPv6]:port"
            )
        port: int | None = None
        host = text
        # IPv6 literals use [addr]:port; bare IPv6 has multiple colons.
        if text.startswith("["):
            host, _, rest = text.partition("]")
            if not _ or not host:
                raise SandboxError(
                    "hermetic: invalid network allowlist entry; expected [IPv6]:port"
                )
            host = host.lstrip("[")
            if rest.startswith(":"):
                port = _parse_port(rest[1:])
            elif rest:
                raise SandboxError(
                    "hermetic: invalid network allowlist entry; unexpected text "
                    "after the IPv6 literal"
                )
        elif text.count(":") == 1:
            host, _, port_text = text.partition(":")
            port = _parse_port(port_text)
        elif text.count(":") > 1:
            try:
                ipaddress.IPv6Address(text)
            except ValueError as exc:
                raise SandboxError(
                    "hermetic: invalid network allowlist entry; bracket an IPv6 "
                    "literal when specifying a port"
                ) from exc
        normalized = _normalize_host(host)
        if not normalized or not _valid_host(normalized):
            raise SandboxError(
                "hermetic: invalid network allowlist host; expected a hostname "
                "or IP address"
            )
        with self._lock:
            self._entries.add((normalized, port))

    def _entry_allows(self, host: str, port: int | None) -> bool:
        return ((host, None) in self._entries
                or (host, port) in self._entries)

    def allows_host(self, host: object, port: int | None) -> bool:
        """Check a hostname/IP before resolution or connection."""
        text = _normalize_host(host)
        with self._lock:
            if self.allow_loopback and _is_loopback(text):
                return True
            if self._entry_allows(text, port):
                return True
            allowed_ports = self._resolved_ips.get(text)
            if allowed_ports is not None and (None in allowed_ports or port in allowed_ports):
                return True
        return False

    def register_resolution(self, host: object, port: int | None, addrinfo: list) -> None:
        """Remember the IPs an allowed hostname resolved to, so connect() to
        those IPs (on the same port) passes the last-line check."""
        with self._lock:
            for family, _type, _proto, _canon, sockaddr in addrinfo:
                if family in (_socket_module.AF_INET, _socket_module.AF_INET6):
                    ip = _normalize_host(sockaddr[0])
                    self._resolved_ips.setdefault(ip, set()).add(port)


def _parse_port(text: str) -> int:
    try:
        port = int(text)
    except (TypeError, ValueError) as exc:
        raise SandboxError(
            "hermetic: invalid network allowlist port; expected 1 through 65535"
        ) from exc
    if not 1 <= port <= 65535:
        raise SandboxError(
            "hermetic: invalid network allowlist port; expected 1 through 65535"
        )
    return port


def _valid_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if len(host) > 253:
        return False
    labels = host.rstrip(".").split(".")
    return all(
        label
        and len(label) <= 63
        and label[0].isalnum()
        and label[-1].isalnum()
        and all(char.isalnum() or char in "-_" for char in label)
        for label in labels
    )

def _address_endpoint(address: object) -> tuple[object, int | None] | None:
    """Extract (host, port) from a sockaddr; None means "not an inet address"."""
    if isinstance(address, tuple) and len(address) >= 2:
        return address[0], address[1]
    return None  # unix path (str/bytes) or exotic family


def _check(policy: NetworkPolicy, sock: object, address: object) -> None:
    endpoint = _address_endpoint(address)
    if endpoint is None:
        if policy.allow_unix:
            return
        raise NetworkBlockedError(address, "unix sockets are blocked (allow_unix=False)")
    host, port = endpoint
    if not policy.allows_host(host, port):
        raise NetworkBlockedError((host, port))


def install_network_patches(patches: PatchSet, policy: NetworkPolicy) -> None:
    def connect(self, address):
        _check(policy, self, address)
        return REAL_CONNECT(self, address)

    def connect_ex(self, address):
        try:
            _check(policy, self, address)
        except NetworkBlockedError:
            return errno.ECONNREFUSED
        return REAL_CONNECT_EX(self, address)

    def sendto(self, data, *args):
        # sendto(data, address) or sendto(data, flags, address)
        if args:
            _check(policy, self, args[-1])
        return REAL_SENDTO(self, data, *args)

    def getaddrinfo(host, port, *args, **kwargs):
        if host in (None, "", b""):
            # Wildcard/bind lookups (AI_PASSIVE) are local, not network traffic.
            return REAL_GETADDRINFO(host, port, *args, **kwargs)
        port_num: int | None
        try:
            port_num = int(port) if port is not None else None
        except (TypeError, ValueError):
            port_num = None  # service names like "https"; match host-only entries
        if not policy.allows_host(host, port_num):
            raise NetworkBlockedError(
                (host, port), "DNS resolution is blocked inside hermetic.sandbox()"
            )
        result = REAL_GETADDRINFO(host, port, *args, **kwargs)
        policy.register_resolution(host, port_num, result)
        return result

    patches.setattr(_socket_module.socket, "connect", connect)
    patches.setattr(_socket_module.socket, "connect_ex", connect_ex)
    patches.setattr(_socket_module.socket, "sendto", sendto)
    patches.setattr(_socket_module, "getaddrinfo", getaddrinfo)
