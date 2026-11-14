"""Outbound connections: plain TCP, SOCKS5 (RFC 1928/1929) and HTTP CONNECT.

Every socket created here carries the daemon's firewall mark, which is the only
thing the firewall lets out to the network. Handshakes run on the raw socket so
the caller receives a connected, ready-to-relay socket.
"""

import asyncio
import base64
import ipaddress
import os
import socket
import struct
import time
from collections import namedtuple

ProxySettings = namedtuple("ProxySettings", "type host port username password")

SO_MARK = getattr(socket, "SO_MARK", 36)
CONNECT_TIMEOUT = 8.0
HANDSHAKE_TIMEOUT = 15.0

_SOCKS_ERRORS = {
    1: "general proxy failure",
    2: "connection not allowed by the proxy",
    3: "network unreachable",
    4: "host unreachable",
    5: "connection refused",
    6: "TTL expired",
    7: "command not supported",
    8: "address type not supported",
}


class ProxyError(Exception):
    """kind: unreachable | auth | refused | protocol | timeout | config"""

    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


def ip_version(host):
    try:
        return ipaddress.ip_address(host).version
    except ValueError:
        return 0


def new_socket(family, kind=socket.SOCK_STREAM, mark=0):
    sock = socket.socket(family, kind)
    try:
        sock.setblocking(False)
        if mark:
            sock.setsockopt(socket.SOL_SOCKET, SO_MARK, mark)
        if kind == socket.SOCK_STREAM:
            tune_stream(sock)
    except BaseException:
        sock.close()
        raise
    return sock


def tune_stream(sock):
    """Low latency plus keep-alives so that dead peers are reaped."""
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 15)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 4)
    except OSError:
        pass


async def tcp_connect(ip, port, mark=0, timeout=CONNECT_TIMEOUT):
    """Open a marked TCP connection to a literal address."""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sock = new_socket(family, mark=mark)
    try:
        await asyncio.wait_for(asyncio.get_running_loop().sock_connect(sock, (ip, port)), timeout)
    except BaseException:
        sock.close()
        raise
    return sock


async def _recv_exact(loop, sock, count):
    buf = bytearray()
    while len(buf) < count:
        chunk = await loop.sock_recv(sock, count - len(buf))
        if not chunk:
            raise ProxyError("protocol", "the proxy closed the connection")
        buf += chunk
    return bytes(buf)


async def _socks5_auth(loop, sock, proxy):
    methods = b"\x00\x02" if proxy.username else b"\x00"
    await loop.sock_sendall(sock, bytes([5, len(methods)]) + methods)
    version, method = await _recv_exact(loop, sock, 2)
    if version != 5:
        raise ProxyError("protocol", "the server is not a SOCKS5 proxy")
    if method == 2:
        user, password = proxy.username.encode(), proxy.password.encode()
        await loop.sock_sendall(
            sock, bytes([1, len(user)]) + user + bytes([len(password)]) + password)
        _, status = await _recv_exact(loop, sock, 2)
        if status != 0:
            raise ProxyError("auth", "the proxy rejected the username or password")
    elif method == 0xFF:
        raise ProxyError("auth", "the proxy rejected the username or password" if proxy.username
                         else "the proxy requires a username and password")
    elif method != 0:
        raise ProxyError("protocol", f"the proxy chose an unsupported auth method ({method})")


async def _socks5_connect(loop, sock, host, port):
    version = ip_version(host)
    if version == 4:
        address = b"\x01" + socket.inet_aton(host)
    elif version == 6:
        address = b"\x04" + socket.inet_pton(socket.AF_INET6, host)
    else:
        name = host.encode("ascii", "ignore")
        if not 0 < len(name) < 256:
            raise ProxyError("protocol", "host name too long for SOCKS5")
        address = bytes([3, len(name)]) + name
    await loop.sock_sendall(sock, b"\x05\x01\x00" + address + struct.pack("!H", port))
    version, reply, _, atyp = await _recv_exact(loop, sock, 4)
    if version != 5:
        raise ProxyError("protocol", "malformed SOCKS5 reply")
    if reply != 0:
        raise ProxyError("refused", _SOCKS_ERRORS.get(reply, f"SOCKS5 error {reply}"))
    if atyp == 1:
        await _recv_exact(loop, sock, 6)
    elif atyp == 4:
        await _recv_exact(loop, sock, 18)
    elif atyp == 3:
        length = (await _recv_exact(loop, sock, 1))[0]
        await _recv_exact(loop, sock, length + 2)
    else:
        raise ProxyError("protocol", "malformed SOCKS5 reply")
    return b""


async def _http_connect(loop, sock, proxy, host, port):
    target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}", "Proxy-Connection: keep-alive"]
    if proxy.username:
        token = base64.b64encode(f"{proxy.username}:{proxy.password}".encode()).decode()
        lines.append(f"Proxy-Authorization: Basic {token}")
    await loop.sock_sendall(sock, ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace"))
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        if len(buf) > 16384:
            raise ProxyError("protocol", "oversized reply from the HTTP proxy")
        chunk = await loop.sock_recv(sock, 4096)
        if not chunk:
            raise ProxyError("protocol", "the proxy closed the connection")
        buf += chunk
    head, _, leftover = bytes(buf).partition(b"\r\n\r\n")
    status = head.split(b"\r\n", 1)[0].decode("latin-1").split(None, 2)
    if len(status) < 2 or not status[0].startswith("HTTP/") or not status[1].isdigit():
        raise ProxyError("protocol", "the server is not an HTTP proxy")
    code = int(status[1])
    if code == 407:
        raise ProxyError("auth", "the proxy rejected the username or password" if proxy.username
                         else "the proxy requires a username and password")
    if not 200 <= code < 300:
        reason = status[2] if len(status) > 2 else ""
        raise ProxyError("refused", f"the proxy answered {code} {reason}".strip())
    return leftover  # bytes the target already sent behind the reply


async def _connect_any(proxy, proxy_ips, mark, timeout):
    if not proxy.host:
        raise ProxyError("config", "no proxy is configured")
    error = None
    for ip in list(proxy_ips)[:3]:
        try:
            return await tcp_connect(ip, proxy.port, mark, timeout)
        except asyncio.TimeoutError:
            error = f"cannot reach the proxy at {ip}:{proxy.port}: timed out"
        except OSError as exc:
            reason = os.strerror(exc.errno) if exc.errno else str(exc)
            error = f"cannot reach the proxy at {ip}:{proxy.port}: {reason}"
    raise ProxyError("unreachable", error or "the proxy host has no address")


async def dial(proxy, proxy_ips, host, port, mark=0,
               connect_timeout=CONNECT_TIMEOUT, handshake_timeout=HANDSHAKE_TIMEOUT):
    """Connect to ``host:port`` through the proxy.

    Returns ``(socket, leftover)`` where *leftover* is payload that arrived
    together with the proxy's reply and must be delivered to the client first.
    """
    sock = await _connect_any(proxy, proxy_ips, mark, connect_timeout)
    loop = asyncio.get_running_loop()

    async def handshake():
        if proxy.type == "socks5":
            await _socks5_auth(loop, sock, proxy)
            return await _socks5_connect(loop, sock, host, port)
        return await _http_connect(loop, sock, proxy, host, port)

    try:
        return sock, await asyncio.wait_for(handshake(), handshake_timeout)
    except asyncio.TimeoutError:
        sock.close()
        raise ProxyError("timeout", "the proxy did not answer in time") from None
    except OSError as exc:
        sock.close()
        raise ProxyError("protocol", f"connection to the proxy failed: {exc.strerror or exc}") from None
    except BaseException:
        sock.close()
        raise


async def probe(proxy, proxy_ips, mark=0, timeout=5.0):
    """Health check: connect and, for SOCKS5, authenticate. Returns latency in ms."""
    started = time.monotonic()
    sock = await _connect_any(proxy, proxy_ips, mark, timeout)
    try:
        if proxy.type == "socks5":
            await asyncio.wait_for(
                _socks5_auth(asyncio.get_running_loop(), sock, proxy), timeout)
    except asyncio.TimeoutError:
        raise ProxyError("timeout", "the proxy did not answer in time") from None
    except OSError as exc:
        raise ProxyError("protocol", f"connection to the proxy failed: {exc.strerror or exc}") from None
    finally:
        sock.close()
    return int((time.monotonic() - started) * 1000)
