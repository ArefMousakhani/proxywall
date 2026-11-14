"""DNS clients used by the daemon itself.

``DirectResolver`` talks to the network's own DNS servers over marked sockets.
It serves excluded and local names and resolves the proxy's hostname. The
daemon must never call ``getaddrinfo``: the system resolver is redirected to
ProxyWall's own DNS server and would hand back placeholder addresses.
"""

import asyncio
import ipaddress
import os
import socket
import struct
import time

from . import dnsmsg
from .fakeip import NETWORK as FAKE_NETWORK
from .upstream import new_socket, tcp_connect

RESOLV_CONF_FILES = ("/run/systemd/resolve/resolv.conf", "/etc/resolv.conf")
FALLBACK_SERVERS = ("1.1.1.1", "8.8.8.8")
_MIN_TTL, _MAX_TTL, _NEGATIVE_TTL = 10, 300, 10
_CACHE_LIMIT = 4096


class ResolveError(Exception):
    pass


def system_dns_servers(files=RESOLV_CONF_FILES):
    """Real upstream resolvers of this machine (loopback stubs are skipped)."""
    servers = []
    for path in files:
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    parts = line.split()
                    if len(parts) < 2 or parts[0] != "nameserver":
                        continue
                    try:
                        addr = ipaddress.ip_address(parts[1])
                    except ValueError:  # e.g. link-local with a %scope
                        continue
                    if addr.is_loopback or addr.is_unspecified:
                        continue
                    if addr.version == 4 and addr in FAKE_NETWORK:
                        continue
                    if str(addr) not in servers:
                        servers.append(str(addr))
        except OSError:
            continue
        if servers:
            break
    return servers


async def _tcp_exchange(sock, payload, timeout):
    loop = asyncio.get_running_loop()

    async def run():
        await loop.sock_sendall(sock, struct.pack("!H", len(payload)) + payload)
        buf = bytearray()
        want = 2
        while len(buf) < want:
            chunk = await loop.sock_recv(sock, 65536)
            if not chunk:
                raise ResolveError("DNS server closed the connection")
            buf += chunk
            if len(buf) >= 2:
                want = 2 + struct.unpack("!H", buf[:2])[0]
        return bytes(buf[2:want])

    return await asyncio.wait_for(run(), timeout)


class DirectResolver:
    def __init__(self, configured=lambda: (), mark=0):
        self._configured = configured
        self.mark = mark
        self._cache = {}
        self._system = ([], 0.0)

    def servers(self):
        configured = list(self._configured())
        if configured:
            return configured
        found, stamp = self._system
        if time.monotonic() - stamp > 5:
            found = system_dns_servers()
            self._system = (found, time.monotonic())
        return found or list(FALLBACK_SERVERS)

    async def _udp(self, server, payload, timeout):
        loop = asyncio.get_running_loop()
        family = socket.AF_INET6 if ":" in server else socket.AF_INET
        sock = new_socket(family, socket.SOCK_DGRAM, self.mark)
        try:
            sock.connect((server, 53))

            async def run():
                await loop.sock_sendall(sock, payload)
                while True:
                    data = await loop.sock_recv(sock, 4096)
                    if len(data) >= 12 and data[:2] == payload[:2] and data[2] & 0x80:
                        return data

            return await asyncio.wait_for(run(), timeout)
        finally:
            sock.close()

    async def _tcp(self, server, payload, timeout):
        sock = await tcp_connect(server, 53, self.mark, timeout)
        try:
            data = await _tcp_exchange(sock, payload, timeout)
        finally:
            sock.close()
        if len(data) < 12 or data[:2] != payload[:2]:
            raise ResolveError("bad DNS reply")
        return data

    async def exchange(self, raw, tcp=False, timeout=2.5):
        """Forward a raw query to the network's DNS. Returns the raw reply."""
        payload = os.urandom(2) + raw[2:]  # fresh id and source port per attempt
        error = None
        for _ in range(2):
            for server in self.servers():
                try:
                    reply = await (self._tcp if tcp else self._udp)(server, payload, timeout)
                    return raw[:2] + reply[2:]
                except asyncio.TimeoutError:
                    error = f"DNS server {server} timed out"
                except (OSError, ResolveError) as exc:
                    error = f"DNS server {server}: {exc}"
        raise ResolveError(error or "no DNS server available")

    async def resolve(self, name, qtype=dnsmsg.A):
        """Return the addresses of *name* (text). Cached; raises ResolveError."""
        key = (name, qtype)
        hit = self._cache.get(key)
        now = time.monotonic()
        if hit and hit[0] > now:
            if hit[1]:
                return hit[1]
            raise ResolveError(f"{name} does not resolve")
        query = dnsmsg.build_query(name, qtype)
        try:
            reply = await self.exchange(query)
            rcode, truncated, answers = dnsmsg.parse_response(reply)
            if truncated:
                reply = await self.exchange(query, tcp=True)
                rcode, truncated, answers = dnsmsg.parse_response(reply)
        except dnsmsg.DNSError as exc:
            raise ResolveError(f"bad DNS reply for {name}: {exc}") from None
        size = 4 if qtype == dnsmsg.A else 16
        family = socket.AF_INET if qtype == dnsmsg.A else socket.AF_INET6
        found = [(ttl, socket.inet_ntop(family, rdata)) for rtype, ttl, rdata in answers
                 if rtype == qtype and len(rdata) == size]
        if len(self._cache) >= _CACHE_LIMIT:
            self._cache.clear()
        if rcode not in (dnsmsg.NOERROR, dnsmsg.NXDOMAIN):
            raise ResolveError(f"DNS error {rcode} for {name}")
        if not found:
            self._cache[key] = (now + _NEGATIVE_TTL, [])
            raise ResolveError(f"{name} does not resolve")
        ttl = max(_MIN_TTL, min(_MAX_TTL, min(t for t, _ in found)))
        addresses = [ip for _, ip in found]
        self._cache[key] = (now + ttl, addresses)
        return addresses

    async def resolve_host(self, name):
        """IPv4 addresses first, IPv6 as a fallback."""
        try:
            return await self.resolve(name, dnsmsg.A)
        except ResolveError as first:
            try:
                return await self.resolve(name, dnsmsg.AAAA)
            except ResolveError:
                raise first from None


async def exchange_over_stream(sock, raw, timeout=5.0):
    """DNS-over-TCP on an already connected socket (used through the proxy)."""
    payload = os.urandom(2) + raw[2:]
    data = await _tcp_exchange(sock, payload, timeout)
    if len(data) < 12 or data[:2] != payload[:2]:
        raise ResolveError("bad DNS reply")
    return raw[:2] + data[2:]
