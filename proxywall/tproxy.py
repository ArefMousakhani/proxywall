"""Transparent TCP front end.

nftables redirects every new TCP connection to this listener. For each one we
recover the destination the application really asked for, decide between
*direct* and *proxy*, open the outbound leg and relay bytes in both directions.
"""

import asyncio
import logging
import socket
import struct
import time

from . import upstream
from .fakeip import FakeIPPool
from .resolver import ResolveError
from .rules import base_domain, is_hostname

log = logging.getLogger("proxywall.tcp")

SO_ORIGINAL_DST = 80  # same value for IPv4 (SOL_IP) and IPv6 (SOL_IPV6)
BUFFER = 64 * 1024
MAX_CONNECTIONS = 4096
SNIFF_TIMEOUT = 1.0
HALF_CLOSE_TIMEOUT = 120.0
CONNECTION_ROWS = 100   # how many destinations the list of open connections reports
_HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ")


def original_destination(sock):
    """Destination before the firewall redirect, or None if not redirected."""
    try:
        if sock.family == socket.AF_INET:
            raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
            return socket.inet_ntoa(raw[4:8]), struct.unpack_from("!H", raw, 2)[0]
        raw = sock.getsockopt(socket.IPPROTO_IPV6, SO_ORIGINAL_DST, 28)
        return socket.inet_ntop(socket.AF_INET6, raw[8:24]), struct.unpack_from("!H", raw, 2)[0]
    except OSError:
        return None


def parse_sni(data):
    """Server name from a TLS ClientHello, or None."""
    try:
        if data[0] != 0x16 or data[5] != 0x01:
            return None
        pos = 5 + 4 + 2 + 32
        pos += 1 + data[pos]                                   # session id
        pos += 2 + int.from_bytes(data[pos:pos + 2], "big")    # cipher suites
        pos += 1 + data[pos]                                   # compression
        end = pos + 2 + int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        while pos + 4 <= min(end, len(data)):
            kind = int.from_bytes(data[pos:pos + 2], "big")
            size = int.from_bytes(data[pos + 2:pos + 4], "big")
            pos += 4
            if kind == 0:
                if data[pos + 2] != 0:
                    return None
                length = int.from_bytes(data[pos + 3:pos + 5], "big")
                name = data[pos + 5:pos + 5 + length].decode("ascii").lower().rstrip(".")
                return name if len(name) == length and is_hostname(name) else None
            pos += size
    except (IndexError, UnicodeDecodeError):
        pass
    return None


def parse_http_host(data):
    """Host header of a plain HTTP request, or None."""
    head = data.split(b"\r\n\r\n", 1)[0]
    for line in head.split(b"\r\n")[1:]:
        if line[:5].lower() == b"host:":
            try:
                host = line[5:].strip().decode("ascii").lower()
            except UnicodeDecodeError:
                return None
            if host.startswith("["):
                return None
            host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
            host = host.rstrip(".")
            return host if is_hostname(host) and upstream.ip_version(host) == 0 else None
    return None


async def sniff(reader):
    """Read the first bytes of a connection and try to find the host name.

    Used only for connections to literal addresses on ports 80/443 (for
    example when an application resolves names itself over DNS-over-HTTPS), so
    domain exclusions keep working. Returns ``(buffered_bytes, name_or_None)``.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + SNIFF_TIMEOUT
    buf = b""
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            break
        try:
            chunk = await asyncio.wait_for(reader.read(BUFFER), remaining)
        except asyncio.TimeoutError:
            break
        if not chunk:
            break
        buf += chunk
        if buf[0] == 0x16:
            if len(buf) >= 5 and len(buf) >= 5 + min(int.from_bytes(buf[3:5], "big"), 16384):
                return buf, parse_sni(buf)
        elif buf.startswith(_HTTP_METHODS):
            if b"\r\n\r\n" in buf or len(buf) > 8192:
                return buf, parse_http_host(buf)
        else:
            break
    if buf[:1] == b"\x16":
        return buf, parse_sni(buf)
    return buf, None


def _abort(writer):
    """Close with a TCP reset so the application fails immediately."""
    try:
        sock = writer.get_extra_info("socket")
        if sock is not None:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass
    writer.transport.abort()


class TransparentProxy:
    def __init__(self, core, original_dst=original_destination):
        self.core = core
        self._original_dst = original_dst
        self._servers = []
        self._tasks = set()
        self._proxied = set()  # the subset of _tasks that goes (or is about to go) through the proxy
        self._open = {}        # task -> what the connection is, for the list of open connections
        self.port = None

    @property
    def listening(self):
        return bool(self._servers)

    async def start(self, port, mark):
        """Bind the redirect target on IPv4 and, when available, IPv6."""
        await self.stop()
        errors = []
        for family, host in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
            sock = None
            try:
                sock = socket.socket(family, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                if mark:
                    sock.setsockopt(socket.SOL_SOCKET, upstream.SO_MARK, mark)
                sock.bind((host, port))
                server = await asyncio.start_server(self._accept, sock=sock, backlog=1024, limit=BUFFER)
                self._servers.append(server)
            except OSError as exc:
                if sock is not None:
                    sock.close()
                errors.append((family, exc))
        if not any(s.sockets and s.sockets[0].family == socket.AF_INET for s in self._servers):
            await self.stop()
            reason = next((exc for family, exc in errors if family == socket.AF_INET), "unknown error")
            raise OSError(f"cannot listen on TCP port {port}: {reason}")
        self.port = port

    async def stop(self):
        servers, self._servers = self._servers, []
        for server in servers:
            server.close()
        self.close_connections()
        for server in servers:
            try:
                await asyncio.wait_for(server.wait_closed(), 2)
            except (asyncio.TimeoutError, OSError):
                pass
        self.port = None

    def close_connections(self, proxied_only=False):
        for task in list(self._proxied if proxied_only else self._tasks):
            task.cancel()

    def close_excluded(self):
        """Cut proxied connections that the exclusion list now sends out directly.

        The application opens them again at once, and this time they bypass
        the proxy: an exclusion takes effect when it is made, not at the next visit.
        """
        rules = self.core.rules
        for task, entry in list(self._open.items()):
            if entry["direct"]:
                continue
            if rules.match_domain(entry["host"]) if entry["named"] else rules.match_ip(entry["host"]):
                task.cancel()

    def connections(self, limit=CONNECTION_ROWS):
        """Open connections, one row per site and route, for people to read.

        Host names are grouped under their domain (``mail.google.com`` and
        ``www.google.com`` are one row); ``exclude`` is the entry that would
        send the row out directly. Connections still waiting for the proxy
        count as ``pending``.
        """
        groups = {}
        for entry in self._open.values():
            host = base_domain(entry["host"]) if entry["named"] else entry["host"]
            key = (host, entry["direct"])
            group = groups.get(key)
            if group is None:
                group = groups[key] = {"host": host, "route": "direct" if entry["direct"] else "proxy",
                                       "exclude": host, "count": 0, "pending": 0, "up": 0, "down": 0,
                                       "since": entry["since"], "names": set()}
            group["count"] += 1
            group["pending"] += entry["pending"]
            group["up"] += entry["up"]
            group["down"] += entry["down"]
            group["since"] = min(group["since"], entry["since"])
            group["names"].add(entry["host"])
        rows = sorted(groups.values(), key=lambda group: (group["host"], group["route"]))[:limit]
        for group in rows:
            group["names"] = sorted(group["names"])[:8]
        return rows

    async def _accept(self, reader, writer):
        task = asyncio.current_task()
        self._tasks.add(task)
        stats = self.core.stats
        stats["active"] += 1
        stats["total"] += 1
        try:
            await self._handle(reader, writer)
        except asyncio.CancelledError:
            _abort(writer)
        except Exception:  # never let one connection hurt the daemon
            log.exception("unexpected error in a relayed connection")
            _abort(writer)
        finally:
            stats["active"] -= 1
            self._tasks.discard(task)
            self._proxied.discard(task)
            self._open.pop(task, None)

    async def _handle(self, reader, writer):
        core = self.core
        sock = writer.get_extra_info("socket")
        upstream.tune_stream(sock)
        dst = self._original_dst(sock)
        if dst is None or (len(self._tasks) > MAX_CONNECTIONS):
            _abort(writer)  # not a redirected connection, or overload
            return
        ip, port = dst
        if ip.startswith("::ffff:"):
            ip = ip[7:]
        if port == self.port and ip in ("127.0.0.1", "::1"):
            _abort(writer)  # would loop back into ourselves
            return

        name = None
        if FakeIPPool.contains(ip):
            name = core.pool.lookup(ip)
            if name is None:  # placeholder from a previous run that we no longer know
                log.debug("unknown placeholder address %s", ip)
                _abort(writer)
                return
        first = b""
        direct = False
        sniffed = None
        if name is not None:
            direct = core.rules.match_domain(name)
        elif core.rules.match_ip(ip):
            direct = True
        elif port in (80, 443) and core.rules.domains:
            first, sniffed = await sniff(reader)
            direct = sniffed is not None and core.rules.match_domain(sniffed)
            log.debug("sniffed %s for %s:%d", sniffed, ip, port)

        target = name or ip
        entry = {"host": name or sniffed or ip, "named": bool(name or sniffed), "direct": direct,
                 "pending": True, "since": time.time(), "up": 0, "down": 0}
        self._open[asyncio.current_task()] = entry
        try:
            if direct:
                up_sock, leftover = await self._dial_direct(target, port), b""
            elif not core.tunnel_open:
                core.stats["blocked"] += 1
                log.debug("blocked %s:%d (not connected)", target, port)
                _abort(writer)
                return
            else:
                # From here on the connection counts as proxied, so that a
                # country block arriving during the dial still cuts it.
                self._proxied.add(asyncio.current_task())
                if not await core.monitor.permit():
                    core.stats["blocked"] += 1
                    log.debug("blocked %s:%d (exit country)", target, port)
                    _abort(writer)
                    return
                up_sock, leftover = await core.dial_proxy(target, port)
        except (upstream.ProxyError, ResolveError, OSError, asyncio.TimeoutError) as exc:
            core.stats["failed"] += 1
            log.debug("%s %s:%d failed: %s", "direct" if direct else "proxy", target, port,
                      exc or type(exc).__name__)
            _abort(writer)
            return

        core.stats["direct" if direct else "proxied"] += 1
        entry["pending"] = False
        log.debug("%s %s:%d", "direct" if direct else "proxy ", target, port)
        try:
            up_reader, up_writer = await asyncio.open_connection(sock=up_sock, limit=BUFFER)
        except BaseException:
            up_sock.close()
            raise
        try:
            if leftover:
                writer.write(leftover)
            if first:
                up_writer.write(first)
            await self._relay(reader, writer, up_reader, up_writer, entry)
        finally:
            for stream in (writer, up_writer):
                if not stream.transport.is_closing():
                    stream.transport.abort()

    async def _dial_direct(self, target, port):
        core = self.core
        if upstream.ip_version(target):
            addresses = [target]
        else:
            addresses = await core.direct.resolve_host(target)
        error = None
        for address in addresses[:3]:
            try:
                return await upstream.tcp_connect(address, port, core.mark)
            except (OSError, asyncio.TimeoutError) as exc:
                error = exc
        raise error or OSError("no address")

    async def _relay(self, c_reader, c_writer, u_reader, u_writer, entry):
        stats = self.core.stats

        async def pipe(reader, writer, key):
            while True:
                data = await reader.read(BUFFER)
                if not data:
                    break
                writer.write(data)
                stats[key] += len(data)
                entry[key] += len(data)
                await writer.drain()
            if writer.can_write_eof():
                writer.write_eof()  # pass the half-close on

        up = asyncio.ensure_future(pipe(c_reader, u_writer, "up"))
        down = asyncio.ensure_future(pipe(u_reader, c_writer, "down"))
        try:
            done, pending = await asyncio.wait({up, down}, return_when=asyncio.FIRST_COMPLETED)
            if pending and all(t.exception() is None for t in done):
                # One side finished sending; give the other side time to finish too.
                await asyncio.wait(pending, timeout=HALF_CLOSE_TIMEOUT)
        finally:
            for task in (up, down):
                if not task.done():
                    task.cancel()
            results = await asyncio.gather(up, down, return_exceptions=True)
            clean = all(r is None for r in results)
        if clean:
            for writer in (c_writer, u_writer):
                writer.close()
        # otherwise the caller aborts both sides (reset), mirroring the failure
