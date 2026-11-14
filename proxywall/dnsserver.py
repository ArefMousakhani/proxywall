"""Local DNS server that every port-53 query on the machine is redirected to.

Answers are synthesised, so a lookup never waits for the network:

* ``A``                 -> a placeholder address (see fakeip.py)
* ``AAAA``/``HTTPS``    -> empty answer, so applications use the ``A`` record
* local names           -> forwarded to the network's own DNS (Allow LAN only)
* other record types    -> excluded names: the network's DNS,
                           everything else: ``remote_dns`` through the proxy
"""

import asyncio
import logging
import socket
import struct

from . import dnsmsg, upstream
from .fakeip import FakeIPPool
from .resolver import ResolveError, exchange_over_stream
from .rules import is_hostname, is_local_name

log = logging.getLogger("proxywall.dns")

FAKE_TTL = 1
MAX_PENDING = 512
IP_PKTINFO = getattr(socket, "IP_PKTINFO", 8)
IPV6_RECVPKTINFO = getattr(socket, "IPV6_RECVPKTINFO", 49)
IPV6_PKTINFO = getattr(socket, "IPV6_PKTINFO", 50)
_EMPTY_TYPES = (dnsmsg.AAAA, dnsmsg.HTTPS, dnsmsg.SVCB, dnsmsg.ANY)


class DnsServer:
    def __init__(self, core):
        self.core = core
        self._udp = []
        self._tcp = []
        self._tasks = set()
        self.port = None

    @property
    def listening(self):
        return bool(self._udp)

    # ------------------------------------------------------------ lifecycle
    async def start(self, port, mark):
        await self.stop()
        loop = asyncio.get_running_loop()
        failure = None
        for family, host in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
            udp = tcp = None
            try:
                udp = socket.socket(family, socket.SOCK_DGRAM)
                tcp = socket.socket(family, socket.SOCK_STREAM)
                tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                for sock in (udp, tcp):
                    if family == socket.AF_INET6:
                        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    if mark:
                        sock.setsockopt(socket.SOL_SOCKET, upstream.SO_MARK, mark)
                # Replies must leave from the address the query was sent to,
                # otherwise the kernel cannot undo the redirect (see _on_udp).
                if family == socket.AF_INET:
                    udp.setsockopt(socket.SOL_IP, IP_PKTINFO, 1)
                else:
                    udp.setsockopt(socket.IPPROTO_IPV6, IPV6_RECVPKTINFO, 1)
                udp.setblocking(False)
                udp.bind((host, port))
                tcp.bind((host, port))
                server = await asyncio.start_server(self._on_tcp, sock=tcp, backlog=128)
            except OSError as exc:
                for sock in (udp, tcp):
                    if sock is not None:
                        sock.close()
                if family == socket.AF_INET:
                    failure = exc
                continue
            loop.add_reader(udp.fileno(), self._on_udp, udp)
            self._udp.append(udp)
            self._tcp.append(server)
        if failure is not None:
            await self.stop()
            raise OSError(f"cannot listen on DNS port {port}: {failure}")
        self.port = port

    async def stop(self):
        loop = asyncio.get_running_loop()
        for sock in self._udp:
            loop.remove_reader(sock.fileno())
            sock.close()
        servers, self._udp, self._tcp = self._tcp, [], []
        for server in servers:
            server.close()
        for task in list(self._tasks):
            task.cancel()
        for server in servers:
            try:
                await asyncio.wait_for(server.wait_closed(), 2)
            except (asyncio.TimeoutError, OSError):
                pass
        self.port = None

    # ------------------------------------------------------------ transport
    def _on_udp(self, sock):
        for _ in range(64):
            try:
                data, ancillary, _, peer = sock.recvmsg(4096, 128)
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                return
            if len(self._tasks) >= MAX_PENDING:
                continue  # overloaded: drop, the client retries
            reply_from = []
            for level, kind, cdata in ancillary:
                if level == socket.SOL_IP and kind == IP_PKTINFO and len(cdata) >= 12:
                    # in_pktinfo{ifindex, spec_dst, addr}: answer from header dst
                    reply_from = [(level, kind, struct.pack("I4s4s", 0, cdata[8:12], b"\0" * 4))]
                elif level == socket.IPPROTO_IPV6 and kind == IPV6_PKTINFO and len(cdata) >= 20:
                    link_local = cdata[0] == 0xFE and cdata[1] & 0xC0 == 0x80
                    reply_from = [(level, kind, cdata[:16] + (cdata[16:20] if link_local else b"\0" * 4))]
            task = asyncio.ensure_future(self._serve_udp(sock, data, peer, reply_from))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def _serve_udp(self, sock, data, peer, reply_from):
        try:
            reply = await self.answer(data, tcp=False)
            if reply:
                sock.sendmsg([reply], reply_from, 0, peer)
        except asyncio.CancelledError:
            raise
        except OSError:
            pass
        except Exception:
            log.exception("unexpected error while answering a DNS query")

    async def _on_tcp(self, reader, writer):
        task = asyncio.current_task()
        self._tasks.add(task)
        try:
            while True:
                head = await asyncio.wait_for(reader.readexactly(2), 10)
                data = await asyncio.wait_for(reader.readexactly(struct.unpack("!H", head)[0]), 10)
                reply = await self.answer(data, tcp=True)
                if not reply:
                    break
                writer.write(struct.pack("!H", len(reply)) + reply)
                await writer.drain()
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
            pass
        except asyncio.CancelledError:
            pass
        except Exception:
            log.exception("unexpected error while answering a DNS query")
        finally:
            self._tasks.discard(task)
            writer.transport.abort()

    # ------------------------------------------------------------ logic
    async def answer(self, data, tcp):
        """Return the reply for one raw query, or None to stay silent."""
        try:
            query = dnsmsg.parse_query(data)
        except dnsmsg.DNSError:
            return None
        core = self.core
        if query.opcode != 0:
            return dnsmsg.build_response(query, dnsmsg.NOTIMP)
        if query.qclass != 1:
            return dnsmsg.build_response(query, dnsmsg.REFUSED)
        name, qtype = query.name, query.qtype

        if name == "localhost" or name.endswith(".localhost"):
            if qtype == dnsmsg.A:
                return dnsmsg.build_response(query, answers=[(dnsmsg.A, 60, b"\x7f\x00\x00\x01")])
            if qtype == dnsmsg.AAAA:
                return dnsmsg.build_response(query, answers=[(dnsmsg.AAAA, 60, b"\0" * 15 + b"\x01")])
            return dnsmsg.build_response(query)

        if qtype == dnsmsg.PTR and name.endswith(".in-addr.arpa"):
            ip = ".".join(reversed(name[:-13].split(".")))
            if FakeIPPool.contains(ip):
                host = core.pool.lookup(ip)
                if host is None:
                    return dnsmsg.build_response(query, dnsmsg.NXDOMAIN)
                return dnsmsg.build_response(query, answers=[(dnsmsg.PTR, FAKE_TTL, dnsmsg.encode_name(host))])

        if core.rules.allow_lan and is_local_name(name):
            return await self._forward_direct(query, data, tcp)

        if not is_hostname(name):
            return dnsmsg.build_response(query, dnsmsg.NXDOMAIN)
        if qtype == dnsmsg.A:
            address = socket.inet_aton(core.pool.get(name))
            return dnsmsg.build_response(query, answers=[(dnsmsg.A, FAKE_TTL, address)])
        if qtype in _EMPTY_TYPES:
            return dnsmsg.build_response(query)
        if core.rules.match_domain(name):
            return await self._forward_direct(query, data, tcp)
        return await self._forward_proxy(query, data)

    async def _forward_direct(self, query, data, tcp):
        try:
            return await self.core.direct.exchange(data, tcp=tcp)
        except ResolveError as exc:
            log.debug("direct DNS for %s failed: %s", query.name, exc)
            return dnsmsg.build_response(query, dnsmsg.SERVFAIL)

    async def _forward_proxy(self, query, data):
        core = self.core
        if not core.tunnel_open:
            return dnsmsg.build_response(query, dnsmsg.SERVFAIL)
        sock = None
        try:
            sock, _ = await core.dial_proxy(core.cfg["remote_dns"], 53)
            return await exchange_over_stream(sock, data)
        except (upstream.ProxyError, ResolveError, OSError, asyncio.TimeoutError) as exc:
            log.debug("remote DNS for %s failed: %s", query.name, exc or type(exc).__name__)
            return dnsmsg.build_response(query, dnsmsg.SERVFAIL)
        finally:
            if sock is not None:
                sock.close()
