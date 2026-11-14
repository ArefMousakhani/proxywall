#!/usr/bin/env python3
"""A miniature Internet for the integration tests.

Runs inside the "wan" network namespace and provides, depending on --role:

* services   HTTP (80), HTTPS (443, optional), DNS (53 udp+tcp), UDP echo (9999)
* socks      a SOCKS5 proxy (1080) with optional username/password
* http       an HTTP CONNECT proxy (8080) with optional Basic auth

Every interesting event is appended to --log so that the tests can prove which
path a connection took.
"""

import argparse
import asyncio
import base64
import json
import os
import socket
import ssl
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from proxywall import dnsmsg  # noqa: E402

HOSTS = {
    "example.com": "93.184.216.34",
    "www.example.com": "93.184.216.34",
    "big.example.com": "93.184.216.34",
    "site.ir": "5.5.5.5",
    "sub.site.ir": "5.5.5.5",
    "printer.lan": "10.0.0.1",
    "proxy.example.net": "10.0.0.1",
}
LOG = None


def record(*fields):
    with open(LOG, "a", encoding="utf-8") as handle:
        handle.write(" ".join(str(f) for f in fields) + "\n")


async def pump(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
    except OSError:
        pass


async def splice(a_reader, a_writer, b_reader, b_writer):
    await asyncio.gather(pump(a_reader, b_writer), pump(b_reader, a_writer))
    for writer in (a_writer, b_writer):
        writer.close()


# ---------------------------------------------------------------- services
async def http_client(reader, writer):
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
        lines = head.decode("latin-1").split("\r\n")
        path = lines[0].split()[1]
        host = next((l.split(":", 1)[1].strip() for l in lines[1:] if l.lower().startswith("host:")), "")
        peer = writer.get_extra_info("peername")[0]
        local = writer.get_extra_info("sockname")[0]
        tls = writer.get_extra_info("ssl_object") is not None
        if path in ("/trace", "/geo", "/ip"):
            # "What is my IP" services. The country they report is whatever the
            # test wrote into <log>.country, so a test can move the exit around.
            try:
                with open(LOG + ".country", encoding="utf-8") as handle:
                    country = handle.read().strip()
            except OSError:
                country = "DE"
            record("check", path, peer, country)
            if path == "/trace":
                body = f"ip={peer}\nloc={country}\n".encode()
            elif path == "/ip":
                body = peer.encode()  # an address and nothing else
            else:
                body = json.dumps({"ip": peer, "country_code": country, "latitude": 1.5, "longitude": 2.5}).encode()
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode()
                         + b"\r\nConnection: close\r\n\r\n" + body)
            await writer.drain()
            return
        record("https" if tls else "http", peer, host, local)
        if path.startswith("/blob/"):
            size = int(path.rsplit("/", 1)[1])
            writer.write(f"HTTP/1.1 200 OK\r\nContent-Length: {size}\r\nConnection: close\r\n\r\n".encode())
            block = bytes(range(256)) * 256
            sent = 0
            while sent < size:
                piece = block[:min(len(block), size - sent)]
                writer.write(piece)
                await writer.drain()
                sent += len(piece)
        else:
            body = json.dumps({"host": host, "peer": peer, "server": local}).encode()
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                         + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
        await writer.drain()
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError, ValueError, IndexError):
        pass
    finally:
        writer.close()


def dns_answer(data, peer, transport):
    try:
        query = dnsmsg.parse_query(data)
    except dnsmsg.DNSError:
        return None
    record("dns", peer, query.name, query.qtype, transport)
    ip = HOSTS.get(query.name)
    if query.qtype == dnsmsg.A and ip:
        return dnsmsg.build_response(query, answers=[(dnsmsg.A, 30, socket.inet_aton(ip))])
    if query.qtype == 16 and (ip or query.name.endswith("example.org")):
        text = f"txt-for-{query.name}".encode()
        return dnsmsg.build_response(query, answers=[(16, 30, bytes([len(text)]) + text)])
    return dnsmsg.build_response(query, dnsmsg.NOERROR if ip else dnsmsg.NXDOMAIN)


class DnsUdp(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        reply = dns_answer(data, addr[0], "udp")
        if reply:
            self.transport.sendto(reply, addr)


async def dns_tcp(reader, writer):
    try:
        size = struct.unpack("!H", await reader.readexactly(2))[0]
        reply = dns_answer(await reader.readexactly(size), writer.get_extra_info("peername")[0], "tcp")
        if reply:
            writer.write(struct.pack("!H", len(reply)) + reply)
            await writer.drain()
    except (asyncio.IncompleteReadError, OSError):
        pass
    finally:
        writer.close()


class UdpEcho(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        record("udp", addr[0])
        self.transport.sendto(b"echo:" + data, addr)


async def run_services(args):
    loop = asyncio.get_running_loop()
    await asyncio.start_server(http_client, "0.0.0.0", 80)
    await asyncio.start_server(http_client, "::", 80)
    if args.cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.cert, args.key)
        await asyncio.start_server(http_client, "0.0.0.0", 443, ssl=context)
    await asyncio.start_server(dns_tcp, "0.0.0.0", 53)
    # One UDP socket per address so replies leave from the queried address.
    for address in ("10.0.0.1", "1.1.1.1"):
        await loop.create_datagram_endpoint(DnsUdp, local_addr=(address, 53))
    for address in ("9.9.9.9", "93.184.216.34"):
        await loop.create_datagram_endpoint(UdpEcho, local_addr=(address, 9999))


# ---------------------------------------------------------------- proxies
async def open_target(host, port):
    address = HOSTS.get(host, host)
    socket.getaddrinfo(address, port, flags=socket.AI_NUMERICHOST)  # names we don't know fail
    return await asyncio.wait_for(asyncio.open_connection(address, port), 5)


async def socks_client(reader, writer, auth):
    try:
        version, count = await reader.readexactly(2)
        methods = await reader.readexactly(count)
        if auth:
            if 2 not in methods:
                writer.write(b"\x05\xff")
                return
            writer.write(b"\x05\x02")
            _, ulen = await reader.readexactly(2)
            user = await reader.readexactly(ulen)
            plen = (await reader.readexactly(1))[0]
            password = await reader.readexactly(plen)
            if f"{user.decode()}:{password.decode()}" != auth:
                writer.write(b"\x01\x01")
                record("socks-auth-failed")
                return
            writer.write(b"\x01\x00")
        else:
            writer.write(b"\x05\x00")
        _, command, _, atyp = await reader.readexactly(4)
        if atyp == 1:
            host = socket.inet_ntoa(await reader.readexactly(4))
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
        else:
            host = (await reader.readexactly((await reader.readexactly(1))[0])).decode()
        port = struct.unpack("!H", await reader.readexactly(2))[0]
        record("socks", f"{host}:{port}")
        try:
            up_reader, up_writer = await open_target(host, port)
        except (OSError, asyncio.TimeoutError):
            writer.write(b"\x05\x04\x00\x01" + b"\0" * 6)
            return
        writer.write(b"\x05\x00\x00\x01" + b"\0" * 6)
        await splice(reader, writer, up_reader, up_writer)
    except (asyncio.IncompleteReadError, OSError):
        pass
    finally:
        try:
            await writer.drain()
        except OSError:
            pass
        writer.close()


async def http_proxy_client(reader, writer, auth):
    try:
        head = (await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)).decode("latin-1")
        lines = head.split("\r\n")
        method, target, _ = lines[0].split()
        if auth:
            expected = "basic " + base64.b64encode(auth.encode()).decode().lower()
            given = next((l.split(":", 1)[1].strip() for l in lines[1:]
                          if l.lower().startswith("proxy-authorization:")), "")
            if given.lower() != expected:
                writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                return
        if method != "CONNECT":
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            return
        host, _, port = target.rpartition(":")
        record("httpproxy", target)
        try:
            up_reader, up_writer = await open_target(host.strip("[]"), int(port))
        except (OSError, asyncio.TimeoutError):
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return
        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await splice(reader, writer, up_reader, up_writer)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError, ValueError):
        pass
    finally:
        try:
            await writer.drain()
        except OSError:
            pass
        writer.close()


async def main():
    global LOG
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", required=True, choices=("services", "socks", "http"))
    parser.add_argument("--log", required=True)
    parser.add_argument("--auth", default="")
    parser.add_argument("--cert")
    parser.add_argument("--key")
    args = parser.parse_args()
    LOG = args.log
    if args.role == "services":
        await run_services(args)
    elif args.role == "socks":
        await asyncio.start_server(lambda r, w: socks_client(r, w, args.auth), "10.0.0.1", 1080)
    else:
        await asyncio.start_server(lambda r, w: http_proxy_client(r, w, args.auth), "10.0.0.1", 8080)
    record("ready", args.role)
    await asyncio.Event().wait()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
