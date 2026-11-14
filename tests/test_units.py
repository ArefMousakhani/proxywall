"""Fast unit tests: no network namespaces, no privileges."""

import asyncio
import ipaddress
import json
import os
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import unittest

from proxywall import config, dnsmsg, firewall, upstream
from proxywall.fakeip import FakeIPPool
from proxywall.monitor import parse_ip_reply
from proxywall.rules import ExcludeRules, is_local_name, normalize_entry, normalize_list
from proxywall.tproxy import parse_http_host, parse_sni


def run(coro):
    return asyncio.run(coro)


class RulesTest(unittest.TestCase):
    def test_domain_forms(self):
        for text in ("*.ir", ".ir", "ir", "IR.", "https://ir/path", "ir:443"):
            self.assertEqual(normalize_entry(text)[:2], ("domain", "ir"), text)
        self.assertEqual(normalize_entry("*.Example.COM")[2], "*.example.com")
        self.assertEqual(normalize_entry("*.ایران")[1], "xn--mgba3a4f16a")

    def test_network_forms(self):
        self.assertEqual(normalize_entry("192.168.1.10")[2], "192.168.1.10")
        self.assertEqual(normalize_entry("10.1.2.3/8")[2], "10.0.0.0/8")
        self.assertEqual(normalize_entry("[2001:db8::1]")[2], "2001:db8::1")
        self.assertEqual(normalize_entry("1.2.3.4:8080")[0], "net")
        self.assertEqual(normalize_entry("http://1.2.3.4/x")[2], "1.2.3.4")

    def test_rejects_dangerous_or_invalid(self):
        for text in ("*", "*.", "0.0.0.0/0", "::/0", "bad domain", "a..b", "-x.com", ""):
            with self.assertRaises(ValueError, msg=text):
                normalize_entry(text)

    def test_list_dedup_and_comments(self):
        entries, errors = normalize_list(["*.ir", "ir", "# note", "", "1.1.1.1  # dns", "bad domain"])
        self.assertEqual(entries, ["*.ir", "1.1.1.1"])
        self.assertEqual(len(errors), 1)

    def test_matching(self):
        rules = ExcludeRules(["*.ir", "bank.example.com", "9.9.9.0/24", "2001:db8::/32"], allow_lan=True)
        for name in ("ir", "site.ir", "a.b.site.ir", "bank.example.com", "www.bank.example.com", "SITE.IR."):
            self.assertTrue(rules.match_domain(name), name)
        for name in ("example.com", "notbank.example.com", "sir", "ir.com", "mir"):
            self.assertFalse(rules.match_domain(name), name)
        for ip in ("9.9.9.9", "192.168.1.1", "10.0.0.1", "2001:db8::5", "fe80::1", "::ffff:10.0.0.1"):
            self.assertTrue(rules.match_ip(ip), ip)
        for ip in ("8.8.8.8", "198.18.0.5", "2606:4700::1", "not-an-ip"):
            self.assertFalse(rules.match_ip(ip), ip)
        self.assertFalse(ExcludeRules([], allow_lan=False).match_ip("192.168.1.1"))

    def test_local_names(self):
        for name in ("printer", "nas.local", "router.lan", "1.1.168.192.in-addr.arpa", "5.0.20.172.in-addr.arpa"):
            self.assertTrue(is_local_name(name), name)
        for name in ("example.com", "lan.example.com", "4.3.2.1.in-addr.arpa", "1.0.32.172.in-addr.arpa"):
            self.assertFalse(is_local_name(name), name)


class ConfigTest(unittest.TestCase):
    def test_defaults_are_valid(self):
        self.assertEqual(config.validate({}), config.defaults())

    def test_normalises(self):
        cfg = config.validate({"proxy": {"host": " Proxy.LAN. ", "port": "1080"}, "exclude": ["*.IR", "ir"]})
        self.assertEqual(cfg["proxy"]["host"], "proxy.lan")
        self.assertEqual(cfg["proxy"]["port"], 1080)
        self.assertEqual(cfg["exclude"], ["*.ir"])

    def test_reports_every_problem(self):
        with self.assertRaises(config.ConfigError) as caught:
            config.validate({"proxy": {"type": "ftp", "host": "bad host", "port": 0},
                             "kill_switch": "yes", "exclude": ["*"], "tcp_port": 80, "nonsense": 1})
        self.assertEqual(len(caught.exception.errors), 1)  # unknown key is reported first
        with self.assertRaises(config.ConfigError) as caught:
            config.validate({"proxy": {"type": "ftp", "host": "bad host", "port": 0},
                             "kill_switch": "yes", "exclude": ["*"], "tcp_port": 80})
        self.assertEqual(len(caught.exception.errors), 6)

    def test_password_is_kept_and_hidden(self):
        base = config.validate({"proxy": {"host": "h", "username": "u", "password": "secret"}})
        merged = config.merge(base, {"proxy": {"port": 9, "password": None}})
        self.assertEqual(merged["proxy"]["password"], "secret")
        view = config.public_view(merged)
        self.assertNotIn("secret", json.dumps(view))
        self.assertTrue(view["proxy"]["password_set"])

    def test_proxy_url(self):
        self.assertEqual(config.parse_proxy_url("socks5://u:p%40ss@192.168.1.5:1080"),
                         {"type": "socks5", "host": "192.168.1.5", "port": 1080, "username": "u", "password": "p@ss"})
        self.assertEqual(config.parse_proxy_url("http://proxy.lan")["port"], 8080)
        self.assertEqual(config.parse_proxy_url("10.0.0.1:1081")["type"], "socks5")
        self.assertEqual(config.parse_proxy_url("socks5://[fd00::1]:1080")["host"], "fd00::1")
        with self.assertRaises(config.ConfigError):
            config.parse_proxy_url("ftp://x")

    def test_save_load_roundtrip_is_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            cfg = config.validate({"proxy": {"host": "h", "username": "u", "password": "x"}})
            config.save(path, cfg)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertEqual(config.load(path), cfg)
            with open(path, "w") as handle:
                handle.write("{broken")
            with self.assertRaises(config.ConfigError):
                config.load(path)
            self.assertEqual(config.load(os.path.join(tmp, "missing.json")), config.defaults())


class DnsMessageTest(unittest.TestCase):
    def test_roundtrip(self):
        query = dnsmsg.parse_query(dnsmsg.build_query("WWW.Example.com", dnsmsg.A, qid=0x1234))
        self.assertEqual((query.id, query.name, query.qtype, query.edns), (0x1234, "www.example.com", 1, False))
        reply = dnsmsg.build_response(query, answers=[(dnsmsg.A, 1, socket.inet_aton("198.18.0.1"))])
        self.assertEqual(dnsmsg.parse_response(reply), (0, False, [(1, 1, socket.inet_aton("198.18.0.1"))]))
        self.assertEqual(reply[:2], b"\x12\x34")

    def test_edns_is_echoed(self):
        raw = bytearray(dnsmsg.build_query("example.com", dnsmsg.A))
        raw[10:12] = b"\x00\x01"
        raw += b"\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00"
        query = dnsmsg.parse_query(bytes(raw))
        self.assertTrue(query.edns)
        self.assertTrue(dnsmsg.build_response(query).endswith(b"\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00"))

    def test_malformed_input_is_rejected(self):
        good = dnsmsg.build_query("example.com", dnsmsg.A)
        bad = [b"", b"\x00" * 11, good[:-3], good[:12] + b"\xc0\x0c" + good[-4:],
               good[:2] + b"\x81\x80" + good[4:], good[:4] + b"\x00\x02" + good[6:], good[:12] + b"\x80abc"]
        for data in bad:
            with self.assertRaises(dnsmsg.DNSError, msg=data):
                dnsmsg.parse_query(data)
        for cut in range(len(good)):  # never an unexpected exception type
            try:
                dnsmsg.parse_query(good[:cut])
            except dnsmsg.DNSError:
                pass


class FakeIPTest(unittest.TestCase):
    def test_stable_mapping(self):
        pool = FakeIPPool()
        a, b = pool.get("a.example"), pool.get("b.example")
        self.assertNotEqual(a, b)
        self.assertEqual(pool.get("a.example"), a)
        self.assertEqual(pool.lookup(a), "a.example")
        self.assertTrue(FakeIPPool.contains(a))
        self.assertIn(ipaddress.ip_address(a), ipaddress.ip_network("198.18.0.0/15"))
        for outside in ("198.17.255.255", "198.20.0.0", "198.18.0.0", "198.19.255.255", "::1", "x"):
            self.assertFalse(FakeIPPool.contains(outside), outside)
        self.assertIsNone(pool.lookup("198.18.200.200"))

    def test_recycles_least_recently_used(self):
        pool = FakeIPPool(size=3)
        ips = [pool.get(f"h{i}") for i in range(3)]
        pool.lookup(ips[0])                      # h0 becomes the most recent
        newest = pool.get("h3")                  # evicts h1
        self.assertEqual(newest, ips[1])
        self.assertEqual(pool.lookup(ips[1]), "h3")
        self.assertEqual(pool.get("h0"), ips[0])
        self.assertEqual(len(pool), 3)

    def test_persistence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "fakeip.json")
            pool = FakeIPPool()
            first = [pool.get(f"host{i}.example") for i in range(50)]
            pool.save(path)
            restored = FakeIPPool()
            restored.load(path)
            self.assertEqual([restored.get(f"host{i}.example") for i in range(50)], first)
            self.assertNotIn(restored.get("new.example"), first)
            with open(path, "w") as handle:
                handle.write("garbage")
            broken = FakeIPPool()
            broken.load(path)
            self.assertEqual(len(broken), 0)


class SniffTest(unittest.TestCase):
    @staticmethod
    def client_hello(name):
        context = ssl.create_default_context()
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        tls = context.wrap_bio(incoming, outgoing, server_hostname=name)
        try:
            tls.do_handshake()
        except ssl.SSLWantReadError:
            pass
        return outgoing.read()

    def test_sni(self):
        hello = self.client_hello("secure.example.ir")
        self.assertEqual(parse_sni(hello), "secure.example.ir")
        for cut in range(len(hello)):            # truncated input never raises
            parse_sni(hello[:cut])
        self.assertIsNone(parse_sni(b"\x16\x03\x01\x00\x05\x02abcd"))
        self.assertIsNone(parse_sni(b"GET / HTTP/1.1\r\n\r\n"))
        self.assertIsNone(parse_sni(os.urandom(600)))

    def test_http_host(self):
        self.assertEqual(parse_http_host(b"GET / HTTP/1.1\r\nUser-Agent: x\r\nHost: Site.IR:8080\r\n\r\n"), "site.ir")
        self.assertIsNone(parse_http_host(b"GET / HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n"))
        self.assertIsNone(parse_http_host(b"GET / HTTP/1.1\r\n\r\n"))


class IpReplyTest(unittest.TestCase):
    def test_formats(self):
        self.assertEqual(parse_ip_reply("fl=1\nip=203.0.113.9\nloc=DE\n"), ("203.0.113.9", "DE"))
        self.assertEqual(parse_ip_reply("203.0.113.9\n"), ("203.0.113.9", None))
        self.assertEqual(parse_ip_reply('{"ip": "2001:db8::1", "country_code": "nl"}'), ("2001:db8::1", "NL"))
        self.assertEqual(parse_ip_reply("<html>blocked</html>"), (None, None))


class FirewallRenderTest(unittest.TestCase):
    def test_contains_the_safety_rules(self):
        text = firewall.render(47201, 47253, 0x5057, ["10.0.0.0/8"], ["fc00::/7"])
        self.assertTrue(text.startswith("table inet proxywall\ndelete table inet proxywall\n"))
        for needle in ("redirect to :47201", "redirect to :47253", "meta mark 0x5057 accept",
                       "elements = { 10.0.0.0/8 }", "reject with tcp reset", "hook forward"):
            self.assertIn(needle, text)
        self.assertNotIn("elements", firewall.render(1, 2, 3))

    @unittest.skipUnless(shutil.which("nft") and shutil.which("unshare"), "needs nft and unshare")
    def test_kernel_accepts_the_rules(self):
        rules = ExcludeRules(["9.9.9.0/24", "9.9.9.9", "10.1.0.0/16", "2001:db8::/32"], allow_lan=True)
        text = firewall.render(47201, 47253, 0x5057, *rules.bypass_sets())
        proc = subprocess.run(["unshare", "--user", "--map-root-user", "--net", "sh", "-c",
                               "nft -f - && nft -f - <<'EOF'\n" + text + "\nEOF\nnft list table inet proxywall >/dev/null"],
                              input=text, text=True, capture_output=True)
        if "Operation not permitted" in proc.stderr and "unshare" in proc.stderr:
            self.skipTest("user namespaces are not available")
        self.assertEqual((proc.returncode, proc.stderr), (0, ""))


class UpstreamTest(unittest.TestCase):
    """SOCKS5 and HTTP CONNECT handshakes against scripted servers."""

    def dial(self, proxy_type, script, user="", password="", host="example.com", port=443):
        async def scenario():
            seen = bytearray()

            async def serve(reader, writer):
                try:
                    await script(reader, writer, seen)
                    await writer.drain()
                except (asyncio.IncompleteReadError, OSError):
                    pass
                finally:
                    writer.close()

            server = await asyncio.start_server(serve, "127.0.0.1", 0)
            proxy = upstream.ProxySettings(proxy_type, "127.0.0.1", server.sockets[0].getsockname()[1], user, password)
            try:
                sock, leftover = await upstream.dial(proxy, ["127.0.0.1"], host, port, handshake_timeout=2)
                sock.close()
                return bytes(seen), leftover
            finally:
                server.close()
        return run(scenario())

    def test_socks5_domain_without_auth(self):
        async def script(reader, writer, seen):
            seen += await reader.readexactly(3)
            writer.write(b"\x05\x00")
            seen += await reader.readexactly(4 + 1 + 11 + 2)
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        seen, leftover = self.dial("socks5", script)
        self.assertEqual(seen, b"\x05\x01\x00" + b"\x05\x01\x00\x03\x0bexample.com\x01\xbb")
        self.assertEqual(leftover, b"")

    def test_socks5_with_password_and_ipv6_target(self):
        async def script(reader, writer, seen):
            seen += await reader.readexactly(4)
            writer.write(b"\x05\x02")
            seen += await reader.readexactly(3 + 2 + 2)
            writer.write(b"\x01\x00")
            seen += await reader.readexactly(4 + 16 + 2)
            writer.write(b"\x05\x00\x00\x04" + b"\0" * 18)
        seen, _ = self.dial("socks5", script, "me", "pw", host="2001:db8::1", port=80)
        self.assertEqual(seen[:11], b"\x05\x02\x00\x02" + b"\x01\x02me\x02pw")
        self.assertEqual(seen[11:15], b"\x05\x01\x00\x04")

    def test_socks5_errors(self):
        async def bad_password(reader, writer, seen):
            await reader.readexactly(4)
            writer.write(b"\x05\x02")
            await reader.readexactly(7)
            writer.write(b"\x01\x01")

        async def needs_auth(reader, writer, seen):
            await reader.readexactly(3)
            writer.write(b"\x05\xff")

        async def refused(reader, writer, seen):
            await reader.readexactly(3)
            writer.write(b"\x05\x00")
            await reader.readexactly(18)
            writer.write(b"\x05\x05\x00\x01" + b"\0" * 6)

        async def not_socks(reader, writer, seen):
            await reader.readexactly(3)
            writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")

        async def silent(reader, writer, seen):
            await asyncio.sleep(5)

        for script, kwargs, kind in ((bad_password, {"user": "me", "password": "pw"}, "auth"),
                                     (needs_auth, {}, "auth"), (refused, {}, "refused"),
                                     (not_socks, {}, "protocol"), (silent, {}, "timeout")):
            with self.assertRaises(upstream.ProxyError, msg=script.__name__) as caught:
                self.dial("socks5", script, **kwargs)
            self.assertEqual(caught.exception.kind, kind, script.__name__)

    def test_http_connect(self):
        async def script(reader, writer, seen):
            seen += await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 200 Connection established\r\nVia: test\r\n\r\nSSH-2.0-early")
        seen, leftover = self.dial("http", script, "me", "pw", port=22)
        self.assertTrue(seen.startswith(b"CONNECT example.com:22 HTTP/1.1\r\nHost: example.com:22\r\n"))
        self.assertIn(b"Proxy-Authorization: Basic bWU6cHc=\r\n", seen)
        self.assertEqual(leftover, b"SSH-2.0-early")       # early payload is not lost

    def test_http_connect_errors(self):
        def reply(status):
            async def script(reader, writer, seen):
                await reader.readuntil(b"\r\n\r\n")
                writer.write(status)
            return script
        for status, kind in ((b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n", "auth"),
                             (b"HTTP/1.1 403 Forbidden\r\n\r\n", "refused"),
                             (b"\x05\x00 not http at all\r\n\r\n", "protocol")):
            with self.assertRaises(upstream.ProxyError) as caught:
                self.dial("http", reply(status))
            self.assertEqual(caught.exception.kind, kind)

    def test_unreachable_proxy(self):
        async def scenario():
            with socket.socket() as placeholder:
                placeholder.bind(("127.0.0.1", 0))
                port = placeholder.getsockname()[1]
            proxy = upstream.ProxySettings("socks5", "127.0.0.1", port, "", "")
            await upstream.dial(proxy, ["127.0.0.1"], "example.com", 80)
        with self.assertRaises(upstream.ProxyError) as caught:
            run(scenario())
        self.assertEqual(caught.exception.kind, "unreachable")
        self.assertIn("refused", str(caught.exception).lower())


if __name__ == "__main__":
    unittest.main()
