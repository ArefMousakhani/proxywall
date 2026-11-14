"""Fast unit tests: no network namespaces, no privileges."""

import asyncio
import base64
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

from proxywall import config, dnsmsg, firewall, geo, links, monitor, upstream
from proxywall.fakeip import FakeIPPool
from proxywall.geodata import COUNTRIES, LAND
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
                         {"type": "socks5", "host": "192.168.1.5", "port": 1080, "username": "u", "password": "p@ss",
                          "link": ""})
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


class LinkTest(unittest.TestCase):
    ID = "b831381d-6324-4d53-ad4f-8cda48b30811"

    def outbound(self, link, address="203.0.113.9", mark=0x5057):
        return links.xray_outbound(links.parse(link), address, mark)

    def test_vless_reality(self):
        out = self.outbound(f"vless://{self.ID}@Example.COM:443?security=reality&sni=www.microsoft.com&fp=chrome"
                            "&pbk=PUBKEY&sid=6ba8&flow=xtls-rprx-vision&type=tcp#My%20server")
        self.assertEqual(out["protocol"], "vless")
        self.assertEqual(out["settings"]["vnext"][0], {
            "address": "203.0.113.9", "port": 443,
            "users": [{"id": self.ID, "encryption": "none", "flow": "xtls-rprx-vision"}]})
        stream = out["streamSettings"]
        self.assertEqual((stream["network"], stream["security"], stream["sockopt"]), ("raw", "reality", {"mark": 0x5057}))
        self.assertEqual(stream["realitySettings"]["publicKey"], "PUBKEY")
        self.assertEqual(links.parse(f"vless://{self.ID}@h.example:1#My%20server")["name"], "My server")

    def test_the_real_name_survives_dialling_by_address(self):
        """Xray is given an IP, so SNI and Host must carry the name explicitly."""
        stream = self.outbound(f"vless://{self.ID}@cdn.example.com:443?security=tls&type=ws&path=%2Fp")["streamSettings"]
        self.assertEqual(stream["tlsSettings"]["serverName"], "cdn.example.com")
        self.assertEqual(stream["wsSettings"], {"path": "/p", "host": "cdn.example.com"})
        explicit = self.outbound(f"vless://{self.ID}@cdn.example.com:443?security=tls&sni=a.example&host=b.example"
                                 "&type=httpupgrade")["streamSettings"]
        self.assertEqual(explicit["tlsSettings"]["serverName"], "a.example")
        self.assertEqual(explicit["httpupgradeSettings"]["host"], "b.example")
        by_ip = self.outbound(f"trojan://pw@198.51.100.7:443")["streamSettings"]
        self.assertNotIn("serverName", by_ip["tlsSettings"])

    def test_vmess(self):
        body = {"v": "2", "ps": "name", "add": "example.com", "port": "443", "id": self.ID, "aid": "0", "scy": "auto",
                "net": "ws", "type": "none", "host": "h.example.com", "path": "/p", "tls": "tls"}
        out = self.outbound("vmess://" + base64.b64encode(json.dumps(body).encode()).decode())
        self.assertEqual(out["settings"]["vnext"][0]["users"], [{"id": self.ID, "alterId": 0, "security": "auto"}])
        self.assertEqual(out["streamSettings"]["wsSettings"], {"path": "/p", "host": "h.example.com"})
        body.update(net="grpc", path="svc", type="multi")
        grpc = self.outbound("vmess://" + base64.b64encode(json.dumps(body).encode()).decode())["streamSettings"]
        self.assertEqual(grpc["grpcSettings"], {"serviceName": "svc", "multiMode": True})

    def test_shadowsocks_forms(self):
        want = {"address": "203.0.113.9", "port": 8388, "method": "aes-256-gcm", "password": "se:cret"}
        sip002 = "ss://" + base64.urlsafe_b64encode(b"aes-256-gcm:se:cret").decode().rstrip("=") + "@example.com:8388#n"
        legacy = "ss://" + base64.b64encode(b"aes-256-gcm:se:cret@example.com:8388").decode() + "#n"
        plain = "ss://aes-256-gcm:se%3Acret@example.com:8388/?#n"
        for link in (sip002, legacy, plain):
            self.assertEqual(self.outbound(link)["settings"]["servers"], [want], link)
        with self.assertRaises(links.LinkError):
            links.parse(sip002.replace("#n", "?plugin=obfs-local#n"))

    def test_trojan_defaults_to_tls(self):
        out = self.outbound("trojan://p%40ss@example.com?type=grpc&serviceName=s")
        self.assertEqual(out["settings"]["servers"][0], {"address": "203.0.113.9", "port": 443, "password": "p@ss"})
        self.assertEqual(out["streamSettings"]["security"], "tls")

    def test_bad_links_have_readable_errors(self):
        cases = {"hysteria2://x@h:1": "Hysteria2", "tuic://a:b@h:1": "TUIC", "wireguard://k@h:1": "WireGuard",
                 "vmess://!!!": "damaged", "": "paste", "ftp://h": "unknown kind",
                 f"vless://{self.ID}@h.example:443?security=reality": "public key",
                 f"vless://{self.ID}@h.example:443?type=h2": "no longer supported",
                 f"vless://{self.ID}@h.example:99999": "valid", f"vless://{self.ID}@:443": "no server address",
                 "vless://" + "x" * 40 + "@h.example:443": "UUID", "trojan://@h.example:443": "no password",
                 "ss://" + base64.b64encode(b"rc4-md5:x@h.example:1").decode(): "not supported",
                 "vless://" + "a" * 9000: "too long"}
        for link, needle in cases.items():
            with self.assertRaises(links.LinkError, msg=link) as caught:
                links.parse(link)
            self.assertIn(needle, str(caught.exception), link)
        for junk in (os.urandom(64).hex(), "vless://", "vmess://e30=", "ss://@", "trojan://a@[::1"):
            with self.assertRaises(links.LinkError, msg=junk):
                links.parse(junk)

    def test_local_port_is_private(self):
        cfg = links.xray_config(links.parse(f"vless://{self.ID}@h.example:443"), "203.0.113.9", 47210, "u", "p", 7)
        inbound = cfg["inbounds"][0]
        self.assertEqual((inbound["listen"], inbound["port"]), ("127.0.0.1", 47210))
        self.assertEqual(inbound["settings"], {"auth": "password", "accounts": [{"user": "u", "pass": "p"}], "udp": False})
        self.assertEqual(len(cfg["outbounds"]), 1)


class ServerConfigTest(unittest.TestCase):
    LINK = f"vless://{LinkTest.ID}@example.com:8443?security=tls&type=ws#Frankfurt"
    KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"

    def test_a_link_defines_the_server(self):
        cfg = config.validate({"proxy": config.parse_proxy_url(self.LINK)})
        proxy = cfg["proxy"]
        self.assertEqual((proxy["type"], proxy["host"], proxy["port"]), ("vless", "example.com", 8443))
        self.assertEqual(config.proxy_label(cfg), "vless://example.com:8443")
        same = config.validate(config.merge(cfg, {"proxy": {"type": "link", "link": None}}))   # "keep the link"
        self.assertEqual(same["proxy"], proxy)
        with self.assertRaises(config.ConfigError):
            config.validate({"proxy": {"type": "link", "link": ""}})
        with self.assertRaises(config.ConfigError):
            config.validate({"proxy": {"type": "vless", "link": "hysteria2://x@h:1"}})

    def test_secrets_never_leave(self):
        cfg = config.validate({"proxy": config.parse_proxy_url(self.LINK)})
        view = config.public_view(cfg)["proxy"]
        self.assertNotIn(LinkTest.ID, json.dumps(view))
        self.assertEqual((view["link_set"], view["name"], view["key_set"]), (True, "Frankfurt", False))
        ssh = config.validate({"proxy": {"type": "ssh", "host": "h.example", "port": 22, "username": "me",
                                         "password": "pw", "private_key": self.KEY}})
        view = config.public_view(ssh)["proxy"]
        self.assertNotIn("AAAA", json.dumps(view))
        self.assertEqual((view["key_set"], view["password_set"]), (True, True))

    def test_switching_kind_drops_what_no_longer_applies(self):
        cfg = config.validate({"proxy": config.parse_proxy_url(self.LINK)})
        socks = config.validate(config.merge(cfg, {"proxy": {"type": "socks5", "host": "10.0.0.1", "port": 1080}}))
        self.assertEqual((socks["proxy"]["link"], socks["proxy"]["private_key"]), ("", ""))

    def test_ssh_needs_a_user_and_a_secret(self):
        base = {"type": "ssh", "host": "h.example", "port": 22}
        for extra in ({"username": "", "password": "x"}, {"username": "me"},
                      {"username": "me", "private_key": "not a key"}):
            with self.assertRaises(config.ConfigError, msg=extra):
                config.validate({"proxy": dict(base, **extra)})
        ok = config.validate({"proxy": dict(base, username="me", private_key=self.KEY)})
        self.assertEqual(config.proxy_label(ok), "ssh://h.example:22")
        self.assertEqual(config.parse_proxy_url("ssh://me:pw@h.example")["port"], 22)

    def test_engine_port(self):
        with self.assertRaises(config.ConfigError):
            config.validate({"engine_port": 47201})
        with self.assertRaises(config.ConfigError):
            config.validate({"engine_path": "xray"})
        rules = firewall.render(47201, 47253, 0x5057, [], [], engine_port=47210)
        self.assertIn("tcp dport 47210 meta mark != 0x5057 reject with tcp reset", rules)
        self.assertLess(rules.index("tcp dport 47210"), rules.index('iifname "lo" accept'))


class CountryConfigTest(unittest.TestCase):
    def test_blocked_countries(self):
        cfg = config.validate({"blocked_countries": ["ir", " RU ", "IR"]})
        self.assertEqual(cfg["blocked_countries"], ["IR", "RU"])
        for bad in ({"blocked_countries": ["XX"]}, {"blocked_countries": "IR"}, {"blocked_countries": [1]},
                    {"blocked_countries": ["IR"], "ip_check_url": ""},
                    {"country_check_seconds": -1}, {"country_check_seconds": 301}, {"country_check_seconds": True}):
            with self.assertRaises(config.ConfigError, msg=bad):
                config.validate(bad)
        self.assertEqual(config.validate({"country_check_seconds": 0})["country_check_seconds"], 0)


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


class GeoTest(unittest.TestCase):
    IPWHO = json.dumps({"ip": "203.0.113.9", "success": True, "country": "Australia", "country_code": "AU",
                        "city": "Brisbane", "latitude": -27.4679371, "longitude": 153.0280882})

    def test_reply_formats(self):
        self.assertEqual(geo.parse_reply(self.IPWHO), {
            "ip": "203.0.113.9", "country": "AU", "city": "Brisbane", "latitude": -27.4679, "longitude": 153.0281})
        ipinfo = geo.parse_reply('{"ip": "203.0.113.9", "city": "Brisbane", "country": "AU", '
                                 '"loc": "-27.4679,153.0281"}')
        self.assertEqual((ipinfo["latitude"], ipinfo["longitude"], ipinfo["country"]), (-27.4679, 153.0281, "AU"))
        ip_api = geo.parse_reply('{"status": "success", "query": "203.0.113.9", "countryCode": "DE", '
                                 '"city": "Frankfurt am Main", "lat": 50.11, "lon": 8.68}')
        self.assertEqual((ip_api["ip"], ip_api["country"], ip_api["latitude"]), ("203.0.113.9", "DE", 50.11))
        trace = geo.parse_reply("ip=203.0.113.9\nloc=NL\n")
        self.assertEqual((trace["country"], trace["latitude"]), ("NL", None))

    def test_bad_replies_are_harmless(self):
        nothing = dict.fromkeys(("ip", "country", "city", "latitude", "longitude"))
        for body in ("", "<html>", "[1, 2]", '{"success": false, "ip": "203.0.113.9"}',
                     '{"status": "fail", "query": "203.0.113.9"}', '{"ip": "not an address"}'):
            self.assertEqual(geo.parse_reply(body), nothing, body)
        for junk in ('"latitude": 91, "longitude": 10', '"latitude": 0, "longitude": 0', '"latitude": "x"',
                     '"latitude": true, "longitude": 1', '"latitude": NaN, "longitude": 1', '"loc": "1"',
                     '"latitude": 10, "longitude": 181'):
            reply = geo.parse_reply('{"ip": "203.0.113.9", %s}' % junk)
            self.assertEqual((reply["ip"], reply["latitude"], reply["longitude"]), ("203.0.113.9", None, None), junk)
        city = geo.parse_reply(json.dumps({"ip": "203.0.113.9", "city": "A\x1b[31m\n" + "b" * 200}))["city"]
        self.assertTrue(city.isprintable() and len(city) <= 60)

    def test_describe_and_formatting(self):
        exact = geo.describe("AU", geo.parse_reply(self.IPWHO))
        self.assertEqual((exact["country_name"], exact["city"], exact["location_exact"]),
                         ("Australia", "Brisbane", True))
        fallback = geo.describe("AU")
        self.assertEqual((fallback["city"], fallback["location_exact"]), (None, False))
        self.assertEqual((fallback["latitude"], fallback["longitude"]), COUNTRIES["AU"][1:])
        unknown = geo.describe("ZZ")
        self.assertEqual((unknown["country"], unknown["country_name"], unknown["latitude"]), ("ZZ", None, None))
        self.assertIsNone(geo.describe(None)["latitude"])
        self.assertEqual(geo.format_coordinates(-27.4679, 153.0281), "27.47° S, 153.03° E")
        self.assertEqual(geo.format_coordinates(50.11, -8.68), "50.11° N, 8.68° W")
        self.assertEqual(geo.format_place(exact), "Brisbane, Australia")
        self.assertEqual(geo.format_place(fallback), "Australia")
        self.assertEqual(geo.format_place(unknown), "ZZ")
        self.assertIsNone(geo.format_place({}))

    def test_generated_data(self):
        self.assertTrue(all(len(row) == geo.MAP_COLS and set(row) <= {"#", "."} for row in LAND))
        for code, (name, latitude, longitude) in COUNTRIES.items():
            self.assertRegex(code, r"^[A-Z]{2}$")
            self.assertTrue(name and -90 <= latitude <= 90 and -180 <= longitude <= 180, code)
        flags = os.path.join(os.path.dirname(__file__), "..", "data", "flags")
        missing = [code for code in COUNTRIES if not os.path.exists(os.path.join(flags, code.lower() + ".png"))]
        self.assertEqual(missing, [])

    def test_map_cells(self):
        def is_land(latitude, longitude):
            column, row = geo.map_cell(latitude, longitude)
            return LAND[min(int(row), geo.MAP_ROWS - 1)][min(int(column), geo.MAP_COLS - 1)] == "#"

        for name, latitude, longitude in (("Tehran", 35.7, 51.4), ("Frankfurt", 50.1, 8.7), ("Denver", 39.7, -105.0),
                                          ("Brasilia", -15.8, -47.9), ("Alice Springs", -23.7, 133.9),
                                          ("Novosibirsk", 55.0, 82.9), ("Anadyr", 64.7, 177.5)):
            self.assertTrue(is_land(latitude, longitude), name)
        for name, latitude, longitude in (("Atlantic", 30.0, -45.0), ("Pacific", 0.0, -140.0), ("Indian", -30.0, 80.0)):
            self.assertFalse(is_land(latitude, longitude), name)
        for latitude, longitude in ((90, 0), (-90, 0), (0, 180), (0, -180), (0, 191.99), (0, -168)):
            column, row = geo.map_cell(latitude, longitude)
            self.assertTrue(0 <= column <= geo.MAP_COLS and 0 <= row <= geo.MAP_ROWS)


class MonitorLocationTest(unittest.TestCase):
    """The lookup order: public IP first, then where it is, with a quiet fallback."""

    class Core:
        cfg = dict(config.defaults(), ip_check_url="http://ip.test/", geo_url="http://geo.test/")

    def lookup(self, replies, ip_reply="ip=203.0.113.9\nloc=AU\n", watcher=None):
        calls = []

        async def fake_fetch(_core, url):
            calls.append(url)
            reply = ip_reply if url == "http://ip.test/" else replies.pop(0)
            if isinstance(reply, Exception):
                raise reply
            return reply

        async def scenario():
            watch = watcher or monitor.Monitor(self.Core())
            watch.state = "connected"
            original, monitor.fetch = monitor.fetch, fake_fetch
            try:
                await watch._start_check()[0]
            finally:
                monitor.fetch = original
            return watch

        return run(scenario()), calls

    def test_city_from_the_geo_service(self):
        watch, calls = self.lookup([GeoTest.IPWHO])
        self.assertEqual(calls, ["http://ip.test/", "http://geo.test/"])
        self.assertEqual(watch.public_ip, "203.0.113.9")
        place = watch.location()
        self.assertEqual((place["country"], place["city"], place["latitude"], place["location_exact"]),
                         ("AU", "Brisbane", -27.4679, True))
        _, again = self.lookup([], watcher=watch)   # same address: not asked a second time
        self.assertEqual(again, ["http://ip.test/"])
        watch.public_ip = "198.51.100.1"            # another address: the old answer no longer applies
        self.assertFalse(watch.location()["location_exact"])

    def test_capital_when_the_geo_service_fails(self):
        for failure in (OSError("down"), "<html>rate limited</html>", '{"success": false}'):
            watch, _ = self.lookup([failure])
            place = watch.location()
            self.assertEqual(watch.public_ip, "203.0.113.9")
            self.assertEqual((place["country_name"], place["city"], place["location_exact"]), ("Australia", None, False))
            self.assertEqual((place["latitude"], place["longitude"]), COUNTRIES["AU"][1:])

    def test_geo_lookup_can_be_turned_off(self):
        core = type("Core", (), {"cfg": dict(config.defaults(), ip_check_url="http://ip.test/", geo_url="")})()
        watch, calls = self.lookup([], watcher=monitor.Monitor(core))
        self.assertEqual(calls, ["http://ip.test/"])
        self.assertEqual(watch.location()["country"], "AU")

    def test_one_service_can_answer_both(self):
        watch, calls = self.lookup([], ip_reply=GeoTest.IPWHO)
        self.assertEqual(calls, ["http://ip.test/"])
        self.assertEqual(watch.location()["city"], "Brisbane")

    def test_nothing_is_shown_once_disconnected(self):
        watch, _ = self.lookup([GeoTest.IPWHO])
        watch.public_ip = watch.country = None
        place = watch.location()
        self.assertEqual((place["country"], place["latitude"], place["city"]), (None, None, None))


class CountryGateTest(unittest.TestCase):
    """With blocked countries, a connection passes only after a fresh, successful check."""

    def setUp(self):
        self.replies = {"http://ip.test/": "ip=203.0.113.9\nloc=DE\n", "http://geo.test/": OSError("down")}
        self.calls = []
        self.cut = []
        gate = self

        class Relay:
            def close_connections(self, proxied_only=False):
                gate.cut.append(proxied_only)

        class Core:
            cfg = dict(config.defaults(), ip_check_url="http://ip.test/", geo_url="http://geo.test/",
                       blocked_countries=["IR"], country_check_seconds=5)
            tproxy = Relay()

        self.core = Core()

    def play(self, scenario):
        async def fake_fetch(_core, url):
            self.calls.append(url)
            await asyncio.sleep(0)
            reply = self.replies[url]
            if isinstance(reply, Exception):
                raise reply
            return reply

        async def wrapper():
            watch = monitor.Monitor(self.core)
            watch.state = "connected"
            original, monitor.fetch = monitor.fetch, fake_fetch
            try:
                return await scenario(watch)
            finally:
                monitor.fetch = original

        return run(wrapper())

    def checks(self):
        return self.calls.count("http://ip.test/")

    def test_allowed_country_passes_and_is_remembered_briefly(self):
        async def scenario(watch):
            first = await watch.permit()
            second = await watch.permit()
            return first, second, watch.exit_verdict

        self.assertEqual(self.play(scenario), (True, True, "ok"))
        self.assertEqual(self.checks(), 1)
        self.assertEqual(self.cut, [])

    def test_blocked_country_never_passes(self):
        self.replies["http://ip.test/"] = "ip=203.0.113.9\nloc=IR\n"

        async def scenario(watch):
            answers = [await watch.permit() for _ in range(5)]
            return answers, watch.exit_verdict, watch.exit_error, watch.location()["country"]

        answers, verdict, error, country = self.play(scenario)
        self.assertEqual(answers, [False] * 5)
        self.assertEqual((verdict, country), ("blocked", "IR"))
        self.assertIn("Iran", error)
        self.assertEqual(self.calls, ["http://ip.test/"])   # no second service, no repeated checks
        self.assertEqual(self.cut, [True])                  # proxied connections were cut, once

    def test_exit_moving_into_a_blocked_country_is_caught_by_the_next_check(self):
        async def scenario(watch):
            before = await watch.permit()
            self.replies["http://ip.test/"] = "ip=198.51.100.7\nloc=IR\n"
            watch._verified_at -= 6     # the last check is now older than country_check_seconds
            after = await watch.permit()
            return before, after, watch.exit_verdict

        self.assertEqual(self.play(scenario), (True, False, "blocked"))
        self.assertEqual(self.cut, [True])

    def test_failed_or_useless_checks_hold_traffic(self):
        for reply in (OSError("no route"), asyncio.TimeoutError(), "<html>", "203.0.113.9\n", ""):
            self.replies["http://ip.test/"] = reply

            async def scenario(watch):
                return await watch.permit(), watch.exit_verdict, bool(watch.exit_error)

            self.assertEqual(self.play(scenario), (False, "unknown", True), repr(reply))

    def test_a_pass_expires(self):
        async def scenario(watch):
            await watch.permit()
            self.replies["http://ip.test/"] = OSError("gone")
            watch._verified_at -= 6
            return await watch.permit(), watch.exit_verdict

        self.assertEqual(self.play(scenario), (False, "unknown"))

    def test_strict_mode_checks_before_every_connection(self):
        self.core.cfg["country_check_seconds"] = 0

        async def scenario(watch):
            return [await watch.permit() for _ in range(4)]

        self.assertEqual(self.play(scenario), [True] * 4)
        self.assertEqual(self.checks(), 4)

    def test_connections_arriving_together_share_one_check(self):
        async def scenario(watch):
            return await asyncio.gather(*(watch.permit() for _ in range(50)))

        self.assertEqual(self.play(scenario), [True] * 50)
        self.assertEqual(self.checks(), 1)

    def test_second_service_can_veto(self):
        self.replies["http://geo.test/"] = json.dumps({"ip": "203.0.113.9", "country_code": "IR",
                                                       "latitude": 35.7, "longitude": 51.4})

        async def scenario(watch):
            return await watch.permit(), watch.exit_verdict, watch.country

        self.assertEqual(self.play(scenario), (False, "blocked", "IR"))

    def test_not_connected_means_no(self):
        async def scenario(watch):
            watch.state = "unreachable"
            return await watch.permit()

        self.assertFalse(self.play(scenario))
        self.assertEqual(self.calls, [])

    def test_blocking_the_current_country_takes_effect_at_once(self):
        async def scenario(watch):
            allowed = await watch.permit()
            self.core.cfg["blocked_countries"] = ["DE", "IR"]
            watch.policy_changed()
            return allowed, watch.exit_verdict, await watch.permit()

        self.assertEqual(self.play(scenario), (True, "blocked", False))
        self.assertEqual(self.cut, [True])

    def test_changed_settings_cancel_a_running_check(self):
        async def scenario(watch):
            task, _ = watch._start_check()
            watch.restart()             # not running: nothing to restart, but
            watch._forget()             # this is what restart and "unreachable" do
            await asyncio.wait({task})
            return task.cancelled(), watch.exit_verdict

        self.assertEqual(self.play(scenario), (True, "unknown"))

    def test_no_list_means_no_gate(self):
        self.core.cfg["blocked_countries"] = []

        async def scenario(watch):
            return await watch.permit()

        self.assertTrue(self.play(scenario))
        self.assertEqual(self.calls, [])


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
