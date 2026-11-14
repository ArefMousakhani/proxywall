"""End-to-end tests with real nftables rules, in throw-away network namespaces.

No root needed: run ``tests/integration/run.sh`` (it re-executes this module
inside ``unshare --user --net --mount``).

Topology::

    [cont] 172.20.0.2 --- 172.20.0.1 [host] 10.0.0.2 --- 10.0.0.1 [wan]
     a "container"         daemon + nftables              proxies, DNS and
                           + test client                  fake public servers

"wan" owns 93.184.216.34 (example.com), 5.5.5.5 (site.ir), 9.9.9.9, 1.1.1.1 and
2001:db8::1. The servers report which address contacted them, so a request
that arrived *directly* shows the host's own address (10.0.0.2), while a
proxied one does not.
"""

import base64
import json
import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)

from proxywall import config, engine  # noqa: E402
from proxywall.client import Client, DaemonError, DaemonUnavailable  # noqa: E402

XRAY = engine.find_program("xray", "", engine.XRAY_PLACES)
UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

IN_NETNS = os.environ.get("PROXYWALL_NETNS_TEST") == "1"
HOST_IP = "10.0.0.2"
CONT_IP = "172.20.0.2"
FAKE_PREFIXES = ("198.18.", "198.19.")


def sh(command, check=True):
    return subprocess.run(command, shell=True, check=check, capture_output=True, text=True)


def http_get(host, port=80, timeout=5, path="/"):
    """GET through the system's normal resolver and stack. Returns parsed JSON."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
            # Complete once the announced body is here: some tunnels (Shadowsocks
            # 2022 in Xray) pass the server's close on only after a long pause.
            head, sep, body = data.partition(b"\r\n\r\n")
            length = [line.split(b":")[1] for line in head.split(b"\r\n") if line.lower().startswith(b"content-length:")]
            if sep and length and len(body) >= int(length[0]):
                break
    head, _, body = data.partition(b"\r\n\r\n")
    if not head.startswith(b"HTTP/1.1 200"):
        raise OSError(f"bad reply: {head[:60]!r}")
    return json.loads(body)


CONT_GET = r"""
import json, socket, sys
host = sys.argv[1]
try:
    s = socket.create_connection((host, 80), timeout=5)
    s.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk: break
        data += chunk
    print(data.partition(b"\r\n\r\n")[2].decode())
except OSError as exc:
    print(json.dumps({"error": type(exc).__name__}))
"""


@unittest.skipUnless(IN_NETNS, "run tests/integration/run.sh")
class NetnsTest(unittest.TestCase):
    maxDiff = None

    # ------------------------------------------------------------ fixture
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="proxywall-it-")
        cls.log = os.path.join(cls.tmp, "wan.log")
        cls.procs = {}
        open(cls.log, "w").close()
        sh("mount -t tmpfs tmpfs /run && mkdir -p /run/netns /run/systemd/resolve")
        for name in ("stub-resolv.conf", "resolv.conf"):
            with open(f"/run/systemd/resolve/{name}", "w") as handle:
                handle.write("nameserver 10.0.0.1\noptions timeout:2 attempts:1\n")
        if not os.path.exists("/etc/resolv.conf"):
            raise unittest.SkipTest("/etc/resolv.conf does not point into /run/systemd/resolve")
        sh("""
            set -e
            ip link set lo up
            ip netns add wan
            ip netns add cont
            ip link add h0 type veth peer name w0
            ip link set w0 netns wan
            ip link add hc0 type veth peer name c0
            ip link set c0 netns cont
            ip addr add 10.0.0.2/24 dev h0
            ip -6 addr add fd00::2/64 dev h0 nodad
            ip link set h0 up
            ip addr add 172.20.0.1/24 dev hc0
            ip link set hc0 up
            ip route add default via 10.0.0.1
            ip -6 route add default via fd00::1
            sysctl -qw net.ipv4.ip_forward=1

            ip -n wan link set lo up
            ip -n wan addr add 10.0.0.1/24 dev w0
            ip -n wan -6 addr add fd00::1/64 dev w0 nodad
            ip -n wan link set w0 up
            ip -n wan link add pub type dummy
            ip -n wan link set pub up
            for a in 93.184.216.34 5.5.5.5 9.9.9.9 1.1.1.1; do ip -n wan addr add $a/32 dev pub; done
            ip -n wan -6 addr add 2001:db8::1/128 dev pub nodad
            ip -n wan route add 172.20.0.0/24 via 10.0.0.2

            ip -n cont link set lo up
            ip -n cont addr add 172.20.0.2/24 dev c0
            ip -n cont link set c0 up
            ip -n cont route add default via 172.20.0.1
        """)
        cls.cert = None
        if shutil.which("openssl"):
            cert, key = os.path.join(cls.tmp, "cert.pem"), os.path.join(cls.tmp, "key.pem")
            made = sh(f"openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=test "
                      f"-keyout {key} -out {cert}", check=False)
            if made.returncode == 0:
                cls.cert = (cert, key)
        cls.start_wan("services", *(["--cert", cls.cert[0], "--key", cls.cert[1]] if cls.cert else []))
        cls.start_wan("socks")
        cls.start_wan("http")

        cls.env = dict(os.environ, PYTHONPATH=ROOT,
                       PROXYWALL_STATE_DIR=os.path.join(cls.tmp, "state"),
                       PROXYWALL_RUNTIME_DIR=os.path.join(cls.tmp, "run"))
        cls.client = Client(os.path.join(cls.tmp, "run", "control.sock"), timeout=20)
        cls.start_daemon()

    @classmethod
    def tearDownClass(cls):
        for proc in cls.procs.values():
            proc.kill()
        for proc in cls.procs.values():
            proc.wait()
        if os.environ.get("PROXYWALL_KEEP_TMP") != "1":
            shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def start_wan(cls, role, *extra):
        marker = f"ready {role}"
        def count():
            with open(cls.log) as handle:
                return handle.read().count(marker)
        before = count()
        cls.procs[role] = subprocess.Popen(
            ["ip", "netns", "exec", "wan", sys.executable, os.path.join(HERE, "fake_internet.py"),
             "--role", role, "--log", cls.log, *extra])
        cls.wait_for(lambda: count() > before, f"{role} to start")

    @classmethod
    def stop_wan(cls, role):
        proc = cls.procs.pop(role)
        proc.terminate()
        proc.wait()
        # `ip netns exec` does not forward signals to its child reliably
        sh(f"ip netns pids wan | xargs -r -n1 sh -c 'grep -qa -- \"--role.{role}\" /proc/$0/cmdline && kill -9 $0' ", check=False)
        time.sleep(0.2)

    @classmethod
    def start_daemon(cls):
        # PROXYWALL_DAEMON lets the suite exercise an installed copy instead of the source tree.
        command = [os.environ["PROXYWALL_DAEMON"]] if os.environ.get("PROXYWALL_DAEMON") \
            else [sys.executable, "-m", "proxywall.daemon"]
        if shutil.which("setpriv"):
            # Same privilege as the systemd unit: nothing but CAP_NET_ADMIN.
            command = ["setpriv", "--bounding-set", "-all,+net_admin", "--inh-caps", "-all"] + command
        with open(os.path.join(cls.tmp, "daemon.log"), "a") as stderr:
            cls.procs["daemon"] = subprocess.Popen(command, env=cls.env, cwd=ROOT, stderr=stderr)

        def up():
            try:
                cls.client.status()
                return True
            except DaemonUnavailable:
                return False
        cls.wait_for(up, "the daemon to start")

    @staticmethod
    def wait_for(predicate, what, timeout=15.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.1)
        raise AssertionError(f"timed out waiting for {what}")

    # ------------------------------------------------------------ helpers
    def wan_log(self):
        with open(self.log) as handle:
            return handle.read().splitlines()

    def mark(self):
        return len(self.wan_log())

    def since(self, mark):
        return self.wan_log()[mark:]

    def state(self):
        return self.client.status()["state"]

    def wait_state(self, wanted, timeout=20.0):
        self.wait_for(lambda: self.state() == wanted, f"state '{wanted}' (now '{self.state()}')", timeout)

    def configure(self, **patch):
        self.client.set_config(patch)

    def reset(self, wait="connected", **extra):
        """Known starting point: SOCKS5 proxy, connected, *.ir excluded."""
        if extra.get("blocked_countries"):
            self.addCleanup(self.configure, blocked_countries=[])
        patch = {"proxy": {"type": "socks5", "host": "10.0.0.1", "port": 1080,
                           "username": "", "password": ""},
                 "kill_switch": False, "allow_lan": True, "exclude": ["*.ir"], "ip_check_url": "",
                 "geo_url": "", "blocked_countries": [], "country_check_seconds": 5}
        patch.update(extra)
        self.configure(**patch)
        self.client.connect()
        self.wait_state(wait)

    def assert_proxied(self, host, port=80):
        mark = self.mark()
        reply = http_get(host, port)
        self.assertNotEqual(reply["peer"], HOST_IP, f"{host} was reached directly")
        return reply, self.since(mark)

    def assert_direct(self, host, port=80):
        mark = self.mark()
        reply = http_get(host, port)
        self.assertEqual(reply["peer"], HOST_IP, f"{host} did not go out directly")
        return reply, self.since(mark)

    def assert_blocked(self, host, port=80):
        """The request must fail *and* must never reach the server."""
        mark = self.mark()
        started = time.monotonic()
        with self.assertRaises(OSError):
            http_get(host, port, timeout=4)
        self.assertLess(time.monotonic() - started, 3.5, "blocked traffic should fail fast, not hang")
        leaked = [line for line in self.since(mark) if line.startswith(("http ", "https ", "udp "))]
        self.assertEqual(leaked, [], "traffic leaked to the server")

    def cont_get(self, host):
        out = subprocess.run(["ip", "netns", "exec", "cont", sys.executable, "-c", CONT_GET, host],
                             capture_output=True, text=True, timeout=20).stdout
        return json.loads(out)

    # ------------------------------------------------------------ tests
    def test_01_direct_before_connecting(self):
        self.assertEqual(self.state(), "disconnected")
        self.assertEqual(http_get("example.com")["peer"], HOST_IP)
        self.assertNotEqual(sh("nft list table inet proxywall", check=False).returncode, 0)

    def test_02_connect_requires_a_proxy(self):
        with self.assertRaises(DaemonError):
            self.client.connect()
        self.assertEqual(self.state(), "disconnected")

    def test_03_traffic_goes_through_the_proxy(self):
        self.reset()
        self.assertTrue(socket.gethostbyname("www.example.com").startswith(FAKE_PREFIXES))
        reply, log = self.assert_proxied("www.example.com")
        self.assertEqual(reply["host"], "www.example.com")
        self.assertIn("socks www.example.com:80", log)          # the proxy resolved the name
        self.assertFalse([line for line in self.wan_log() if line.startswith("dns") and "www.example.com" in line],
                         "the name leaked to the local DNS server")

    def test_04_literal_addresses_are_proxied(self):
        self.reset()
        _, log = self.assert_proxied("93.184.216.34")
        self.assertIn("socks 93.184.216.34:80", log)

    def test_05_excluded_domain_goes_direct(self):
        self.reset()
        for host in ("site.ir", "sub.site.ir"):
            _, log = self.assert_direct(host)
            self.assertFalse([line for line in log if line.startswith("socks")])
        self.assert_proxied("example.com")

    def test_06_excluded_network_goes_direct_including_udp(self):
        self.reset(exclude=["*.ir", "9.9.9.0/24"])
        self.assert_direct("9.9.9.9")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.sendto(b"ping", ("9.9.9.9", 9999))
            self.assertEqual(sock.recv(100), b"echo:ping")

    def test_07_udp_and_ping_cannot_leak(self):
        self.reset()
        mark = self.mark()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1.5)
            sock.connect(("93.184.216.34", 9999))
            with self.assertRaises(OSError):
                sock.send(b"leak")
                sock.recv(100)
        if shutil.which("ping"):
            self.assertNotEqual(sh("ping -c1 -W1 93.184.216.34", check=False).returncode, 0)
        self.assertFalse([line for line in self.since(mark) if line.startswith("udp")])

    def test_08_lan_is_reachable_directly(self):
        self.reset()
        self.assert_direct("10.0.0.1")
        self.assert_direct("printer.lan")

    def test_09_lan_is_proxied_when_allow_lan_is_off(self):
        self.reset(allow_lan=False)
        self.assert_proxied("10.0.0.1")
        self.assert_proxied("www.example.com")

    def test_10_proxy_failure_blocks_instead_of_going_direct(self):
        self.reset()
        self.stop_wan("socks")
        try:
            self.assert_blocked("www.example.com")
            self.assert_blocked("93.184.216.34")
            self.assert_direct("site.ir")                      # exclusions are unaffected
            self.wait_state("unreachable")
            self.assertIn("proxy", self.client.status()["error"])
            self.assert_blocked("example.com")
        finally:
            self.start_wan("socks")
        self.wait_state("connected")
        self.assert_proxied("www.example.com")

    def test_11_daemon_crash_blocks_instead_of_going_direct(self):
        self.reset()
        daemon = self.procs.pop("daemon")
        daemon.send_signal(signal.SIGKILL)
        daemon.wait()
        try:
            self.assert_blocked("www.example.com")
            self.assert_blocked("93.184.216.34")
            self.assert_blocked("5.5.5.5")
        finally:
            self.start_daemon()
        self.wait_state("connected")                           # the session is restored
        self.assert_proxied("www.example.com")

    def test_12_clean_stop_keeps_the_firewall(self):
        self.reset()
        daemon = self.procs.pop("daemon")
        daemon.terminate()
        self.assertEqual(daemon.wait(timeout=10), 0)
        try:
            self.assert_blocked("www.example.com")
        finally:
            self.start_daemon()
        self.wait_state("connected")

    def test_13_disconnect_without_kill_switch_restores_direct(self):
        self.reset()
        self.client.disconnect()
        self.assertEqual(self.state(), "disconnected")
        self.assertNotEqual(sh("nft list table inet proxywall", check=False).returncode, 0)
        self.assertFalse(os.path.exists(os.path.join(self.env["PROXYWALL_STATE_DIR"], "boot.nft")))
        time.sleep(1.2)                                        # placeholder answers expire (TTL 1 s)
        self.assert_direct("example.com")

    def test_14_kill_switch_blocks_while_disconnected(self):
        self.reset(kill_switch=True)
        self.client.disconnect()
        self.assertEqual(self.state(), "blocked")
        self.assert_blocked("www.example.com")
        self.assert_blocked("93.184.216.34")
        self.assert_direct("site.ir")
        self.assert_direct("10.0.0.1")
        boot = os.path.join(self.env["PROXYWALL_STATE_DIR"], "boot.nft")
        self.assertTrue(os.path.exists(boot))
        # What systemd does at boot, before the daemon is up: load the saved rules.
        self.assertEqual(sh(f"nft -c -f {boot}", check=False).stderr, "")
        self.configure(kill_switch=False)
        self.assertEqual(self.state(), "disconnected")
        time.sleep(1.2)
        self.assert_direct("example.com")

    def test_15_kill_switch_survives_a_restart_while_disconnected(self):
        self.reset(kill_switch=True)
        self.client.disconnect()
        daemon = self.procs.pop("daemon")
        daemon.terminate()
        daemon.wait(timeout=10)
        sh("nft delete table inet proxywall")                  # simulate a reboot: kernel state is gone
        boot = os.path.join(self.env["PROXYWALL_STATE_DIR"], "boot.nft")
        sh(f"nft -f {boot}")                                   # ExecStartPre
        self.assert_blocked("93.184.216.34")
        self.start_daemon()
        self.assertEqual(self.state(), "blocked")
        self.assert_blocked("www.example.com")
        self.configure(kill_switch=False)

    def test_16_http_proxy(self):
        self.reset(proxy={"type": "http", "host": "10.0.0.1", "port": 8080})
        _, log = self.assert_proxied("www.example.com")
        self.assertIn("httpproxy www.example.com:80", log)
        self.assert_direct("site.ir")

    def test_17_proxy_authentication(self):
        self.stop_wan("socks")
        self.start_wan("socks", "--auth", "alice:s3cret")
        try:
            self.configure(proxy={"type": "socks5", "host": "10.0.0.1", "port": 1080,
                                  "username": "alice", "password": "wrong"},
                           exclude=["*.ir"], ip_check_url="")
            self.client.connect()
            self.wait_state("unreachable")
            self.assertIn("username or password", self.client.status()["error"])
            self.assert_blocked("www.example.com")
            self.configure(proxy={"password": "s3cret"})
            self.wait_state("connected")
            self.assert_proxied("www.example.com")
            self.assertNotIn("s3cret", json.dumps(self.client.get_config()))
        finally:
            self.stop_wan("socks")
            self.start_wan("socks")

    def test_18_proxy_by_hostname(self):
        self.reset(proxy={"type": "socks5", "host": "proxy.example.net", "port": 1080})
        self.assert_proxied("www.example.com")

    def test_19_sni_keeps_exclusions_working_for_literal_addresses(self):
        if not self.cert:
            self.skipTest("openssl not available")
        self.reset()
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        def tls_get(ip, name):
            with socket.create_connection((ip, 443), timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname=name) as tls:
                    tls.sendall(f"GET / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n".encode())
                    data = b""
                    while True:
                        chunk = tls.recv(65536)
                        if not chunk:
                            break
                        data += chunk
            return json.loads(data.partition(b"\r\n\r\n")[2])

        self.assertEqual(tls_get("5.5.5.5", "site.ir")["peer"], HOST_IP)
        self.assertNotEqual(tls_get("93.184.216.34", "example.com")["peer"], HOST_IP)

    def test_20_other_dns_record_types(self):
        self.reset()
        mark = self.mark()
        sys.path.insert(0, ROOT)
        from proxywall import dnsmsg

        def txt(name):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(8)
                sock.sendto(dnsmsg.build_query(name, 16), ("10.0.0.1", 53))
                rcode, _, answers = dnsmsg.parse_response(sock.recv(4096))
            return rcode, [rdata[1:].decode() for _, _, rdata in answers]

        self.assertEqual(txt("info.example.org"), (0, ["txt-for-info.example.org"]))
        self.assertEqual(txt("site.ir"), (0, ["txt-for-site.ir"]))
        log = self.since(mark)
        self.assertIn("socks 1.1.1.1:53", log)                         # remote DNS through the proxy
        self.assertFalse([l for l in log if "info.example.org" in l and f"dns {HOST_IP}" in l])
        self.assertTrue([l for l in log if "site.ir" in l and f"dns {HOST_IP}" in l])

    def test_21_ipv6(self):
        self.reset()
        _, log = self.assert_proxied("2001:db8::1")
        self.assertIn("socks 2001:db8::1:80", log)
        self.assertEqual(socket.getaddrinfo("www.example.com", 80, socket.AF_INET)[0][4][0][:7], "198.18.")
        with self.assertRaises(socket.gaierror):
            socket.getaddrinfo("www.example.com", 80, socket.AF_INET6)

    def test_22_forwarded_traffic_is_captured_too(self):
        self.reset()
        self.assertEqual(self.cont_get("www.example.com").get("host"), "www.example.com")
        self.assertNotEqual(self.cont_get("www.example.com")["peer"], CONT_IP)
        # Excluded names are dialled directly *by the daemon*, so the server sees the host.
        mark = self.mark()
        self.assertEqual(self.cont_get("site.ir")["peer"], HOST_IP)
        self.assertFalse([l for l in self.since(mark) if l.startswith("socks")])
        self.stop_wan("socks")
        try:
            mark = self.mark()
            self.assertIn("error", self.cont_get("www.example.com"))
            self.assertIn("error", self.cont_get("93.184.216.34"))
            self.assertFalse([l for l in self.since(mark) if l.startswith("http ")])
        finally:
            self.start_wan("socks")

    def test_23_large_transfer_is_intact(self):
        self.reset()
        size = 64 * 1024 * 1024
        started = time.monotonic()
        received, checksum = 0, 0
        with socket.create_connection(("big.example.com", 80), timeout=30) as sock:
            sock.sendall(f"GET /blob/{size} HTTP/1.1\r\nHost: big.example.com\r\n\r\n".encode())
            data = b""
            while b"\r\n\r\n" not in data:
                data += sock.recv(65536)
            body = data.partition(b"\r\n\r\n")[2]
            while True:
                received += len(body)
                checksum = (checksum + sum(body[::4093])) & 0xFFFFFFFF
                body = sock.recv(1 << 20)
                if not body:
                    break
        elapsed = time.monotonic() - started
        self.assertEqual(received, size)
        print(f"\n    relay throughput: {size / elapsed / 1e6:.0f} MB/s ", end="", file=sys.stderr)

    def test_24_many_parallel_connections(self):
        self.reset()
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(64) as pool:
            replies = list(pool.map(lambda _: http_get("www.example.com", timeout=20), range(400)))
        self.assertEqual(len(replies), 400)
        self.assertTrue(all(r["peer"] != HOST_IP for r in replies))
        self.wait_for(lambda: self.client.status()["stats"]["active"] == 0, "connections to drain")

    def test_25_ports_are_not_reachable_from_outside(self):
        self.reset()
        cfg = self.client.get_config()
        for port in (cfg["tcp_port"], cfg["dns_port"]):
            probe = sh(f"ip netns exec cont {sys.executable} -c \"import socket; "
                       f"socket.create_connection(('172.20.0.1', {port}), timeout=2)\"", check=False)
            self.assertNotEqual(probe.returncode, 0, f"port {port} is reachable from another machine")

    def test_26_status_reports_traffic(self):
        self.reset()
        before = self.client.status()["stats"]
        self.assert_proxied("www.example.com")
        after = self.client.status()["stats"]
        self.assertGreater(after["down"], before["down"])
        self.assertGreater(after["proxied"], before["proxied"])

    def test_27_connections_opened_before_connecting_are_cut(self):
        self.configure(kill_switch=False)
        self.client.disconnect()
        time.sleep(1.2)
        with socket.create_connection(("93.184.216.34", 80), timeout=5) as old:   # direct, pre-existing
            self.reset()
            mark = self.mark()
            with self.assertRaises(OSError):
                old.sendall(b"GET / HTTP/1.1\r\nHost: leak.example\r\nConnection: close\r\n\r\n")
                if not old.recv(100):
                    raise ConnectionResetError
            self.assertFalse([l for l in self.since(mark) if "leak.example" in l])

    def test_28_dns_is_captured_on_every_transport(self):
        self.reset()
        from proxywall import dnsmsg
        query = dnsmsg.build_query("transport.example.com", dnsmsg.A)

        def fake(reply):
            rcode, _, answers = dnsmsg.parse_response(reply)
            return rcode == 0 and socket.inet_ntoa(answers[0][2]).startswith(FAKE_PREFIXES)

        mark = self.mark()
        with socket.create_connection(("10.0.0.1", 53), timeout=5) as tcp:           # DNS over TCP
            tcp.sendall(len(query).to_bytes(2, "big") + query)
            data = tcp.recv(4096)
        self.assertTrue(fake(data[2:]))
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as udp6:              # IPv6 resolver
            udp6.settimeout(5)
            udp6.sendto(query, ("fd00::1", 53))
            self.assertTrue(fake(udp6.recv(4096)))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp4:               # any public resolver
            udp4.settimeout(5)
            udp4.sendto(query, ("9.9.9.9", 53))
            self.assertTrue(fake(udp4.recv(4096)))
        self.assertFalse([l for l in self.since(mark) if l.startswith("dns")], "a DNS query left the machine")

    # ------------------------------------------------------------ blocked countries
    TRACE = "http://93.184.216.34/trace"

    def set_exit_country(self, code):
        with open(self.log + ".country", "w", encoding="utf-8") as handle:
            handle.write(code)

    def test_29_blocked_country_stops_the_very_next_connection(self):
        self.set_exit_country("DE")
        self.reset(ip_check_url=self.TRACE, blocked_countries=["IR"], country_check_seconds=0)
        self.assert_proxied("www.example.com")
        held = socket.create_connection(("www.example.com", 80), timeout=5)   # open before the exit moves
        self.addCleanup(held.close)

        self.set_exit_country("IR")
        self.assert_blocked("www.example.com")          # no waiting: the next connection is already refused
        self.assert_blocked("93.184.216.34")
        status = self.client.status()
        self.assertEqual((status["state"], status["country"]), ("country_blocked", "IR"))
        self.assertIn("Iran", status["error"])
        try:                                            # the connection from before was cut as well
            held.sendall(b"GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: close\r\n\r\n")
            self.assertEqual(held.recv(100), b"")
        except OSError:
            pass
        self.assert_direct("site.ir")                   # what the user excluded never used the proxy anyway
        self.assertEqual(http_get("10.0.0.1")["peer"], HOST_IP)
        for _ in range(3):
            self.assert_blocked("www.example.com")      # and it stays shut

        self.set_exit_country("DE")
        self.wait_state("connected", 25)
        self.assert_proxied("www.example.com")

    def test_30_blocked_country_with_a_check_interval(self):
        self.set_exit_country("DE")
        self.reset(ip_check_url=self.TRACE, blocked_countries=["IR", "RU"], country_check_seconds=1)
        mark = self.mark()
        for _ in range(5):
            self.assert_proxied("www.example.com")
        self.assertLessEqual(len([line for line in self.since(mark) if line.startswith("check ")]), 3,
                             "a fresh answer should be reused for a moment")
        self.set_exit_country("RU")
        time.sleep(1.2)                                 # older than country_check_seconds
        self.assert_blocked("www.example.com")
        self.assertEqual(self.state(), "country_blocked")

    def test_31_unverifiable_exit_is_blocked(self):
        self.set_exit_country("DE")
        self.configure(blocked_countries=[], ip_check_url="")
        self.reset(wait="checking", ip_check_url="http://93.184.216.34:81/trace", blocked_countries=["IR"])
        self.assert_blocked("www.example.com")
        self.assertIn("could not be checked", self.client.status()["error"])
        self.assert_direct("site.ir")

    def test_32_second_opinion_and_restart(self):
        """The city service may veto, and a restarted service starts closed."""
        self.set_exit_country("IR")
        self.configure(blocked_countries=[], ip_check_url="")
        # A plain-text IP service knows no country, so the verdict rests on the second service.
        self.reset(wait="country_blocked", ip_check_url="http://93.184.216.34/ip",
                   geo_url="http://93.184.216.34/geo", blocked_countries=["IR"])
        self.assert_blocked("www.example.com")
        daemon = self.procs.pop("daemon")
        daemon.terminate()
        daemon.wait()
        self.start_daemon()
        self.assert_blocked("www.example.com")
        self.wait_state("country_blocked")
        # The way out of a wrong veto: stop asking that service.
        self.set_exit_country("DE")
        self.configure(ip_check_url=self.TRACE, geo_url="")
        self.wait_state("connected")
        self.assert_proxied("www.example.com")

    # ------------------------------------------------------------ share links (Xray)
    SERVER = "93.184.216.34"   # a public address: only marked traffic may reach it

    def start_xray_server(self):
        """An Xray server on the fake internet, one port per protocol."""
        if not XRAY:
            self.skipTest("xray is not installed")
        if "xray" in self.procs:
            return
        sys.path.insert(0, HERE)
        from fake_internet import HOSTS
        key16 = base64.b64encode(b"0123456789abcdef").decode()
        clients = {"clients": [{"id": UUID}], "decryption": "none"}
        inbounds = [
            {"port": 2001, "protocol": "vless", "settings": clients},
            {"port": 2002, "protocol": "vmess", "settings": {"clients": [{"id": UUID}]},
             "streamSettings": {"network": "ws", "wsSettings": {"path": "/vm"}}},
            {"port": 2004, "protocol": "shadowsocks",
             "settings": {"method": "aes-256-gcm", "password": "secret", "network": "tcp"}},
            {"port": 2005, "protocol": "vless", "settings": clients,
             "streamSettings": {"network": "grpc", "grpcSettings": {"serviceName": "svc"}}},
            {"port": 2006, "protocol": "vless", "settings": clients,
             "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/x"}}},
            {"port": 2007, "protocol": "shadowsocks",
             "settings": {"method": "2022-blake3-aes-128-gcm", "password": key16, "network": "tcp"}},
            {"port": 2009, "protocol": "trojan", "settings": {"clients": [{"password": "secret"}]},
             "streamSettings": {"network": "httpupgrade", "httpupgradeSettings": {"path": "/up"}}},
        ]
        if self.cert:
            tls = {"certificates": [{"certificateFile": self.cert[0], "keyFile": self.cert[1]}]}
            inbounds += [
                {"port": 2003, "protocol": "trojan", "settings": {"clients": [{"password": "secret"}]},
                 "streamSettings": {"network": "raw", "security": "tls", "tlsSettings": tls}},
                {"port": 2008, "protocol": "vless", "settings": clients,
                 "streamSettings": {"network": "ws", "security": "tls", "tlsSettings": tls,
                                    "wsSettings": {"path": "/ws"}}},
            ]
        for inbound in inbounds:
            inbound["listen"] = "0.0.0.0"
        path = os.path.join(self.tmp, "xray-server.json")
        with open(path, "w") as handle:
            json.dump({"log": {"loglevel": "warning"}, "dns": {"hosts": HOSTS}, "inbounds": inbounds,
                       "outbounds": [{"protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}}]}, handle)
        with open(os.path.join(self.tmp, "xray-server.log"), "a") as output:
            type(self).procs["xray"] = subprocess.Popen(
                ["ip", "netns", "exec", "wan", XRAY, "run", "-c", path], stdout=output, stderr=output)

        def listening():
            return sh("ip netns exec wan sh -c 'ss -ltn | grep -q :2001'", check=False).returncode == 0
        self.wait_for(listening, "the Xray server to start")

    def stop_xray_server(self):
        proc = self.procs.pop("xray")
        proc.terminate()
        proc.wait()
        sh("ip netns pids wan | xargs -r -n1 sh -c 'grep -qa xray-server /proc/$0/cmdline && kill -9 $0'", check=False)
        time.sleep(0.3)

    def share_links(self):
        vmess = base64.b64encode(json.dumps({
            "v": "2", "ps": "vmess over websocket", "add": "example.com", "port": "2002", "id": UUID, "aid": "0",
            "net": "ws", "path": "/vm", "host": "example.com", "tls": ""}).encode()).decode()
        secret = base64.urlsafe_b64encode(b"aes-256-gcm:secret").decode().rstrip("=")
        key16 = base64.b64encode(b"0123456789abcdef").decode().replace("=", "%3D")
        share = {
            "vless": f"vless://{UUID}@{self.SERVER}:2001?encryption=none&type=tcp#plain",
            "vless by name": f"vless://{UUID}@example.com:2001?type=tcp#by-name",
            "vmess ws": f"vmess://{vmess}",
            "shadowsocks": f"ss://{secret}@{self.SERVER}:2004#ss",
            "shadowsocks 2022": f"ss://2022-blake3-aes-128-gcm:{key16}@{self.SERVER}:2007#ss2022",
            "vless grpc": f"vless://{UUID}@{self.SERVER}:2005?type=grpc&serviceName=svc#grpc",
            "vless xhttp": f"vless://{UUID}@{self.SERVER}:2006?type=xhttp&path=%2Fx#xhttp",
            "trojan httpupgrade": f"trojan://secret@{self.SERVER}:2009?security=none&type=httpupgrade&path=%2Fup#tr",
        }
        if self.cert:
            share["trojan tls"] = f"trojan://secret@{self.SERVER}:2003?sni=test&allowInsecure=1#trojan"
            share["vless ws tls"] = (f"vless://{UUID}@example.com:2008?security=tls&sni=test&allowInsecure=1"
                                     "&type=ws&path=%2Fws#wss")
        return share

    def use_link(self, link, wait="connected"):
        self.reset(wait=wait, proxy=config.parse_proxy_url(link))

    def test_40_every_share_link_protocol_carries_traffic(self):
        self.start_xray_server()
        for name, link in self.share_links().items():
            with self.subTest(protocol=name):
                self.use_link(link)
                reply, _ = self.assert_proxied("www.example.com")
                self.assertEqual(reply["host"], "www.example.com")
                self.assert_proxied("93.184.216.34")            # a literal address
                self.assert_direct("site.ir")                   # exclusions are untouched
                self.assertFalse([line for line in self.wan_log() if line.startswith("dns") and "www.example" in line])

    def test_41_engine_port_is_for_the_daemon_only(self):
        self.start_xray_server()
        self.use_link(self.share_links()["vless"])
        port = self.client.get_config()["engine_port"]
        with self.assertRaises(OSError):                        # another program on this machine
            socket.create_connection(("127.0.0.1", port), timeout=3).close()
        self.assert_proxied("www.example.com")                  # while the daemon uses it happily

    def test_42_dead_link_server_blocks_and_recovers(self):
        self.start_xray_server()
        self.use_link(self.share_links()["vless"])
        self.assert_proxied("www.example.com")
        self.stop_xray_server()
        self.assert_blocked("www.example.com")                  # never direct
        self.wait_state("unreachable", 40)
        self.assert_blocked("www.example.com")
        self.start_xray_server()
        self.wait_state("connected", 40)
        self.assert_proxied("www.example.com")

    def test_43_engine_crash_blocks_and_recovers(self):
        self.start_xray_server()
        self.use_link(self.share_links()["shadowsocks"])
        self.assert_proxied("www.example.com")
        sh("pkill -9 -f 'run -c .*/run/engine[.]json'")
        self.assert_blocked("www.example.com")                  # the helper is gone: closed, not direct

        def works():
            try:
                return http_get("www.example.com")["peer"] != HOST_IP
            except OSError:
                return False
        self.wait_for(works, "the engine to be restarted", 30)

    def test_44_wrong_link_secret_is_reported_and_blocks(self):
        self.start_xray_server()
        wrong = self.share_links()["vless"].replace(UUID, "11111111-2222-3333-4444-555555555555")
        self.use_link(wrong, wait="unreachable")
        self.assert_blocked("www.example.com")
        self.assertTrue(self.client.status()["error"])

    def test_45_country_gate_applies_to_link_servers(self):
        self.start_xray_server()
        self.set_exit_country("IR")
        self.reset(wait="country_blocked", proxy=config.parse_proxy_url(self.share_links()["vless"]),
                   ip_check_url=self.TRACE, blocked_countries=["IR"])
        self.assert_blocked("www.example.com")
        self.set_exit_country("DE")
        self.wait_state("connected", 25)
        self.assert_proxied("www.example.com")

    def test_46_marked_pipe_is_the_only_way_out_for_ssh(self):
        """ssh reaches its server through proxywall.pipe: marked it passes, unmarked it does not."""
        self.reset(kill_switch=True)
        request = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        mark = str(self.client.get_config()["fwmark"])

        def through_pipe(mark_value):
            return subprocess.run([sys.executable, "-m", "proxywall.pipe", "93.184.216.34", "80", mark_value],
                                  input=request, capture_output=True, cwd=ROOT, timeout=30)
        marked = through_pipe(mark)
        self.assertIn(b"200 OK", marked.stdout)
        self.assertIn(HOST_IP.encode(), marked.stdout)          # it went out directly, as the daemon's own traffic
        unmarked = through_pipe("0")
        self.assertNotIn(HOST_IP.encode(), unmarked.stdout)     # captured like any other program

    def test_99_final_disconnect_cleans_up(self):
        self.configure(kill_switch=False)
        self.client.disconnect()
        self.assertEqual(sh("nft list ruleset").stdout.strip(), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
