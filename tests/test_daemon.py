"""The service end to end over its control socket, in development mode
(PROXYWALL_FIREWALL=none: no privileges, no real firewall)."""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

from proxywall.client import Client, DaemonError, DaemonUnavailable  # noqa: E402


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class DaemonTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.env = dict(os.environ, PYTHONPATH=ROOT, PROXYWALL_FIREWALL="none",
                       PROXYWALL_STATE_DIR=os.path.join(cls.tmp.name, "state"),
                       PROXYWALL_RUNTIME_DIR=os.path.join(cls.tmp.name, "run"))
        cls.env.pop("PROXYWALL_SOCKET", None)
        cls.client = Client(os.path.join(cls.tmp.name, "run", "control.sock"))
        cls.ports = {"tcp_port": free_port(), "dns_port": free_port()}
        cls.daemon = None
        cls.start()
        cls.client.set_config(cls.ports)

    @classmethod
    def start(cls):
        cls.daemon = subprocess.Popen([sys.executable, "-m", "proxywall.daemon"], env=cls.env, cwd=ROOT,
                                      stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 10
        while True:
            try:
                cls.client.status()
                return
            except DaemonUnavailable:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.05)

    @classmethod
    def stop(cls):
        cls.daemon.terminate()
        cls.daemon.wait(timeout=10)

    @classmethod
    def tearDownClass(cls):
        cls.stop()
        cls.tmp.cleanup()

    def cli(self, *args):
        return subprocess.run([sys.executable, "-m", "proxywall.cli", *args], cwd=ROOT, text=True,
                              capture_output=True,
                              env=dict(self.env, PROXYWALL_SOCKET=self.client.path))

    def test_1_initial_state(self):
        status = self.client.status()
        self.assertEqual(status["state"], "disconnected")
        self.assertFalse(status["proxy_configured"])
        with self.assertRaises(DaemonError):
            self.client.connect()

    def test_2_validation_errors_are_reported(self):
        with self.assertRaises(DaemonError) as caught:
            self.client.set_config({"proxy": {"host": "bad host", "port": 99999}, "exclude": ["*"]})
        self.assertEqual(len(caught.exception.errors), 3)
        with self.assertRaises(DaemonError):
            self.client.request("no_such_command")
        self.assertEqual(self.client.get_config()["proxy"]["host"], "")   # nothing was applied

    def test_3_cli_workflow(self):
        self.assertEqual(self.cli("set-proxy", "socks5://bob:pw@127.0.0.1:9").returncode, 0)
        self.assertIn("*.ir", self.cli("exclude", "add", "*.ir", "10.9.0.0/16", "https://example.com/x").stdout)
        self.assertEqual(self.cli("exclude", "remove", "example.com").stdout.split(), ["*.ir", "10.9.0.0/16"])
        self.assertEqual(self.cli("exclude", "add", "not valid!").returncode, 1)
        shown = json.loads(self.cli("config").stdout)
        self.assertEqual(shown["proxy"], {"type": "socks5", "host": "127.0.0.1", "port": 9,
                                          "username": "bob", "password_set": True,
                                          "key_set": False, "link_set": False, "name": ""})
        self.assertEqual(self.cli("kill-switch", "on").returncode, 0)
        result = self.cli("connect", "--wait", "8")
        self.assertEqual(result.returncode, 3)
        self.assertIn("unreachable", result.stdout.lower())
        status = json.loads(self.cli("status", "--json").stdout)
        self.assertEqual((status["state"], status["enabled"], status["firewall_active"]),
                         ("unreachable", True, True))
        self.assertIn("Connection refused", status["error"])
        self.assertIn("Proxy unreachable", self.cli("status").stdout)
        self.assertIn("unreachable", self.cli("logs").stdout)

    def test_4_state_survives_a_restart(self):
        self.stop()
        state_dir = self.env["PROXYWALL_STATE_DIR"]
        for name in ("config.json", "state.json"):
            self.assertEqual(os.stat(os.path.join(state_dir, name)).st_mode & 0o777, 0o600, name)
        self.assertEqual(self.cli("status").returncode, 4)       # clear message while it is down
        self.start()
        status = self.client.status()
        self.assertTrue(status["enabled"])
        self.assertIn(status["state"], ("connecting", "unreachable"))

    def test_5_kill_switch_states(self):
        self.client.disconnect()
        self.assertEqual(self.client.status()["state"], "blocked")
        self.client.set_config({"kill_switch": False})
        self.assertEqual(self.client.status()["state"], "disconnected")
        with self.assertRaises(DaemonError):
            self.client.set_config({"kill_switch": "maybe"})

    def test_6_port_conflict_is_an_error_not_a_crash(self):
        with socket.socket() as squatter:
            squatter.bind(("0.0.0.0", 0))
            squatter.listen(1)
            self.client.set_config({"tcp_port": squatter.getsockname()[1]})
            with self.assertRaises(DaemonError) as caught:
                self.client.connect()
            self.assertIn("cannot listen", str(caught.exception))
            self.assertEqual(self.client.status()["state"], "error")
        self.client.set_config({"tcp_port": self.ports["tcp_port"]})
        self.client.connect()
        self.assertIn(self.client.status()["state"], ("connecting", "unreachable"))
        self.client.disconnect()

    def test_85_exclusions_by_command(self):
        before = self.client.get_config()["exclude"]
        self.assertEqual(self.client.status()["connections"], [])
        added = self.client.exclude(add=["Example.com", "https://mail.example.org/inbox", "10.77.0.0/16"])
        self.assertEqual(added["exclude"], before + ["example.com", "mail.example.org", "10.77.0.0/16"])
        self.assertEqual(self.client.exclude(add=["example.com"])["exclude"], added["exclude"])   # once is enough
        with self.assertRaises(DaemonError):
            self.client.exclude(add=["not a domain"])
        with self.assertRaises(DaemonError):
            self.client.request("exclude", add="example.com")
        self.assertEqual(self.client.get_config()["exclude"], added["exclude"])
        self.assertEqual(self.cli("connections").stdout.strip(), "(no open connections)")
        self.stop()                                              # saved: still there after a restart
        self.start()
        self.assertEqual(self.client.get_config()["exclude"], added["exclude"])
        left = self.client.exclude(remove=["*.example.com", "mail.example.org", "10.77.0.0/16"])
        self.assertEqual(left["exclude"], before)

    def test_8_saved_servers(self):
        for server in self.client.status()["servers"]:
            self.client.server_remove(server["id"])
        self.assertFalse(self.client.status()["proxy_configured"])
        first = self.client.server_save(None, "one", {"type": "socks5", "host": "127.0.0.1", "port": 9})
        self.assertEqual(self.cli("server", "add", "http://127.0.0.1:10", "--name", "two").returncode, 0)
        status = self.client.status()
        self.assertEqual([s["name"] for s in status["servers"]], ["one", "two"])
        self.assertEqual((status["active_server"], status["proxy"]), (first, "socks5://127.0.0.1:9"))
        listing = self.cli("server", "use", "two").stdout
        self.assertRegex(listing, r"\*\s+2\s+two\s+http://127\.0\.0\.1:10")
        self.assertEqual(self.client.status()["proxy"], "http://127.0.0.1:10")
        with self.assertRaises(DaemonError):
            self.client.server_save(None, "bad", {"type": "socks5", "host": "", "port": 1})
        with self.assertRaises(DaemonError):
            self.client.server_select("nope")
        self.assertEqual(self.client.request("server_test", ids=["zzz"])["started"], 0)
        with self.assertRaises(DaemonError):
            self.client.request("server_test", ids="s1")

        tested = self.cli("server", "test", "one")               # nothing listens on port 9
        self.assertIn("does not answer", tested.stdout)
        result = self.client.status()["tests"][first]
        self.assertEqual((result["state"], result["ping_ms"], result["reach"]), ("done", None, None))
        self.client.server_save(first, None, {"port": 11})       # an edited server has not been tested
        self.assertNotIn(first, self.client.status()["tests"])

        self.stop()                                              # the list is kept across restarts
        self.start()
        self.assertEqual([s["name"] for s in self.client.status()["servers"]], ["one", "two"])
        self.assertEqual(self.cli("server", "remove", "1").returncode, 0)
        self.assertEqual([s["name"] for s in self.client.status()["servers"]], ["two"])
        self.client.connect()
        with self.assertRaises(DaemonError):                     # not the one carrying the traffic
            self.client.server_remove(self.client.status()["active_server"])
        self.client.disconnect()

    def test_7_garbage_on_the_socket_is_survived(self):
        with socket.socket(socket.AF_UNIX) as sock:
            sock.connect(self.client.path)
            sock.sendall(b"\x00\xff not json\n[1,2]\n")
            sock.settimeout(10)
            reader = sock.makefile()     # one reader: a second one could find its line already taken
            replies = reader.readline(), reader.readline()
        self.assertTrue(all('"ok": false' in r for r in replies))
        self.assertEqual(self.client.status()["state"], "disconnected")


if __name__ == "__main__":
    unittest.main()
