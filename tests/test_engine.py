"""The helper processes for real: Xray and ssh against servers started on loopback.

No privileges and no network are needed, but the programs are: tests are
skipped where `xray` or `sshd` is not installed.
"""

import asyncio
import base64
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest

from proxywall import config, engine, paths, upstream

XRAY = engine.find_program("xray", "", engine.XRAY_PLACES)
SSHD = shutil.which("sshd") or ("/usr/sbin/sshd" if os.path.exists("/usr/sbin/sshd") else None)
UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"


def free_port():
    import socket
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_port(port, timeout=10):
    import socket
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket() as sock:
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.05)
    raise AssertionError(f"nothing listens on port {port}")


class FakeCore:
    """What the engine needs from the daemon, and nothing else."""
    mark = 0

    class direct:
        @staticmethod
        async def resolve_host(host):
            return ["127.0.0.1"]

    def __init__(self):
        self.cfg = dict(config.defaults(), engine_port=free_port())


class EngineCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="proxywall-engine-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self._paths = (paths.STATE_DIR, paths.RUNTIME_DIR)
        paths.STATE_DIR, paths.RUNTIME_DIR = os.path.join(self.tmp, "state"), os.path.join(self.tmp, "run")
        for directory in (paths.STATE_DIR, paths.RUNTIME_DIR):
            os.makedirs(directory)
        self.addCleanup(lambda: setattr(paths, "STATE_DIR", self._paths[0]))
        self.addCleanup(lambda: setattr(paths, "RUNTIME_DIR", self._paths[1]))
        self.servers = []
        self.addCleanup(self.stop_servers)

    def stop_servers(self):
        for process in self.servers:
            process.terminate()
        for process in self.servers:
            process.wait()

    def spawn(self, command, port):
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.servers.append(process)
        wait_port(port)
        return process

    def play(self, scenario):
        """Run *scenario(core, engine, fetch)* next to a tiny web server."""
        async def web(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello")
            await writer.drain()
            writer.close()

        async def wrapper():
            server = await asyncio.start_server(web, "127.0.0.1", 0)
            web_port = server.sockets[0].getsockname()[1]
            core = FakeCore()
            runner = engine.Engine(core)

            async def fetch(kind, settings=None):
                sock, _ = await upstream.dial(settings or runner.settings(kind), ["127.0.0.1"], "127.0.0.1", web_port)
                reader, writer = await asyncio.open_connection(sock=sock)
                writer.write(b"GET / HTTP/1.0\r\n\r\n")
                data = await asyncio.wait_for(reader.read(200), 10)
                writer.close()
                return data

            try:
                return await scenario(core, runner, fetch)
            finally:
                await runner.stop()
                server.close()

        return asyncio.run(wrapper())


@unittest.skipUnless(XRAY, "xray is not installed")
class XrayEngineTest(EngineCase):
    def start_server(self):
        self.ports = {name: free_port() for name in ("vless", "vmess", "ss", "trojan")}
        inbounds = [
            {"listen": "127.0.0.1", "port": self.ports["vless"], "protocol": "vless",
             "settings": {"clients": [{"id": UUID}], "decryption": "none"}},
            {"listen": "127.0.0.1", "port": self.ports["vmess"], "protocol": "vmess",
             "settings": {"clients": [{"id": UUID}]},
             "streamSettings": {"network": "ws", "wsSettings": {"path": "/vm"}}},
            {"listen": "127.0.0.1", "port": self.ports["ss"], "protocol": "shadowsocks",
             "settings": {"method": "aes-256-gcm", "password": "secret", "network": "tcp"}},
            {"listen": "127.0.0.1", "port": self.ports["trojan"], "protocol": "trojan",
             "settings": {"clients": [{"password": "secret"}]},
             "streamSettings": {"network": "httpupgrade", "httpupgradeSettings": {"path": "/tr"}}},
        ]
        path = os.path.join(self.tmp, "server.json")
        with open(path, "w") as handle:
            json.dump({"log": {"loglevel": "none"}, "inbounds": inbounds, "outbounds": [{"protocol": "freedom"}]}, handle)
        self.spawn([XRAY, "run", "-c", path], self.ports["vless"])
        vmess = base64.b64encode(json.dumps({
            "v": "2", "ps": "t", "add": "localhost", "port": self.ports["vmess"], "id": UUID, "aid": 0,
            "net": "ws", "path": "/vm", "tls": ""}).encode()).decode()
        secret = base64.urlsafe_b64encode(b"aes-256-gcm:secret").decode().rstrip("=")
        return {
            "vless": f"vless://{UUID}@localhost:{self.ports['vless']}?type=tcp#one",
            "vmess": f"vmess://{vmess}",
            "shadowsocks": f"ss://{secret}@127.0.0.1:{self.ports['ss']}#three",
            "trojan": f"trojan://secret@127.0.0.1:{self.ports['trojan']}?security=none&type=httpupgrade&path=/tr#four",
        }

    def proxy(self, link):
        return config.validate({"proxy": config.parse_proxy_url(link)})["proxy"]

    def test_every_protocol_carries_traffic(self):
        share = self.start_server()

        async def scenario(core, runner, fetch):
            seen = {}
            for kind, link in share.items():
                await runner.ensure(self.proxy(link))
                self.assertTrue(runner.running, f"{kind}: {runner.error}")
                seen[kind] = await fetch(kind)
            return seen

        for kind, reply in self.play(scenario).items():
            self.assertTrue(reply.endswith(b"hello"), f"{kind}: {reply!r}")

    def test_local_port_wants_the_daemons_password(self):
        share = self.start_server()

        async def scenario(core, runner, fetch):
            await runner.ensure(self.proxy(share["vless"]))
            stranger = upstream.ProxySettings("socks5", "127.0.0.1", runner.port, "", "")
            with self.assertRaises(upstream.ProxyError):
                await fetch("vless", stranger)
            wrong = upstream.ProxySettings("socks5", "127.0.0.1", runner.port, "proxywall", "guess")
            with self.assertRaises(upstream.ProxyError):
                await fetch("vless", wrong)

        self.play(scenario)

    def test_restarts_after_a_crash_and_cleans_up(self):
        share = self.start_server()
        config_file = os.path.join(paths.RUNTIME_DIR, "engine.json")

        async def scenario(core, runner, fetch):
            await runner.ensure(self.proxy(share["vless"]))
            self.assertEqual(os.stat(config_file).st_mode & 0o777, 0o600)
            first = runner._process.pid
            runner._process.kill()
            for _ in range(100):
                await asyncio.sleep(0.1)
                if runner.running and runner._process and runner._process.pid != first:
                    break
            self.assertTrue(runner.running, "the engine was not restarted")
            reply = await fetch("vless")
            process = runner._process
            await runner.stop()
            return reply, process.returncode

        reply, code = self.play(scenario)
        self.assertTrue(reply.endswith(b"hello"))
        self.assertIsNotNone(code, "stop() left the process running")
        self.assertFalse(os.path.exists(config_file), "the configuration with the secrets was left behind")

    def test_missing_program_is_explained(self):
        async def scenario(core, runner, fetch):
            core.cfg["engine_path"] = os.path.join(self.tmp, "no-such-xray")
            original, engine.READY_TIMEOUT = engine.READY_TIMEOUT, 1.0
            try:
                await runner.ensure(self.proxy(f"vless://{UUID}@127.0.0.1:1?type=tcp"))
            finally:
                engine.READY_TIMEOUT = original
            return runner.running, runner.error

        running, error = self.play(scenario)
        self.assertFalse(running)
        self.assertIn("not an executable", error)


@unittest.skipUnless(SSHD and shutil.which("ssh-keygen"), "sshd is not installed")
class SshEngineTest(EngineCase):
    def start_sshd(self, host_key="hostkey"):
        port = getattr(self, "ssh_port", None) or free_port()
        self.ssh_port = port
        for name in (host_key, "userkey", "lockedkey", "otherkey"):
            path = os.path.join(self.tmp, name)
            if not os.path.exists(path):
                passphrase = "open sesame" if name == "lockedkey" else ""
                subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", passphrase, "-f", path], check=True)
        with open(os.path.join(self.tmp, "authorized_keys"), "w") as handle:
            for name in ("userkey", "lockedkey"):
                with open(os.path.join(self.tmp, name + ".pub")) as key:
                    handle.write(key.read())
        conf = os.path.join(self.tmp, "sshd_config")
        with open(conf, "w") as handle:
            handle.write(f"Port {port}\nListenAddress 127.0.0.1\nHostKey {self.tmp}/{host_key}\n"
                         f"PidFile {self.tmp}/sshd.pid\nAuthorizedKeysFile {self.tmp}/authorized_keys\n"
                         "StrictModes no\nUsePAM no\nPasswordAuthentication no\nAllowTcpForwarding yes\n"
                         "LogLevel ERROR\n")
        try:
            return self.spawn([SSHD, "-D", "-e", "-f", conf], port)
        except AssertionError:
            self.skipTest("sshd cannot be started as this user here")

    def proxy(self, key_name, password=""):
        with open(os.path.join(self.tmp, key_name)) as handle:
            key = handle.read()
        import getpass
        return config.validate({"proxy": {"type": "ssh", "host": "localhost", "port": self.ssh_port,
                                          "username": getpass.getuser(), "password": password,
                                          "private_key": key}})["proxy"]

    def test_tunnel_with_a_key(self):
        self.start_sshd()

        async def scenario(core, runner, fetch):
            await runner.ensure(self.proxy("userkey"))
            self.assertTrue(runner.running, runner.error)
            reply = await fetch("ssh")
            key_file = os.path.join(paths.RUNTIME_DIR, "engine_key")
            mode = os.stat(key_file).st_mode & 0o777
            await runner.stop()
            return reply, mode, os.path.exists(key_file)

        reply, mode, left_behind = self.play(scenario)
        self.assertTrue(reply.endswith(b"hello"), reply)
        self.assertEqual(mode, 0o600)
        self.assertFalse(left_behind)

    def test_key_with_a_passphrase(self):
        self.start_sshd()

        async def scenario(core, runner, fetch):
            await runner.ensure(self.proxy("lockedkey", password="open sesame"))
            self.assertTrue(runner.running, runner.error)
            return await fetch("ssh")

        self.assertTrue(self.play(scenario).endswith(b"hello"))

    def test_rejected_key_is_explained(self):
        self.start_sshd()

        async def scenario(core, runner, fetch):
            await runner.ensure(self.proxy("otherkey"))
            for _ in range(60):
                if runner.error:
                    break
                await asyncio.sleep(0.1)
            return runner.running, runner.error

        running, error = self.play(scenario)
        self.assertFalse(running)
        self.assertIn("rejected", error)

    def test_changed_host_key_is_refused(self):
        first = self.start_sshd()

        async def connect(core, runner, fetch):
            await runner.ensure(self.proxy("userkey"))
            for _ in range(60):
                if runner.error or runner.running:
                    break
                await asyncio.sleep(0.1)
            return runner.running, runner.error

        self.assertEqual(self.play(connect), (True, None))
        first.terminate()
        first.wait()
        self.servers.remove(first)
        time.sleep(0.3)
        self.start_sshd(host_key="hostkey2")       # somebody else answers on the same address
        running, error = self.play(connect)
        self.assertFalse(running)
        self.assertIn("host key", error)


if __name__ == "__main__":
    unittest.main()
