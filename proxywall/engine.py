"""Protocol engines: Xray for share links, OpenSSH for SSH tunnels.

Both run as child processes that offer a local SOCKS5 port on 127.0.0.1. The
daemon is their only client, so the firewall, the exclusions and the country
gate work exactly as with a plain SOCKS5 proxy. The engine's own connection
to the server leaves through the firewall the same way the daemon's sockets
do: carrying the firewall mark (Xray sets it itself; ssh is given a marked
connection through `proxywall.pipe`).
"""

import asyncio
import contextlib
import json
import logging
import os
import secrets
import shlex
import shutil
import signal
import sys
import time

from . import links, paths, upstream

log = logging.getLogger("proxywall.engine")

ENGINE_TYPES = links.ENGINE_KINDS + ("ssh",)
XRAY_PLACES = ("/usr/lib/proxywall/xray", "/usr/local/bin/xray", "/usr/bin/xray", "/opt/xray/xray")
READY_TIMEOUT = 8.0
PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASKPASS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ssh-askpass")


class EngineError(Exception):
    pass


def find_program(name, configured="", places=()):
    """Path of an executable: the configured one, well-known places, then PATH."""
    if configured:
        if os.path.isfile(configured) and os.access(configured, os.X_OK):
            return configured
        raise EngineError(f"'{configured}' is not an executable file")
    for path in places:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return shutil.which(name)


def _die_with_parent():
    """Runs in the child before exec: do not outlive the daemon (Linux)."""
    if sys.platform.startswith("linux"):
        try:
            import ctypes
            ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGTERM)  # PR_SET_PDEATHSIG
        except Exception:
            pass


def _write_private(path, text, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)


class Engine:
    """Keeps one engine process running for the configured server, restarting it when it dies."""

    def __init__(self, core, port=None, quiet=False):
        self.core = core
        self._port = port          # None: the configured engine_port (the tunnel in use)
        self._quiet = quiet        # a short-lived test helper should not fill the log
        self.user = "proxywall"
        self.password = secrets.token_urlsafe(18)   # between the daemon and Xray's local port
        self.error = None                           # why the engine is not running, for people
        self.running = False
        self._spec = None
        self._task = None
        self._process = None
        self._ready = asyncio.Event()

    @property
    def port(self):
        return self._port or self.core.cfg["engine_port"]

    @property
    def _files(self):
        suffix = f"-{self._port}" if self._port else ""
        return (os.path.join(paths.RUNTIME_DIR, f"engine{suffix}.json"),
                os.path.join(paths.RUNTIME_DIR, f"engine_key{suffix}"))

    def settings(self, kind):
        """How the daemon reaches the engine. ssh -D cannot ask for a password; Xray does."""
        if kind == "ssh":
            return upstream.ProxySettings("socks5", "127.0.0.1", self.port, "", "")
        return upstream.ProxySettings("socks5", "127.0.0.1", self.port, self.user, self.password)

    # ------------------------------------------------------------ lifecycle
    async def ensure(self, proxy):
        """Run the engine for *proxy* (the validated `proxy` section of the configuration)."""
        spec = json.dumps([proxy, self.port, self.core.mark, self.core.cfg["engine_path"]], sort_keys=True)
        if self._task is not None and spec == self._spec and not self._task.done():
            return
        await self.stop()
        self._spec, self.error = spec, None
        self._ready.clear()
        self._task = asyncio.ensure_future(self._supervise(dict(proxy)))
        try:
            await asyncio.wait_for(self._ready.wait(), READY_TIMEOUT)
        except asyncio.TimeoutError:
            pass  # the supervisor keeps trying; the monitor reports what is wrong

    async def stop(self):
        task, self._task, self._spec = self._task, None, None
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        self.running = False
        self.error = None

    async def _supervise(self, proxy):
        delay = 1.0
        while True:
            started = time.monotonic()
            try:
                await self._run_once(proxy)
            except asyncio.CancelledError:
                raise
            except EngineError as exc:
                self.error = str(exc)
            except Exception as exc:  # a broken engine must never take the daemon down
                log.exception("engine supervisor failed")
                self.error = f"the engine could not be started: {exc}"
            self.running = False
            self._ready.set()  # whoever waits for the start should stop waiting
            log.log(logging.DEBUG if self._quiet else logging.WARNING, "engine stopped: %s", self.error)
            if time.monotonic() - started > 30:
                delay = 1.0
            await asyncio.sleep(delay)
            delay = min(delay * 2, 15.0)

    async def _run_once(self, proxy):
        kind = proxy["type"]
        host = proxy["host"]
        if upstream.ip_version(host):
            address = host
        else:
            try:
                address = (await self.core.direct.resolve_host(host))[0]
            except Exception as exc:
                raise EngineError(f"cannot find the address of {host}: {exc}") from None
        os.makedirs(paths.RUNTIME_DIR, exist_ok=True)
        if kind == "ssh":
            command, env, cleanup = self._ssh_command(proxy, address)
        else:
            command, env, cleanup = self._xray_command(proxy, address)
        tail = []
        try:
            try:
                process = await asyncio.create_subprocess_exec(
                    *command, env=env, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT, preexec_fn=_die_with_parent, start_new_session=True)
            except OSError as exc:
                raise EngineError(f"cannot start {os.path.basename(command[0])}: {exc.strerror or exc}") from None
            self._process = process
            watcher = asyncio.ensure_future(self._watch_port(process))
            try:
                while True:
                    line = await process.stdout.readline()
                    if not line:
                        break
                    text = line.decode("utf-8", "replace").strip()
                    if text:
                        log.debug("%s: %s", kind, text)
                        tail.append(text)
                        del tail[:-5]
                code = await process.wait()
            finally:
                watcher.cancel()
                await self._kill(process)
        finally:
            for path in cleanup:
                with contextlib.suppress(OSError):
                    os.unlink(path)
        reason = _explain(kind, tail) or f"exit code {code}"
        raise EngineError(f"{'ssh' if kind == 'ssh' else 'Xray'} stopped: {reason}")

    async def _watch_port(self, process):
        """Declare the engine ready once its local port answers."""
        while process.returncode is None:
            try:
                sock = await upstream.tcp_connect("127.0.0.1", self.port, self.core.mark, timeout=1.0)
            except (upstream.ProxyError, OSError, asyncio.TimeoutError):
                await asyncio.sleep(0.1)
                continue
            sock.close()
            self.running, self.error = True, None
            self._ready.set()
            log.log(logging.DEBUG if self._quiet else logging.INFO, "engine is up on 127.0.0.1:%d", self.port)
            return

    async def _kill(self, process):
        if process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                process.terminate()
            try:
                await asyncio.wait_for(asyncio.shield(process.wait()), 2)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                with contextlib.suppress(ProcessLookupError):
                    process.kill()
                with contextlib.suppress(Exception):
                    await asyncio.shield(process.wait())
        if self._process is process:
            self._process = None

    # ------------------------------------------------------------ commands
    def _xray_command(self, proxy, address):
        program = find_program("xray", self.core.cfg["engine_path"], XRAY_PLACES)
        if not program:
            raise EngineError("this kind of server needs Xray, which is not installed "
                              "(see the README, 'Other protocols')")
        try:
            server = links.parse(proxy["link"])
            config = links.xray_config(server, address, self.port, self.user, self.password, self.core.mark)
        except links.LinkError as exc:
            raise EngineError(str(exc)) from None
        path = self._files[0]
        _write_private(path, json.dumps(config))
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "XRAY_LOCATION_ASSET": paths.RUNTIME_DIR}
        return [program, "run", "-c", path], env, [path]

    def _ssh_command(self, proxy, address):
        program = find_program("ssh")
        if not program:
            raise EngineError("SSH tunnels need the OpenSSH client (package openssh-client)")
        cleanup = []
        # ssh reaches the server through a helper that opens a marked socket:
        # the firewall lets nothing else out.
        pipe = [sys.executable, "-I", "-c",
                "import sys; sys.path.insert(0, sys.argv[1]); from proxywall.pipe import main; main(sys.argv[2:])",
                PACKAGE_ROOT, address, str(proxy["port"]), str(self.core.mark)]
        options = {
            "ProxyCommand": shlex.join(pipe),
            "HostKeyAlias": f"{proxy['host']}:{proxy['port']}",
            "UserKnownHostsFile": os.path.join(paths.STATE_DIR, "known_hosts"),
            "GlobalKnownHostsFile": "/dev/null",
            "StrictHostKeyChecking": "accept-new",
            "ExitOnForwardFailure": "yes",
            "ServerAliveInterval": "15",
            "ServerAliveCountMax": "3",
            "ConnectTimeout": "12",
            "NumberOfPasswordPrompts": "1",
            "IdentitiesOnly": "yes",
            "IdentityAgent": "none",
            "ForwardAgent": "no",
            "ForwardX11": "no",
            "PermitLocalCommand": "no",
            "LogLevel": "ERROR",
        }
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": paths.RUNTIME_DIR}
        methods = []
        command = [program, "-N", "-T", "-F", "/dev/null", "-D", f"127.0.0.1:{self.port}",
                   "-p", str(proxy["port"]), "-l", proxy["username"]]
        if proxy["private_key"]:
            key = self._files[1]
            _write_private(key, proxy["private_key"].rstrip("\n") + "\n")
            cleanup.append(key)
            command += ["-i", key]
            methods.append("publickey")
        if proxy["password"]:
            # Answers the password prompt, and the passphrase prompt of an encrypted key.
            env.update(SSH_ASKPASS=ASKPASS, SSH_ASKPASS_REQUIRE="force", PROXYWALL_SSH_SECRET=proxy["password"])
            methods += ["password", "keyboard-interactive"]
        options["PreferredAuthentications"] = ",".join(methods) or "none"
        for key, value in options.items():
            command += ["-o", f"{key}={value}"]
        return command + [address], env, cleanup


def _explain(kind, tail):
    """Turn the last lines of an engine into one sentence a person can act on."""
    text = " ".join(tail)
    lowered = text.lower()
    if kind == "ssh":
        if "host key verification failed" in lowered or "remote host identification has changed" in lowered:
            return ("the server's host key has changed since the first connection. If that is expected, "
                    "remove /var/lib/proxywall/known_hosts")
        if "permission denied" in lowered:
            return "the server rejected the username, password or key"
        if "connection refused" in lowered or "connection closed" in lowered or "proxycommand" in lowered:
            return "cannot reach the SSH server"
        if "timed out" in lowered:
            return "the SSH server did not answer in time"
        if "bad permissions" in lowered or "invalid format" in lowered or "error in libcrypto" in lowered:
            return "the private key could not be read (wrong format?)"
    # The start-up chatter says nothing about why it stopped.
    useful = [line for line in tail if "core: Xray" not in line and "Reading config" not in line]
    return useful[-1][-200:] if useful else None
