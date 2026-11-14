"""proxywalld - the privileged service that owns the firewall and the relays."""

import argparse
import asyncio
import collections
import json
import logging
import os
import signal
import sys
import time

from . import __version__, config, firewall, paths, upstream
from .control import ControlServer
from .dnsserver import DnsServer
from .fakeip import FakeIPPool
from .monitor import Monitor
from .resolver import DirectResolver
from .rules import ExcludeRules
from .tproxy import TransparentProxy

log = logging.getLogger("proxywall")


class CommandError(Exception):
    """An error that is reported to the client without a traceback in the log."""
    expected = True


class RingLog(logging.Handler):
    """Keeps the most recent log lines in memory for `proxywall logs` and the GUI."""

    def __init__(self, size=500):
        super().__init__()
        self.lines = collections.deque(maxlen=size)

    def emit(self, record):
        try:
            self.lines.append({"time": record.created, "level": record.levelname.lower(),
                               "message": record.getMessage()})
        except Exception:
            pass


class Core:
    """State machine. Desired state = (config, state.enabled); `reconcile` makes it real.

    ============  ========  =========  ==========================================
    enabled       kill sw.  firewall   behaviour
    ============  ========  =========  ==========================================
    no            off       removed    normal direct networking
    no            on        applied    everything blocked (exclusions still direct)
    yes           any       applied    everything through the proxy, or nowhere
    ============  ========  =========  ==========================================
    """

    def __init__(self, fw=None):
        self.cfg = config.defaults()
        self.enabled = False
        self.active = False       # firewall applied and listeners expected to run
        self.error = None         # why the desired state could not be reached
        self.config_error = None
        self.started = time.time()
        self.stats = {k: 0 for k in ("up", "down", "active", "total", "proxied",
                                     "direct", "blocked", "failed")}
        self.ring = RingLog()
        self.pool = FakeIPPool()
        self.rules = ExcludeRules()
        self.mark = 0
        self.proxy = upstream.ProxySettings("socks5", "", 1080, "", "")
        self.direct = DirectResolver(lambda: self.cfg["direct_dns"])
        self.firewall = fw
        self.tproxy = TransparentProxy(self)
        self.dns = DnsServer(self)
        self.monitor = Monitor(self)
        self.control = ControlServer(self, paths.SOCKET_PATH)
        self._lock = asyncio.Lock()
        self._stop = asyncio.Event()

    # ------------------------------------------------------------ derived
    @property
    def tunnel_open(self):
        """May non-excluded traffic be handed to the proxy right now?"""
        return self.enabled and self.active

    @property
    def proxy_label(self):
        return config.proxy_label(self.cfg)

    async def proxy_ips(self):
        host = self.proxy.host
        if not host:
            raise upstream.ProxyError("config", "no proxy is configured")
        if upstream.ip_version(host):
            return [host]
        return await self.direct.resolve_host(host)

    async def dial_proxy(self, host, port):
        """Connect to host:port through the configured proxy (marked socket)."""
        return await upstream.dial(self.proxy, await self.proxy_ips(), host, port, self.mark)

    # ------------------------------------------------------------ persistence
    def _load(self):
        try:
            self.cfg = config.load(paths.CONFIG_FILE)
        except config.ConfigError as exc:
            # Fail closed: a broken config must not silently open the network.
            self.config_error = f"configuration is invalid: {exc}"
            log.error("%s", self.config_error)
            self.cfg = config.defaults()
            self.cfg["kill_switch"] = os.path.exists(paths.BOOT_RULES_FILE)
        try:
            with open(paths.STATE_FILE, encoding="utf-8") as handle:
                self.enabled = bool(json.load(handle).get("enabled"))
        except FileNotFoundError:
            pass
        except (OSError, ValueError, AttributeError) as exc:
            log.error("cannot read %s: %s", paths.STATE_FILE, exc)
        self.pool.load(paths.FAKEIP_FILE)
        self._adopt_config()

    def _adopt_config(self):
        cfg = self.cfg
        logging.getLogger("proxywall").setLevel(cfg["log_level"].upper())
        self.rules = ExcludeRules(cfg["exclude"], cfg["allow_lan"])
        self.mark = cfg["fwmark"] if isinstance(self.firewall, firewall.NftFirewall) else 0
        self.direct.mark = self.mark
        p = cfg["proxy"]
        self.proxy = upstream.ProxySettings(p["type"], p["host"], p["port"], p["username"], p["password"])

    def _save_state(self):
        try:
            config.write_atomic(paths.STATE_FILE, json.dumps({"enabled": self.enabled}) + "\n")
        except OSError as exc:
            log.error("cannot write %s: %s", paths.STATE_FILE, exc)

    def _save_pool(self):
        if self.pool.dirty:
            try:
                self.pool.save(paths.FAKEIP_FILE)
            except OSError as exc:
                log.error("cannot write %s: %s", paths.FAKEIP_FILE, exc)

    # ------------------------------------------------------------ reconcile
    async def reconcile(self):
        """Drive firewall, listeners and monitor to the desired state.

        Ordering keeps the machine closed during every transition: listeners
        come up before the rules that feed them; rules are removed before the
        listeners go away.
        """
        cfg = self.cfg
        want_active = self.enabled or cfg["kill_switch"]
        self.error = None
        if want_active:
            listen_error = None
            try:
                if self.tproxy.port != cfg["tcp_port"]:
                    await self.tproxy.start(cfg["tcp_port"], self.mark)
                if self.dns.port != cfg["dns_port"]:
                    await self.dns.start(cfg["dns_port"], self.mark)
            except OSError as exc:
                listen_error = str(exc)
                log.error("%s", listen_error)
            bypass4, bypass6 = self.rules.bypass_sets()
            script = firewall.render(cfg["tcp_port"], cfg["dns_port"], cfg["fwmark"], bypass4, bypass6)
            try:
                self.firewall.apply(script)
                self.active = True
            except firewall.FirewallError as exc:
                self.error = f"cannot apply the firewall: {exc}"
                log.error("%s", self.error)
                self.active = self.firewall.is_active()
            if listen_error and not self.error:
                self.error = listen_error + " (traffic is blocked)"
        else:
            try:
                self.firewall.remove()
                self.active = False
            except firewall.FirewallError as exc:
                self.error = f"cannot remove the firewall: {exc}"
                log.error("%s", self.error)
                self.active = self.firewall.is_active()
            if not self.active:
                await self.tproxy.stop()
                await self.dns.stop()
                self._save_pool()

        if self.enabled and self.active:
            self.monitor.start()
        elif self.monitor.running:
            await self.monitor.stop()

    def state_name(self):
        if self.error:
            return "error"
        if not self.active:
            return "disconnected"
        if not self.enabled:
            return "blocked"
        monitor = self.monitor
        if monitor.state == "connected" and monitor.guarding and monitor.exit_verdict != "ok":
            return "country_blocked" if monitor.exit_verdict == "blocked" else "checking"
        return monitor.state if monitor.state != "idle" else "connecting"

    # ------------------------------------------------------------ commands
    async def cmd_status(self, _request):
        monitor = self.monitor
        return {
            "version": __version__,
            "state": self.state_name(),
            "enabled": self.enabled,
            "kill_switch": self.cfg["kill_switch"],
            "allow_lan": self.cfg["allow_lan"],
            "firewall_active": self.active,
            "proxy": self.proxy_label,
            "proxy_configured": bool(self.proxy.host),
            "since": monitor.since if self.enabled else None,
            "latency_ms": monitor.latency_ms,
            "public_ip": monitor.public_ip,
            **monitor.location(),
            "blocked_countries": list(self.cfg["blocked_countries"]),
            "error": self.error or self.config_error or (
                (monitor.last_error or (monitor.exit_error if monitor.guarding else None))
                if self.enabled else None),
            "stats": dict(self.stats),
            "excluded": len(self.cfg["exclude"]),
        }

    async def cmd_get_config(self, _request):
        return {"config": config.public_view(self.cfg)}

    async def cmd_set_config(self, request):
        patch = request.get("config")
        async with self._lock:
            new = config.validate(config.merge(self.cfg, patch))
            if new == self.cfg:
                return {"config": config.public_view(self.cfg)}
            if self.enabled and not new["proxy"]["host"]:
                raise config.ConfigError("disconnect before removing the proxy")
            proxy_changed = new["proxy"] != self.cfg["proxy"]
            gate_changed = any(new[key] != self.cfg[key] for key in (
                "blocked_countries", "country_check_seconds", "ip_check_url", "geo_url"))
            ports_changed = (new["tcp_port"], new["dns_port"], new["fwmark"]) != (
                self.cfg["tcp_port"], self.cfg["dns_port"], self.cfg["fwmark"])
            config.save(paths.CONFIG_FILE, new)
            self.cfg, self.config_error = new, None
            self._adopt_config()
            if ports_changed and self.active:
                await self.tproxy.stop()
                await self.dns.stop()
            await self.reconcile()
            if proxy_changed:
                self.monitor.restart()
            elif gate_changed:
                self.monitor.policy_changed()
            log.info("configuration updated")
            return {"config": config.public_view(self.cfg)}

    async def cmd_connect(self, _request):
        async with self._lock:
            if not self.proxy.host:
                raise CommandError("Set the proxy address first")
            if self.enabled and self.active and not self.error:
                return {}
            self.enabled = True
            await self.reconcile()
            if self.error:
                message = self.error
                if not self.cfg["kill_switch"]:
                    self.enabled = False
                    await self.reconcile()
                    self.error = message
                self._save_state()
                raise CommandError(message)
            self._save_state()
            log.info("connecting through %s", self.proxy_label)
            return {}

    async def cmd_disconnect(self, _request):
        async with self._lock:
            self.enabled = False
            self._save_state()
            await self.reconcile()
            self.tproxy.close_connections()  # running transfers end with the tunnel
            if self.error:
                raise CommandError(self.error)
            log.info("disconnected%s", " (kill switch is on: traffic stays blocked)"
                     if self.cfg["kill_switch"] else "")
            return {}

    async def cmd_refresh_ip(self, _request):
        self.monitor.refresh_ip()
        return {}

    async def cmd_logs(self, request):
        count = request.get("count", 200)
        count = count if isinstance(count, int) and 0 < count <= 500 else 200
        return {"lines": list(self.ring.lines)[-count:]}

    # ------------------------------------------------------------ lifecycle
    async def run(self):
        self._load()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, self._stop.set)
        async with self._lock:
            await self.reconcile()
        await self.control.start()
        log.info("proxywalld %s ready (state: %s)", __version__, self.state_name())
        _sd_notify("READY=1")
        saver = asyncio.ensure_future(self._housekeeping())
        try:
            await self._stop.wait()
        finally:
            _sd_notify("STOPPING=1")
            saver.cancel()
            await self.control.stop()
            await self.monitor.stop()
            await self.tproxy.stop()
            await self.dns.stop()
            self._save_pool()
            # The firewall is intentionally left in place: while it is applied,
            # a stopped or crashed daemon means "blocked", never "direct".
            if self.active:
                log.info("stopping; the firewall stays applied (traffic is blocked "
                         "until the service runs again)")

    async def _housekeeping(self):
        """Persist the placeholder map and retry listeners that failed to bind."""
        ticks = 0
        while True:
            await asyncio.sleep(5)
            ticks += 1
            try:
                if ticks % 60 == 0:
                    self._save_pool()
                if self.active and not (self.tproxy.listening and self.dns.listening):
                    async with self._lock:
                        await self.reconcile()
            except Exception:
                log.exception("housekeeping failed")


def _sd_notify(message):
    """Minimal sd_notify(3) so the unit can be Type=notify without dependencies."""
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        return
    import socket
    if address.startswith("@"):
        address = "\0" + address[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(address)
            sock.sendall(message.encode())
    except OSError:
        pass


def main(argv=None):
    parser = argparse.ArgumentParser(prog="proxywalld", description="ProxyWall service")
    parser.add_argument("--version", action="version", version=__version__)
    parser.parse_args(argv)

    under_systemd = "JOURNAL_STREAM" in os.environ or "INVOCATION_ID" in os.environ
    logging.basicConfig(
        stream=sys.stderr, level=logging.WARNING,
        format="%(levelname)s: %(message)s" if under_systemd else "%(asctime)s %(levelname)s %(name)s: %(message)s")

    backend = os.environ.get("PROXYWALL_FIREWALL", "nft")
    if backend == "none":
        fw = firewall.NullFirewall()
    else:
        fw = firewall.NftFirewall(paths.BOOT_RULES_FILE)
    for directory, mode in ((paths.STATE_DIR, 0o700), (os.path.dirname(paths.SOCKET_PATH), 0o755)):
        try:
            os.makedirs(directory, mode=mode, exist_ok=True)
        except OSError as exc:
            log.critical("cannot create %s: %s", directory, exc)
            return 1

    async def amain():
        core = Core(fw)
        logging.getLogger("proxywall").addHandler(core.ring)
        logging.getLogger("proxywall").setLevel(logging.INFO)
        if backend == "none":
            log.warning("PROXYWALL_FIREWALL=none: development mode, no traffic is captured or blocked")
        await core.run()

    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
