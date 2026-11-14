"""Health monitor: is the proxy reachable, how fast, and what is our public IP.

The monitor only *reports*. It never opens a direct route when the proxy is
down: routing is decided by the firewall and stays closed regardless.
"""

import asyncio
import ipaddress
import json
import logging
import re
import ssl
import time
from urllib.parse import urlsplit

from . import upstream
from .resolver import ResolveError

log = logging.getLogger("proxywall.monitor")

INTERVAL_UP = 10.0
INTERVAL_DOWN = 3.0
IP_REFRESH = 900.0


def parse_ip_reply(body):
    """Extract (ip, country) from a Cloudflare trace, JSON or plain-text reply."""
    ip = country = None
    trace_ip = re.search(r"^ip=(\S+)$", body, re.M)
    if trace_ip:
        ip = trace_ip.group(1)
        loc = re.search(r"^loc=(\S+)$", body, re.M)
        country = loc.group(1) if loc else None
    else:
        text = body.strip()
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                ip = data.get("ip") or data.get("query")
                country = data.get("country_code") or data.get("countryCode") or data.get("country")
        except ValueError:
            ip = text
    try:
        ip = str(ipaddress.ip_address(str(ip).strip()))
    except ValueError:
        return None, None
    if not isinstance(country, str) or not re.fullmatch(r"[A-Za-z]{2}", country):
        country = None
    return ip, (country.upper() if country else None)


class Monitor:
    def __init__(self, core):
        self.core = core
        self.state = "idle"  # idle | connecting | connected | unreachable
        self.since = time.time()
        self.latency_ms = None
        self.last_error = None
        self.public_ip = None
        self.country = None
        self._task = None
        self._wake = asyncio.Event()
        self._ip_task = None
        self._ip_at = 0.0

    @property
    def running(self):
        return self._task is not None

    def start(self):
        if self._task is None:
            self._set("connecting")
            self._task = asyncio.ensure_future(self._run())

    async def stop(self):
        tasks = [t for t in (self._task, self._ip_task) if t is not None]
        self._task = self._ip_task = None
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._set("idle")
        self.latency_ms = self.last_error = self.public_ip = self.country = None

    def restart(self):
        """The proxy settings changed: forget what we knew and probe again now."""
        if self._task is not None:
            self._set("connecting")
            self.latency_ms = self.last_error = self.public_ip = self.country = None
            self._ip_at = 0.0
            self._wake.set()

    def refresh_ip(self):
        self._ip_at = 0.0
        self._wake.set()

    def _set(self, state):
        if state != self.state:
            self.state = state
            self.since = time.time()

    async def _run(self):
        core = self.core
        failures = 0
        while True:
            self._wake.clear()
            try:
                proxy = core.proxy
                latency = await upstream.probe(proxy, await core.proxy_ips(), core.mark)
                error = None
            except (upstream.ProxyError, ResolveError, OSError, asyncio.TimeoutError) as exc:
                error = str(exc) or type(exc).__name__
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # the monitor must survive anything
                log.exception("health check crashed")
                error = str(exc)
            if self._wake.is_set():
                continue  # settings changed while probing: result is stale
            if error is None:
                failures = 0
                self.latency_ms, self.last_error = latency, None
                if self.state != "connected":
                    log.info("proxy %s is reachable (%d ms)", core.proxy_label, latency)
                    self._set("connected")
                    self._ip_at = 0.0
                if time.monotonic() - self._ip_at > IP_REFRESH or self._ip_at == 0.0:
                    self._start_ip_lookup()
            else:
                failures += 1
                self.last_error = error
                if self.state == "connecting" or failures >= 2:
                    if self.state != "unreachable":
                        log.warning("proxy %s is unreachable, traffic stays blocked: %s",
                                    core.proxy_label, error)
                        self._set("unreachable")
                    self.latency_ms = self.public_ip = self.country = None
            try:
                await asyncio.wait_for(self._wake.wait(),
                                       INTERVAL_UP if self.state == "connected" else INTERVAL_DOWN)
            except asyncio.TimeoutError:
                pass

    def _start_ip_lookup(self):
        url = self.core.cfg["ip_check_url"]
        if not url or (self._ip_task is not None and not self._ip_task.done()):
            return
        self._ip_at = time.monotonic()
        self._ip_task = asyncio.ensure_future(self._lookup_ip(url))

    async def _lookup_ip(self, url):
        try:
            body = await asyncio.wait_for(fetch(self.core, url), 15)
            ip, country = parse_ip_reply(body)
            if ip and self.state == "connected":
                self.public_ip, self.country = ip, country
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.debug("public IP lookup failed: %s", exc or type(exc).__name__)
            self._ip_at = time.monotonic() - IP_REFRESH + 30  # retry in 30 s


async def fetch(core, url):
    """Minimal HTTP/1.0 GET through the proxy. Returns the body as text."""
    parts = urlsplit(url)
    secure = parts.scheme == "https"
    host = parts.hostname
    port = parts.port or (443 if secure else 80)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    sock, _ = await core.dial_proxy(host, port)
    try:
        context = ssl.create_default_context() if secure else None
        reader, writer = await asyncio.open_connection(
            sock=sock, ssl=context, server_hostname=host if secure else None)
    except BaseException:
        sock.close()
        raise
    try:
        writer.write((f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: proxywall\r\n"
                      "Accept: */*\r\nConnection: close\r\n\r\n").encode("latin-1"))
        await writer.drain()
        raw = await reader.read(65536)
        while len(raw) < 65536:
            chunk = await reader.read(65536)
            if not chunk:
                break
            raw += chunk
    finally:
        writer.transport.abort()
    head, _, body = raw.partition(b"\r\n\r\n")
    status = head.split(b"\r\n", 1)[0].split()
    if len(status) < 2 or status[1] != b"200":
        raise OSError("unexpected HTTP reply")
    return body.decode("utf-8", "replace")
