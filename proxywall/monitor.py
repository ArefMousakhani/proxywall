"""Health monitor: is the proxy reachable, how fast, where does it come out.

The monitor never opens a direct route when the proxy is down: routing is
decided by the firewall and stays closed regardless. It can only make things
stricter: with a list of blocked countries it is also the gate every proxied
connection has to pass (see `Monitor.permit`).
"""

import asyncio
import logging
import ssl
import time
from urllib.parse import urlsplit

from . import geo, upstream
from .resolver import ResolveError

log = logging.getLogger("proxywall.monitor")

INTERVAL_UP = 10.0
INTERVAL_DOWN = 3.0
IP_REFRESH = 900.0
CHECK_TIMEOUT = 10.0      # the public IP lookup
GEO_TIMEOUT = 8.0         # the city lookup
GEO_RETRY = 300.0         # ask again for the same address after a failed city lookup
VERDICT_RETRY = 3.0       # while traffic is held back, check again at most this often


def parse_ip_reply(body):
    """Extract (ip, country) from a Cloudflare trace, JSON or plain-text reply."""
    reply = geo.parse_reply(body)
    return reply["ip"], reply["country"]


class Monitor:
    def __init__(self, core):
        self.core = core
        self.state = "idle"  # idle | connecting | connected | unreachable
        self.since = time.time()
        self.latency_ms = None
        self.last_error = None
        self.public_ip = None
        self.country = None
        # Country gate. "ok" means: the last check found the exit outside every
        # blocked country. Anything else holds proxied traffic back.
        self.exit_verdict = "unknown"   # unknown | ok | blocked
        self.exit_error = None          # why the verdict is not "ok", for people
        self._verified_at = 0.0         # when the check behind an "ok" started
        self._checked_at = 0.0          # when the last check finished
        self._check = None              # (task, start time) of the running lookup
        self._geo = None                # last geo-IP answer; kept while the public IP stays the same
        self._geo_tried = (None, 0.0)   # (address, time) of the last city lookup
        self._task = None
        self._wake = asyncio.Event()
        self._ip_at = 0.0

    @property
    def running(self):
        return self._task is not None

    @property
    def guarding(self):
        return bool(self.core.cfg["blocked_countries"])

    def start(self):
        if self._task is None:
            self._set("connecting")
            self._task = asyncio.ensure_future(self._run())

    async def stop(self):
        tasks = [t for t in (self._task, self._check[0] if self._check else None) if t is not None]
        self._task = self._check = None
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._set("idle")
        self._forget()

    def restart(self):
        """The proxy settings changed: forget what we knew and probe again now."""
        if self._task is not None:
            self._set("connecting")
            self._forget()
            self._wake.set()

    def refresh_ip(self):
        self._ip_at = 0.0
        self._wake.set()

    def _forget(self):
        if self._check is not None:  # an answer about the old situation must not land in the new one
            self._check[0].cancel()
            self._check = None
        self.latency_ms = self.last_error = self.public_ip = self.country = None
        self.exit_verdict, self.exit_error = "unknown", None
        self._verified_at = self._checked_at = self._ip_at = 0.0

    def location(self):
        """Country, city and coordinates of the public IP, for the status reply."""
        found = self._geo if self._geo and self._geo["ip"] == self.public_ip else None
        return geo.describe(self.country, found)

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
                due = self._ip_at == 0.0 or time.monotonic() - self._ip_at > IP_REFRESH
                if due or (self.guarding and self.exit_verdict != "ok"):
                    self._start_check()
            else:
                failures += 1
                self.last_error = error
                if self.state == "connecting" or failures >= 2:
                    if self.state != "unreachable":
                        log.warning("proxy %s is unreachable, traffic stays blocked: %s",
                                    core.proxy_label, error)
                        self._set("unreachable")
                    self._forget()
                    self.last_error = error
            try:
                await asyncio.wait_for(self._wake.wait(),
                                       INTERVAL_UP if self.state == "connected" else INTERVAL_DOWN)
            except asyncio.TimeoutError:
                pass

    # ------------------------------------------------------------ country gate
    async def permit(self):
        """May one more connection be handed to the proxy right now?

        Always yes when no country is blocked. Otherwise only when a check that
        is at most `country_check_seconds` old found the exit outside every
        blocked country; a connection that arrives later waits for a new check
        and is refused if that check fails for any reason.
        """
        if not self.guarding:
            return True
        if self.state != "connected":
            return False
        arrived = time.monotonic()
        max_age = self.core.cfg["country_check_seconds"]
        if self.exit_verdict == "ok":
            age = arrived - self._verified_at
            if max_age and age <= max_age:
                if age > max_age / 2:
                    self._start_check()  # traffic is flowing: renew before it runs out
                return True
        elif arrived - self._checked_at < VERDICT_RETRY:
            return False  # just checked; programs retry faster than the answer can change
        while True:
            check = self._start_check()
            if check is None:
                return False
            task, started = check
            await asyncio.wait({task})
            if started >= arrived - max_age:
                break
        return self.exit_verdict == "ok" and self._verified_at >= arrived - max_age

    def policy_changed(self):
        """The list of blocked countries changed: apply it to what is known now."""
        self._verified_at = 0.0
        if self.state != "connected":
            return
        if not self.guarding:
            self.exit_verdict, self.exit_error = "unknown", None
            return
        cfg = self.core.cfg
        seen = {self.country}
        if cfg["geo_url"] and self._geo and self._geo["ip"] == self.public_ip:
            seen.add(self._geo["country"])
        hit = sorted(seen & set(cfg["blocked_countries"]))
        if hit:
            self._block(hit[0])  # at once, on what is known
        else:
            self.exit_verdict, self.exit_error = "unknown", None
        # Then ask again from nothing: the services may have changed too, and
        # only a new answer can open the gate (or lift a block).
        self._geo, self._geo_tried = None, (None, 0.0)
        if self._check is not None:
            self._check[0].cancel()
            self._check = None
        self._start_check()

    def _block(self, country):
        name = geo.country_name(country) or country
        self.exit_error = f"The proxy comes out in {name} ({self.public_ip}), a blocked country"
        if self.exit_verdict != "blocked":
            log.warning("%s: nothing is sent through the proxy", self.exit_error)
            self.exit_verdict = "blocked"
            self.core.tproxy.close_connections(proxied_only=True)

    def _hold(self, reason):
        """The exit could not be verified: with blocked countries that means closed."""
        if self.guarding and (self.exit_verdict == "ok" or self.exit_error is None):
            log.warning("%s: nothing is sent through the proxy until a check succeeds", reason)
        self.exit_verdict, self.exit_error = "unknown", reason

    def _start_check(self):
        """Start the public IP lookup unless one is running. Returns (task, start time)."""
        if self._check is not None and not self._check[0].done():
            return self._check
        url = self.core.cfg["ip_check_url"]
        if not url:
            return None
        started = self._ip_at = time.monotonic()
        self._check = (asyncio.ensure_future(self._check_exit(url, started)), started)
        return self._check

    async def _check_exit(self, url, started):
        try:
            await self._check_exit_unguarded(url, started)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # anything unexpected counts as "not verified"
            log.exception("exit check crashed")
            self._hold(f"The exit country could not be checked: {exc}")
        finally:
            self._checked_at = time.monotonic()

    async def _check_exit_unguarded(self, url, started):
        cfg = self.core.cfg
        try:
            reply = geo.parse_reply(await asyncio.wait_for(fetch(self.core, url), CHECK_TIMEOUT))
        except Exception as exc:
            log.debug("public IP lookup failed: %s", exc or type(exc).__name__)
            self._ip_at = time.monotonic() - IP_REFRESH + 30  # retry in 30 s
            self._hold(f"The exit country could not be checked: {str(exc) or 'no answer in time'}")
            return
        ip = reply["ip"]
        if self.state != "connected":
            return
        if not ip:
            self._hold("The exit country could not be checked: the IP service gave no usable answer")
            return
        blocked = set(cfg["blocked_countries"])
        self.public_ip, self.country = ip, reply["country"]
        if reply["country"] in blocked:
            self._block(reply["country"])  # settled: no need to ask anybody else
            return
        if reply["latitude"] is not None:
            self._geo = dict(reply)
        elif not (self._geo and self._geo["ip"] == ip) and cfg["geo_url"]:
            tried_ip, tried_at = self._geo_tried
            if tried_ip != ip or time.monotonic() - tried_at > GEO_RETRY:
                self._geo_tried = (ip, time.monotonic())
                found = await self._lookup_geo(cfg["geo_url"])
                if self.state != "connected" or self.public_ip != ip:
                    return
                if found["ip"]:
                    self._geo = dict(found, ip=ip)
        second = self._geo["country"] if self._geo and self._geo["ip"] == ip else None
        self.country = self.country or second
        if not blocked:
            self.exit_verdict, self.exit_error = "unknown", None
        elif second in blocked:  # the two services disagree: the stricter answer wins
            self.country = second
            self._block(second)
        elif not self.country:
            self._hold(f"The exit country could not be checked: nobody knows where {ip} is")
        else:
            if self.exit_verdict != "ok":
                log.info("the proxy comes out in %s (%s): allowed",
                         geo.country_name(self.country) or self.country, ip)
            self.exit_verdict, self.exit_error = "ok", None
            self._verified_at = started

    async def _lookup_geo(self, url):
        """The location is decoration: failing to get it is never an error."""
        try:
            return geo.parse_reply(await asyncio.wait_for(fetch(self.core, url), GEO_TIMEOUT))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.debug("location lookup failed: %s", exc or type(exc).__name__)
            return geo.parse_reply("")


_tls_context = None


def _tls():
    global _tls_context
    if _tls_context is None:
        _tls_context = ssl.create_default_context()
    return _tls_context


async def fetch(core, url):
    """Minimal HTTP/1.0 GET through the proxy. Returns the body as text."""
    parts = urlsplit(url)
    secure = parts.scheme == "https"
    host = parts.hostname
    port = parts.port or (443 if secure else 80)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    sock, _ = await core.dial_proxy(host, port)
    try:
        reader, writer = await asyncio.open_connection(
            sock=sock, ssl=_tls() if secure else None, server_hostname=host if secure else None)
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
