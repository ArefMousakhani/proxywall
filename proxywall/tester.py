"""Try a saved server without using it: how far away is it, and does it reach the outside world.

For every server asked about, the daemon
  1. times a TCP connection to the server itself ("ping"),
  2. goes through the server to the IP service to learn where it comes out, and
  3. fetches `test_url` (Google's empty page by default) through it.

Step 3 is skipped when the exit is in a blocked country, or its country is
unknown while countries are blocked: the promise that nothing is sent from
such an exit also covers test requests.
"""

import asyncio
import logging
import time

from . import config, geo, upstream
from .engine import Engine
from .monitor import http_get, http_latency

log = logging.getLogger("proxywall.tester")

PARALLEL = 4
PING_TIMEOUT = 5.0
STEP_TIMEOUT = 12.0
KEEP_SECONDS = 3600.0


class Tester:
    def __init__(self, core):
        self.core = core
        self.results = {}      # server id -> result dict (see `_blank`)
        self._tasks = {}
        self._slots = None     # helper ports that are free, created with the first test

    @staticmethod
    def _blank(state):
        return {"state": state, "at": time.time(), "ping_ms": None, "reach": None, "reach_ms": None,
                "ip": None, "country": None, "error": None}

    def view(self):
        """Results for the status reply, without the ones that have gone stale."""
        now = time.time()
        return {server_id: dict(result) for server_id, result in self.results.items()
                if result["state"] != "done" or now - result["at"] < KEEP_SECONDS}

    def forget(self, server_id=None):
        """A server changed or went away: what was measured no longer describes it."""
        for key in [server_id] if server_id else list(self.results):
            task = self._tasks.pop(key, None)
            if task is not None:
                task.cancel()
            self.results.pop(key, None)

    def start(self, server_ids=None):
        servers = [server for server in self.core.cfg["servers"]
                   if server_ids is None or server["id"] in server_ids]
        if self._slots is None:
            first = self.core.cfg["engine_port"] + 1
            self._slots = asyncio.Queue()
            for port in range(first, first + min(PARALLEL, config.ENGINE_PORTS - 1)):
                self._slots.put_nowait(port)
        started = 0
        for server in servers:
            if server["id"] in self._tasks:
                continue  # already being tested
            self.results[server["id"]] = self._blank("waiting")
            task = asyncio.ensure_future(self._run(dict(server)))
            self._tasks[server["id"]] = task
            started += 1
        return started

    async def stop(self):
        tasks = list(self._tasks.values())
        self._tasks.clear()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _run(self, server):
        server_id = server["id"]
        result = self.results[server_id]
        port = await self._slots.get()
        try:
            result["state"] = "testing"
            await self._test(server["proxy"], result, port)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # a test must never hurt the daemon
            log.exception("server test crashed")
            result["error"] = str(exc) or type(exc).__name__
        finally:
            self._slots.put_nowait(port)
            if self._tasks.get(server_id) is asyncio.current_task():
                del self._tasks[server_id]
                result["state"], result["at"] = "done", time.time()

    async def _test(self, proxy, result, port):
        core = self.core
        cfg = core.cfg
        host = proxy["host"]
        try:
            addresses = [host] if upstream.ip_version(host) else await core.direct.resolve_host(host)
        except Exception as exc:
            result["error"] = f"cannot find the address of {host}: {exc}"
            return

        # 1. How far away is the server itself?
        started = time.monotonic()
        try:
            sock = await upstream.tcp_connect(addresses[0], proxy["port"], core.mark, timeout=PING_TIMEOUT)
            sock.close()
            result["ping_ms"] = max(1, int((time.monotonic() - started) * 1000))
        except (upstream.ProxyError, OSError, asyncio.TimeoutError) as exc:
            result["error"] = f"the server does not answer ({_short(exc)})"
            return

        helper = None
        try:
            if proxy["type"] in config.ENGINE_TYPES:
                helper = Engine(core, port=port, quiet=True)
                await helper.ensure(proxy)
                if not helper.running:
                    result["error"] = helper.error or "the helper did not start"
                    return
                settings, addresses = helper.settings(proxy["type"]), ["127.0.0.1"]
            else:
                settings = upstream.ProxySettings(proxy["type"], host, proxy["port"],
                                                  proxy["username"], proxy["password"])

            async def dial(target, target_port):
                return await upstream.dial(settings, addresses, target, target_port, core.mark)

            # 2. Where does it come out?
            blocked = set(cfg["blocked_countries"])
            if cfg["ip_check_url"]:
                try:
                    _, body = await asyncio.wait_for(http_get(dial, cfg["ip_check_url"]), STEP_TIMEOUT)
                    reply = geo.parse_reply(body)
                    result["ip"], result["country"] = reply["ip"], reply["country"]
                except (upstream.ProxyError, OSError, asyncio.TimeoutError) as exc:
                    result["reach"], result["error"] = False, f"nothing comes back through it ({_short(exc)})"
                    return
            if blocked and (result["country"] in blocked or not result["country"]):
                name = geo.country_name(result["country"]) or "an unknown country"
                result["error"] = f"comes out in {name}: not tested further"
                return

            # 3. Does it reach the outside world?
            try:
                status, elapsed = await asyncio.wait_for(http_latency(dial, cfg["test_url"]), STEP_TIMEOUT)
                result["reach"] = 200 <= status < 400
                result["reach_ms"] = elapsed
                if not result["reach"]:
                    result["error"] = f"the test page answered with error {status}"
            except (upstream.ProxyError, OSError, asyncio.TimeoutError) as exc:
                result["reach"], result["error"] = False, f"cannot reach the test page ({_short(exc)})"
        finally:
            if helper is not None:
                await helper.stop()


def _short(exc):
    if isinstance(exc, asyncio.TimeoutError):
        return "timed out"
    text = str(exc) or type(exc).__name__
    return text if len(text) <= 90 else text[:87] + "..."
