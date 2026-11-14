"""Control socket: newline-delimited JSON over a Unix socket.

Request  ``{"cmd": "status"}``            Reply ``{"ok": true, ...}``
                                          or    ``{"ok": false, "error": "..."}``

Access is decided from the kernel-verified peer credentials: root and regular
(human) accounts may control ProxyWall, system/service accounts may not.
"""

import asyncio
import json
import logging
import os
import socket
import struct

from .config import ConfigError

log = logging.getLogger("proxywall.control")

MAX_REQUEST = 1024 * 1024


def human_uid_range(path="/etc/login.defs"):
    low, high = 1000, 60000
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    if parts[0] == "UID_MIN":
                        low = int(parts[1])
                    elif parts[0] == "UID_MAX":
                        high = int(parts[1])
    except OSError:
        pass
    return low, high


class ControlServer:
    def __init__(self, core, path):
        self.core = core
        self.path = path
        self._server = None
        self._uid_range = human_uid_range()

    async def start(self):
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass
        self._server = await asyncio.start_unix_server(self._client, path=self.path, limit=MAX_REQUEST)
        os.chmod(self.path, 0o666)  # authorisation happens per connection, below

    async def stop(self):
        if self._server is not None:
            self._server.close()
            self._server = None
            try:
                os.unlink(self.path)
            except OSError:
                pass

    def _allowed(self, writer):
        sock = writer.get_extra_info("socket")
        try:
            creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _, uid, _ = struct.unpack("3i", creds)
        except OSError:
            return False
        low, high = self._uid_range
        return uid in (0, os.geteuid()) or low <= uid <= high

    async def _client(self, reader, writer):
        try:
            if not self._allowed(writer):
                writer.write(b'{"ok": false, "error": "permission denied"}\n')
                await writer.drain()
                return
            while True:
                try:
                    line = await asyncio.wait_for(reader.readline(), 300)
                except ValueError:
                    break  # oversized request
                if not line:
                    break
                reply = await self._dispatch(line)
                writer.write(json.dumps(reply, ensure_ascii=False).encode() + b"\n")
                await writer.drain()
        except (asyncio.TimeoutError, OSError):
            pass
        finally:
            writer.close()

    async def _dispatch(self, line):
        try:
            request = json.loads(line)
            if not isinstance(request, dict) or not isinstance(request.get("cmd"), str):
                raise ValueError
        except ValueError:
            return {"ok": False, "error": "malformed request"}
        handler = getattr(self.core, "cmd_" + request["cmd"], None)
        if handler is None:
            return {"ok": False, "error": f"unknown command '{request['cmd']}'"}
        try:
            result = await handler(request)
            return {"ok": True, **(result or {})}
        except ConfigError as exc:
            return {"ok": False, "error": exc.errors[0], "errors": exc.errors}
        except Exception as exc:
            if not getattr(exc, "expected", False):
                log.exception("command %s failed", request["cmd"])
            return {"ok": False, "error": str(exc) or type(exc).__name__}
