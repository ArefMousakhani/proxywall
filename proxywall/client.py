"""Blocking client for the control socket (used by the CLI and the GUI)."""

import json
import socket

from . import paths


class DaemonUnavailable(Exception):
    """The service is not running or the socket cannot be reached."""


class DaemonError(Exception):
    """The service answered with an error."""

    def __init__(self, message, errors=None):
        super().__init__(message)
        self.errors = errors or [message]


class Client:
    def __init__(self, path=None, timeout=15.0):
        self.path = path or paths.SOCKET_PATH
        self.timeout = timeout

    def request(self, cmd, **fields):
        payload = json.dumps({"cmd": cmd, **fields}).encode() + b"\n"
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect(self.path)
                sock.sendall(payload)
                buf = bytearray()
                while not buf.endswith(b"\n"):
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
        except (OSError, socket.timeout) as exc:
            raise DaemonUnavailable(str(exc)) from None
        try:
            reply = json.loads(buf)
        except ValueError:
            raise DaemonUnavailable("the service sent an invalid reply") from None
        if not reply.get("ok"):
            raise DaemonError(reply.get("error", "unknown error"), reply.get("errors"))
        return reply

    def status(self):
        return self.request("status")

    def connect(self):
        return self.request("connect")

    def disconnect(self):
        return self.request("disconnect")

    def get_config(self):
        return self.request("get_config")["config"]

    def set_config(self, patch):
        return self.request("set_config", config=patch)["config"]

    def server_save(self, server_id=None, name=None, proxy=None):
        """Add (no id) or change a saved server. Returns its id."""
        return self.request("server_save", id=server_id, name=name, proxy=proxy)["id"]

    def server_remove(self, server_id):
        return self.request("server_remove", id=server_id)["config"]

    def server_select(self, server_id):
        return self.request("server_select", id=server_id)["config"]

    def server_test(self, server_ids=None):
        return self.request("server_test", ids=server_ids)["started"]

    def logs(self, count=200):
        return self.request("logs", count=count)["lines"]
