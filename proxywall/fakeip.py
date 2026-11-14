"""Fake-IP pool.

Every hostname an application asks for is answered with a private placeholder
address from 198.18.0.0/15 (reserved for benchmarking, never routed on the
Internet). When the application then connects to that address the connection
is redirected to ProxyWall, which maps the address back to the hostname and
hands the *name* to the proxy. Local DNS is therefore never consulted for
proxied traffic: no DNS leak and no dependence on a poisoned resolver.
"""

import ipaddress
import json
import time
from collections import OrderedDict

from .config import write_atomic

NETWORK = ipaddress.ip_network("198.18.0.0/15")
_BASE = int(NETWORK.network_address)
_SIZE = NETWORK.num_addresses
_SAVE_LIMIT = 20000


class FakeIPPool:
    def __init__(self, size=_SIZE - 2):
        self._size = max(1, min(size, _SIZE - 2))
        self._by_name = OrderedDict()  # name -> offset, least recently used first
        self._by_offset = {}
        self._next = 1
        self.dirty = False

    def __len__(self):
        return len(self._by_name)

    @staticmethod
    def contains(ip):
        try:
            return 0 < int(ipaddress.IPv4Address(ip)) - _BASE < _SIZE - 1
        except ValueError:
            return False

    @staticmethod
    def _text(offset):
        return str(ipaddress.IPv4Address(_BASE + offset))

    def get(self, name):
        """Return the placeholder address for *name*, allocating one if needed."""
        offset = self._by_name.get(name)
        if offset is not None:
            self._by_name.move_to_end(name)
            return self._text(offset)
        if len(self._by_name) >= self._size:
            _, offset = self._by_name.popitem(last=False)  # recycle the oldest
        else:
            while self._next in self._by_offset:  # skip offsets restored by load()
                self._next += 1
            offset = self._next
            self._next += 1
        self._by_name[name] = offset
        self._by_offset[offset] = name
        self.dirty = True
        return self._text(offset)

    def lookup(self, ip):
        """Return the hostname behind a placeholder address, or None."""
        try:
            offset = int(ipaddress.IPv4Address(ip)) - _BASE
        except ValueError:
            return None
        name = self._by_offset.get(offset)
        if name is not None:
            self._by_name.move_to_end(name)
        return name

    def save(self, path):
        """Persist the newest mappings so a restart is invisible to applications."""
        recent = list(self._by_name.items())[-_SAVE_LIMIT:]
        write_atomic(path, json.dumps({"saved": int(time.time()), "map": recent}))
        self.dirty = False

    def load(self, path):
        try:
            with open(path, encoding="utf-8") as handle:
                entries = json.load(handle)["map"]
            for name, offset in entries:
                if (isinstance(name, str) and isinstance(offset, int)
                        and 0 < offset <= self._size and offset not in self._by_offset
                        and name not in self._by_name):
                    self._by_name[name] = offset
                    self._by_offset[offset] = name
            used = set(self._by_offset)
            while self._next in used:
                self._next += 1
        except FileNotFoundError:
            pass
        except (OSError, ValueError, KeyError, TypeError):
            self._by_name.clear()
            self._by_offset.clear()
            self._next = 1
