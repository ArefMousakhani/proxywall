"""The nftables rule set: traffic capture and the fail-closed kill switch.

One table, ``inet proxywall``, holds everything, so applying and removing the
firewall are single atomic transactions that never touch anybody else's rules.

Design: the rules do not know whether the proxy is healthy. They only say
"new TCP goes to the daemon, the daemon's own (marked) sockets may leave, the
rest is rejected". If the proxy dies, or the daemon itself crashes, traffic
has nowhere to go. There is no code path that falls back to a direct route.
"""

import logging
import os
import shutil
import subprocess

from .config import write_atomic

log = logging.getLogger("proxywall.firewall")

TABLE = "proxywall"
_PRELUDE = f"table inet {TABLE}\ndelete table inet {TABLE}\n"


class FirewallError(Exception):
    pass


def render(tcp_port, dns_port, mark, bypass4=(), bypass6=(), engine_port=0):
    """Return the complete rule set as nft script text (an atomic replace)."""
    # The helper process (Xray, ssh) listens on loopback for the daemon alone:
    # a program that talked to it directly would skip exclusions and the country gate.
    engine_guard = (f"        tcp dport {engine_port} meta mark != {mark:#x} reject with tcp reset\n"
                    if engine_port else "")

    def address_set(name, kind, elements):
        body = f"        type {kind}\n        flags interval\n        auto-merge\n"
        if elements:
            body += "        elements = { " + ", ".join(elements) + " }\n"
        return f"    set {name} {{\n{body}    }}\n"

    capture = f"""\
        fib daddr type local accept
        meta l4proto {{ tcp, udp }} th dport 53 redirect to :{dns_port}
        ip daddr @bypass4 accept
        ip6 daddr @bypass6 accept
        meta l4proto tcp redirect to :{tcp_port}"""

    return f"""{_PRELUDE}
table inet {TABLE} {{
{address_set("bypass4", "ipv4_addr", bypass4)}
{address_set("bypass6", "ipv6_addr", bypass6)}
    # Applications on this machine: DNS and new TCP connections go to the daemon.
    chain capture_local {{
        type nat hook output priority dstnat; policy accept;
        meta mark {mark:#x} accept
{capture}
    }}

    # Containers, virtual machines and hotspot clients routed through this machine.
    chain capture_forwarded {{
        type nat hook prerouting priority dstnat; policy accept;
{capture}
    }}

    # The daemon's ports are reachable only by redirected connections.
    chain guard_ports {{
        type filter hook input priority filter; policy accept;
{engine_guard}        iifname "lo" accept
        meta l4proto {{ tcp, udp }} th dport {{ {tcp_port}, {dns_port} }} ct status dnat accept
        meta l4proto {{ tcp, udp }} th dport {{ {tcp_port}, {dns_port} }} drop
    }}

    # Kill switch: nothing leaves unless it is the daemon, local, or excluded.
    chain killswitch_local {{
        type filter hook output priority filter; policy accept;
        meta mark {mark:#x} accept
        oifname "lo" accept
        fib daddr type local accept
        ip daddr @bypass4 accept
        ip6 daddr @bypass6 accept
        icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, mld-listener-report, mld2-listener-report }} accept
        udp sport 68 udp dport 67 accept
        udp sport 546 udp dport 547 accept
        meta l4proto tcp reject with tcp reset
        reject
    }}

    chain killswitch_forwarded {{
        type filter hook forward priority filter; policy accept;
        ip daddr @bypass4 accept
        ip6 daddr @bypass6 accept
        meta l4proto tcp reject with tcp reset
        reject
    }}
}}
"""


class NftFirewall:
    """Applies the rule set with the ``nft`` command line tool."""

    def __init__(self, boot_file=None):
        self.boot_file = boot_file
        self.nft = shutil.which("nft") or "/usr/sbin/nft"

    def _run(self, script):
        try:
            proc = subprocess.run([self.nft, "-f", "-"], input=script, text=True,
                                  capture_output=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise FirewallError(f"cannot run nft: {exc}") from None
        if proc.returncode != 0:
            raise FirewallError(proc.stderr.strip() or f"nft exited with {proc.returncode}")

    def apply(self, script):
        """Load the rules and keep a copy that systemd restores early at boot."""
        self._run(script)
        if self.boot_file:
            try:
                write_atomic(self.boot_file, script)
            except OSError as exc:
                log.error("cannot write %s: %s", self.boot_file, exc)

    def remove(self):
        if self.boot_file:
            try:
                os.unlink(self.boot_file)
            except FileNotFoundError:
                pass
            except OSError as exc:
                log.error("cannot remove %s: %s", self.boot_file, exc)
        self._run(_PRELUDE)

    def is_active(self):
        try:
            return subprocess.run([self.nft, "list", "table", "inet", TABLE],
                                  capture_output=True, timeout=20).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False


class NullFirewall:
    """Development backend (PROXYWALL_FIREWALL=none): records, changes nothing."""

    def __init__(self):
        self.script = None

    def apply(self, script):
        self.script = script

    def remove(self):
        self.script = None

    def is_active(self):
        return self.script is not None
