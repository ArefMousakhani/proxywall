"""Exclusion rules: which destinations bypass the proxy and go out directly.

An entry is one of:

* a domain          ``example.com``  - the domain itself and every subdomain
* a wildcard domain ``*.ir``         - same meaning, written the familiar way
* an IP address     ``192.0.2.10``
* a network (CIDR)  ``10.20.0.0/16`` or ``2001:db8::/32``
"""

import ipaddress
import re
from urllib.parse import urlsplit

_LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")

# Destinations treated as "the local network" when *Allow LAN* is on.
LAN_NETS4 = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
)
LAN_NETS6 = (
    "fc00::/7",
    "fe80::/10",
    "ff01::/16",
    "ff02::/16",
)

# Names that only make sense on the local network. With *Allow LAN* on they are
# answered by the system's own DNS servers instead of being sent to the proxy.
LOCAL_SUFFIXES = ("local", "lan", "home", "home.arpa", "internal", "intranet", "localdomain")
_PRIVATE_PTR_RE = re.compile(
    r"(^|\.)(10|168\.192|254\.169|(1[6-9]|2[0-9]|3[01])\.172)\.in-addr\.arpa$"
)


def normalize_domain(text):
    """Return the canonical ASCII form of a domain name or raise ValueError."""
    name = text.strip().lower().rstrip(".")
    if not name:
        raise ValueError("empty domain")
    try:
        name = ".".join(
            label if label.isascii() else label.encode("idna").decode("ascii")
            for label in name.split(".")
        )
    except UnicodeError:
        raise ValueError(f"'{text}' is not a valid domain name") from None
    if len(name) > 253 or not all(_LABEL_RE.match(label) for label in name.split(".")):
        raise ValueError(f"'{text}' is not a valid domain name")
    return name


# Registries that hand out names one level down (example.co.uk, example.ac.ir).
_SECOND_LEVEL = frozenset(("ac", "co", "com", "edu", "go", "gov", "id", "mil", "ne", "net", "nom", "or", "org", "sch"))


def base_domain(name):
    """The domain a host name belongs to: ``mail.google.com`` -> ``google.com``.

    A rule of thumb, not the public suffix list: two labels, or three under a
    two-letter country code with a generic second level (``bbc.co.uk``). Used
    to group open connections and to offer one exclusion for a whole site.
    """
    labels = name.lower().rstrip(".").split(".")
    keep = 3 if len(labels[-1]) == 2 and len(labels) > 2 and labels[-2] in _SECOND_LEVEL else 2
    return ".".join(labels[-keep:])


def is_hostname(name):
    """True if *name* (already lower-case) can be handed to a proxy as a host."""
    return 0 < len(name) <= 253 and all(_LABEL_RE.match(label) for label in name.split("."))


def normalize_entry(text):
    """Parse one exclusion entry.

    Returns ``("net", ip_network, canonical_text)`` or
    ``("domain", suffix, canonical_text)``. Raises ValueError on bad input.
    """
    raw = text.split("#", 1)[0].strip()
    if not raw:
        raise ValueError("empty entry")
    candidate = raw.strip("[]")
    try:
        net = ipaddress.ip_network(candidate, strict=False)
    except ValueError:
        net = None
    value = raw.lower()
    if net is None:
        if "://" in value:  # a pasted URL: keep only the host
            value = urlsplit(value).hostname or ""
        value = value.split("/", 1)[0]
        if value.count(":") == 1:  # host:port
            value = value.split(":", 1)[0]
        try:
            net = ipaddress.ip_network(value.strip("[]"), strict=False)
        except ValueError:
            net = None
    if net is not None:
        if net.prefixlen == 0:
            raise ValueError(f"'{raw}' would exclude every address")
        canonical = str(net.network_address) if net.num_addresses == 1 else str(net)
        return "net", net, canonical

    wildcard = False
    while value.startswith(("*.", ".")):
        wildcard = True
        value = value[2:] if value.startswith("*.") else value[1:]
    if value in ("", "*"):
        raise ValueError(f"'{raw}' would exclude every domain")
    domain = normalize_domain(value)
    return "domain", domain, ("*." + domain if wildcard else domain)


def normalize_list(entries):
    """Normalise a list of entries. Returns (canonical_list, error_messages)."""
    seen, out, errors = set(), [], []
    for entry in entries:
        if not isinstance(entry, str):
            errors.append(f"exclusion entries must be text, got {entry!r}")
            continue
        if not entry.split("#", 1)[0].strip():
            continue
        try:
            kind, value, canonical = normalize_entry(entry)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        key = (kind, str(value))
        if key not in seen:
            seen.add(key)
            out.append(canonical)
    return out, errors


def is_local_name(name):
    """Single-label names, well-known private suffixes and private reverse zones."""
    if "." not in name:
        return True
    if _PRIVATE_PTR_RE.search(name):
        return True
    return any(name == s or name.endswith("." + s) for s in LOCAL_SUFFIXES)


class ExcludeRules:
    """Compiled, immutable view of the exclusion list."""

    def __init__(self, entries=(), allow_lan=True):
        self.allow_lan = bool(allow_lan)
        self.domains = set()
        nets4, nets6 = [], []
        for entry in entries:
            kind, value, _ = normalize_entry(entry)
            if kind == "domain":
                self.domains.add(value)
            elif value.version == 4:
                nets4.append(value)
            else:
                nets6.append(value)
        if self.allow_lan:
            nets4 += [ipaddress.ip_network(n) for n in LAN_NETS4]
            nets6 += [ipaddress.ip_network(n) for n in LAN_NETS6]
        self.nets4 = list(ipaddress.collapse_addresses(nets4))
        self.nets6 = list(ipaddress.collapse_addresses(nets6))

    def match_domain(self, name):
        """True if *name* or one of its parent domains is excluded."""
        if not self.domains:
            return False
        name = name.lower().rstrip(".")
        while name:
            if name in self.domains:
                return True
            _, _, name = name.partition(".")
        return False

    def match_ip(self, ip):
        """True if the address (text or ipaddress object) goes out directly."""
        try:
            addr = ipaddress.ip_address(ip) if isinstance(ip, str) else ip
        except ValueError:
            return False
        if addr.version == 6 and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        nets = self.nets4 if addr.version == 4 else self.nets6
        return any(addr in net for net in nets)

    def bypass_sets(self):
        """Elements for the nftables bypass sets: (ipv4_list, ipv6_list)."""
        return [str(n) for n in self.nets4], [str(n) for n in self.nets6]
