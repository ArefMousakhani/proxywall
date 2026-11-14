"""Configuration schema, validation and atomic persistence."""

import copy
import ipaddress
import json
import os
import re
from urllib.parse import unquote, urlsplit

from .rules import normalize_list

PROXY_TYPES = ("socks5", "http")
LOG_LEVELS = ("debug", "info", "warning", "error")
_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$")

DEFAULTS = {
    "proxy": {"type": "socks5", "host": "", "port": 1080, "username": "", "password": ""},
    # Block all traffic whenever the proxy is not connected (also after reboot).
    "kill_switch": False,
    # Let private/local networks bypass the proxy.
    "allow_lan": True,
    # Domains / IPs / CIDRs that always go out directly.
    "exclude": [],
    # DNS servers for excluded and local names. Empty = use the system's.
    "direct_dns": [],
    # Resolver reached *through the proxy* for record types other than A/AAAA.
    "remote_dns": "1.1.1.1",
    # Fetched through the proxy to show the public IP. Empty = never fetch.
    "ip_check_url": "https://www.cloudflare.com/cdn-cgi/trace",
    "tcp_port": 47201,
    "dns_port": 47253,
    "fwmark": 0x5057,
    "log_level": "info",
}


class ConfigError(ValueError):
    def __init__(self, errors):
        self.errors = [errors] if isinstance(errors, str) else list(errors)
        super().__init__("; ".join(self.errors))


def defaults():
    return copy.deepcopy(DEFAULTS)


def parse_proxy_url(url):
    """``socks5://user:pass@host:1080`` -> proxy dict. Raises ConfigError."""
    text = url.strip()
    if "://" not in text:
        text = "socks5://" + text
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        raise ConfigError(f"'{url}' is not a valid proxy address") from None
    scheme = {"socks5": "socks5", "socks5h": "socks5", "socks": "socks5",
              "http": "http"}.get(parts.scheme.lower())
    if scheme is None:
        raise ConfigError(f"unsupported proxy type '{parts.scheme}' (use socks5:// or http://)")
    if not parts.hostname:
        raise ConfigError(f"'{url}' has no host")
    return {
        "type": scheme,
        "host": parts.hostname,
        "port": port or (1080 if scheme == "socks5" else 8080),
        "username": unquote(parts.username or ""),
        "password": unquote(parts.password or ""),
    }


def merge(base, patch):
    """Return *base* updated with *patch*. Unknown keys raise ConfigError.

    ``proxy.password = None`` means "keep the stored password", so clients never
    need to read the secret back in order to change something else.
    """
    if not isinstance(patch, dict):
        raise ConfigError("configuration must be an object")
    out = copy.deepcopy(base)
    errors = []
    for key, value in patch.items():
        if key not in DEFAULTS:
            errors.append(f"unknown setting '{key}'")
        elif key == "proxy":
            if not isinstance(value, dict):
                errors.append("'proxy' must be an object")
                continue
            for sub, subval in value.items():
                if sub not in DEFAULTS["proxy"]:
                    errors.append(f"unknown setting 'proxy.{sub}'")
                elif sub == "password" and subval is None:
                    continue
                else:
                    out["proxy"][sub] = subval
        else:
            out[key] = value
    if errors:
        raise ConfigError(errors)
    return out


def _is_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def validate(raw):
    """Return a normalised copy of *raw* or raise ConfigError listing every problem."""
    cfg = merge(defaults(), raw)
    errors = []

    proxy = cfg["proxy"]
    if proxy["type"] not in PROXY_TYPES:
        errors.append("proxy type must be 'socks5' or 'http'")
    host = proxy["host"]
    if not isinstance(host, str):
        errors.append("proxy host must be text")
    else:
        host = host.strip().strip("[]").lower().rstrip(".")
        if host and not _is_ip(host) and not _HOST_RE.match(host):
            errors.append(f"'{proxy['host']}' is not a valid proxy host")
        proxy["host"] = host
    port = proxy["port"]
    if isinstance(port, str) and port.strip().isdigit():
        port = int(port)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        errors.append("proxy port must be a number between 1 and 65535")
    proxy["port"] = port
    for field in ("username", "password"):
        value = proxy[field]
        if not isinstance(value, str) or len(value.encode()) > 255:
            errors.append(f"proxy {field} must be text of at most 255 bytes")
    if isinstance(proxy["username"], str) and isinstance(proxy["password"], str):
        if proxy["password"] and not proxy["username"]:
            errors.append("a proxy password needs a username")
        if ":" in proxy["username"] and proxy["type"] == "http":
            errors.append("an HTTP proxy username cannot contain ':'")

    for flag in ("kill_switch", "allow_lan"):
        if not isinstance(cfg[flag], bool):
            errors.append(f"'{flag}' must be true or false")

    if not isinstance(cfg["exclude"], list):
        errors.append("'exclude' must be a list")
    else:
        cfg["exclude"], bad = normalize_list(cfg["exclude"])
        errors.extend(bad)

    if not isinstance(cfg["direct_dns"], list) or not all(
        isinstance(s, str) and _is_ip(s.strip()) for s in cfg["direct_dns"]
    ):
        errors.append("'direct_dns' must be a list of IP addresses")
    else:
        cfg["direct_dns"] = [s.strip() for s in cfg["direct_dns"]]
    if not isinstance(cfg["remote_dns"], str) or not _is_ip(cfg["remote_dns"].strip()):
        errors.append("'remote_dns' must be an IP address")
    else:
        cfg["remote_dns"] = cfg["remote_dns"].strip()

    url = cfg["ip_check_url"]
    if not isinstance(url, str) or (url and not re.match(r"^https?://[^/\s]+", url.strip())):
        errors.append("'ip_check_url' must be an http(s) URL or empty")
    else:
        cfg["ip_check_url"] = url.strip()

    for key in ("tcp_port", "dns_port"):
        value = cfg[key]
        if isinstance(value, bool) or not isinstance(value, int) or not 1024 <= value <= 65535:
            errors.append(f"'{key}' must be a number between 1024 and 65535")
    if cfg["tcp_port"] == cfg["dns_port"]:
        errors.append("'tcp_port' and 'dns_port' must differ")
    mark = cfg["fwmark"]
    if isinstance(mark, bool) or not isinstance(mark, int) or not 1 <= mark <= 0xFFFFFFFF:
        errors.append("'fwmark' must be a number between 1 and 4294967295")
    if cfg["log_level"] not in LOG_LEVELS:
        errors.append("'log_level' must be one of " + ", ".join(LOG_LEVELS))

    if errors:
        raise ConfigError(errors)
    return cfg


def public_view(cfg):
    """Configuration as shown to clients: the password never leaves the daemon."""
    out = copy.deepcopy(cfg)
    out["proxy"]["password_set"] = bool(out["proxy"].pop("password"))
    return out


def proxy_label(cfg):
    proxy = cfg["proxy"]
    if not proxy["host"]:
        return ""
    host = f"[{proxy['host']}]" if ":" in proxy["host"] else proxy["host"]
    return f"{proxy['type']}://{host}:{proxy['port']}"


def write_atomic(path, text, mode=0o600):
    tmp = f"{path}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load(path):
    """Load and validate. A missing file yields defaults; a broken one raises."""
    try:
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
    except FileNotFoundError:
        return defaults()
    except (OSError, ValueError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from None
    return validate(raw)


def save(path, cfg):
    write_atomic(path, json.dumps(cfg, indent=2, ensure_ascii=False) + "\n")
