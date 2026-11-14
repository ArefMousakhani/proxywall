"""Configuration schema, validation and atomic persistence."""

import copy
import ipaddress
import json
import os
import re
from urllib.parse import unquote, urlsplit

from . import links
from .geodata import COUNTRIES
from .rules import normalize_list

NATIVE_TYPES = ("socks5", "http")                       # spoken by ProxyWall itself
ENGINE_TYPES = links.ENGINE_KINDS + ("ssh",)            # need a helper process (Xray, ssh)
PROXY_TYPES = NATIVE_TYPES + ENGINE_TYPES
LOG_LEVELS = ("debug", "info", "warning", "error")
_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$")

DEFAULTS = {
    # type: socks5 | http | ssh | vless | vmess | trojan | shadowsocks. The last four
    # are described by `link` (a share link); host and port are then taken from it.
    "proxy": {"type": "socks5", "host": "", "port": 1080, "username": "", "password": "",
              "link": "", "private_key": ""},
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
    # Asked through the proxy where that IP is (city and coordinates for the map).
    # Empty = never ask; the map then shows the capital of the country.
    "geo_url": "https://ipwho.is/",
    # Country codes (ISO 3166, e.g. "IR"). While the proxy comes out in one of
    # them, or the country cannot be established, nothing is sent through it.
    "blocked_countries": [],
    # How old the last country check may be when a new connection is let
    # through, in seconds. 0 = check again before every single connection.
    "country_check_seconds": 5,
    "tcp_port": 47201,
    "dns_port": 47253,
    # Local port of the helper process for ssh and share-link servers.
    "engine_port": 47210,
    # Path of the Xray program. Empty = look in the usual places.
    "engine_path": "",
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
    if links.is_engine_link(text):
        try:
            server = links.parse(text)
        except links.LinkError as exc:
            raise ConfigError(str(exc)) from None
        return {"type": server["kind"], "host": server["host"], "port": server["port"],
                "username": "", "password": "", "link": text}
    if "://" not in text:
        text = "socks5://" + text
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        raise ConfigError(f"'{url}' is not a valid proxy address") from None
    scheme = {"socks5": "socks5", "socks5h": "socks5", "socks": "socks5",
              "http": "http", "ssh": "ssh"}.get(parts.scheme.lower())
    if scheme is None:
        raise ConfigError(f"unsupported proxy type '{parts.scheme}' "
                          "(use socks5://, http://, ssh://, vless://, vmess://, trojan:// or ss://)")
    if not parts.hostname:
        raise ConfigError(f"'{url}' has no host")
    return {
        "type": scheme,
        "host": parts.hostname,
        "port": port or {"socks5": 1080, "http": 8080, "ssh": 22}[scheme],
        "username": unquote(parts.username or ""),
        "password": unquote(parts.password or ""),
        "link": "",
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
                elif sub in ("password", "link", "private_key") and subval is None:
                    continue  # "keep what is stored": clients never have to read secrets back
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
    for field in ("link", "private_key"):
        if not isinstance(proxy[field], str):
            errors.append(f"proxy {field} must be text")
            proxy[field] = ""
    if proxy["type"] == "link" or proxy["type"] in links.ENGINE_KINDS:
        # A share link describes the whole server: everything else follows from it.
        try:
            server = links.parse(proxy["link"])
            proxy.update(type=server["kind"], host=server["host"], port=server["port"],
                         username="", password="", private_key="", link=proxy["link"].strip())
        except links.LinkError as exc:
            errors.append(str(exc))
    elif proxy["type"] not in PROXY_TYPES:
        errors.append("proxy type must be one of " + ", ".join(PROXY_TYPES))
    else:
        proxy["link"] = ""
        if proxy["type"] != "ssh":
            proxy["private_key"] = ""
    if proxy["type"] == "ssh" and isinstance(proxy["host"], str) and proxy["host"].strip():
        if not proxy["username"]:
            errors.append("an SSH tunnel needs a username")
        key = proxy["private_key"].strip()
        if key and ("PRIVATE KEY-----" not in key or len(key) > 20000):
            errors.append("that does not look like an SSH private key file")
        elif not key and not proxy["password"]:
            errors.append("an SSH tunnel needs a password or a private key")
        proxy["private_key"] = key
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

    for key in ("ip_check_url", "geo_url"):
        url = cfg[key]
        if not isinstance(url, str) or (url and not re.match(r"^https?://[^/\s]+", url.strip())):
            errors.append(f"'{key}' must be an http(s) URL or empty")
        else:
            cfg[key] = url.strip()

    countries = cfg["blocked_countries"]
    if not isinstance(countries, list) or not all(isinstance(code, str) for code in countries):
        errors.append("'blocked_countries' must be a list of country codes")
    else:
        codes = sorted({code.strip().upper() for code in countries})
        unknown = [code for code in codes if code not in COUNTRIES]
        if unknown:
            errors.append("unknown country code: " + ", ".join(unknown))
        elif codes and not cfg["ip_check_url"]:
            errors.append("blocking countries needs 'ip_check_url': without it the country is never known")
        cfg["blocked_countries"] = codes
    age = cfg["country_check_seconds"]
    if isinstance(age, bool) or not isinstance(age, int) or not 0 <= age <= 300:
        errors.append("'country_check_seconds' must be a number between 0 and 300")

    for key in ("tcp_port", "dns_port", "engine_port"):
        value = cfg[key]
        if isinstance(value, bool) or not isinstance(value, int) or not 1024 <= value <= 65535:
            errors.append(f"'{key}' must be a number between 1024 and 65535")
    if len({cfg["tcp_port"], cfg["dns_port"], cfg["engine_port"]}) != 3:
        errors.append("'tcp_port', 'dns_port' and 'engine_port' must differ")
    if not isinstance(cfg["engine_path"], str) or (cfg["engine_path"] and not cfg["engine_path"].startswith("/")):
        errors.append("'engine_path' must be an absolute path or empty")
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
    proxy = out["proxy"]
    proxy["password_set"] = bool(proxy.pop("password"))
    proxy["key_set"] = bool(proxy.pop("private_key"))
    link = proxy.pop("link")
    proxy["link_set"] = bool(link)
    proxy["name"] = ""
    if link:
        try:
            proxy["name"] = links.parse(link)["name"]
        except links.LinkError:
            pass
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
