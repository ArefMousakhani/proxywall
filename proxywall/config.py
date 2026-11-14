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
MAX_SERVERS = 200
ENGINE_PORTS = 10    # engine_port .. engine_port+9: one for the tunnel in use, the rest for tests
LOG_LEVELS = ("debug", "info", "warning", "error")
_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$")

DEFAULTS = {
    # type: socks5 | http | ssh | vless | vmess | trojan | shadowsocks. The last four
    # are described by `link` (a share link); host and port are then taken from it.
    "proxy": {"type": "socks5", "host": "", "port": 1080, "username": "", "password": "",
              "link": "", "private_key": ""},
    # Saved servers: [{"id", "name", "proxy": {...as above...}}]. `proxy` is always a
    # copy of the one named by `active_server` (empty = none chosen).
    "servers": [],
    "active_server": "",
    # Fetched through a server to see whether it reaches the outside world.
    "test_url": "https://www.google.com/generate_204",
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


def merge(base, patch, known=None):
    """Return *base* updated with *patch*. Unknown keys raise ConfigError.

    ``proxy.password = None`` means "keep the stored password", so clients never
    need to read the secret back in order to change something else.
    """
    if not isinstance(patch, dict):
        raise ConfigError("configuration must be an object")
    out = copy.deepcopy(base)
    errors = []
    for key, value in patch.items():
        if key not in (known or DEFAULTS):
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
    if "proxy" in patch and known is None and "servers" not in patch and isinstance(out.get("servers"), list):
        # Setting `proxy` directly (`proxywall set-proxy`, older clients) edits the
        # server in use, or becomes the first one.
        server = next((item for item in out["servers"]
                       if isinstance(item, dict) and item.get("id") == out.get("active_server")), None)
        if server is not None:
            server["proxy"] = copy.deepcopy(out["proxy"])
        elif not out.get("active_server") and (out["proxy"].get("host") or out["proxy"].get("link")):
            new_id = _next_server_id(out["servers"])
            out["servers"].append({"id": new_id, "name": "", "proxy": copy.deepcopy(out["proxy"])})
            out["active_server"] = new_id
    return out


def _is_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _normalise_proxy(proxy, errors):
    """Check and tidy one `proxy` section in place, appending problems to *errors*."""
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


def _next_server_id(servers):
    taken = {server.get("id") for server in servers if isinstance(server, dict)}
    number = 1
    while f"s{number}" in taken:
        number += 1
    return f"s{number}"


def server_name(server):
    """What to call a saved server: its own name, the name in its link, or its address."""
    if server.get("name"):
        return server["name"]
    proxy = server["proxy"]
    if proxy.get("link"):
        try:
            name = links.parse(proxy["link"])["name"]
            if name:
                return name
        except links.LinkError:
            pass
    return proxy.get("host") or "New server"


def _normalise_servers(cfg, errors, proxy_before):
    """`servers` is the list of saved servers; `proxy` always mirrors the one in use."""
    servers = cfg["servers"]
    if not isinstance(servers, list) or len(servers) > MAX_SERVERS:
        errors.append(f"'servers' must be a list of at most {MAX_SERVERS} servers")
        cfg["servers"] = []
        return
    seen = set()
    for position, server in enumerate(servers, 1):
        if (not isinstance(server, dict) or set(server) != {"id", "name", "proxy"}
                or not isinstance(server["proxy"], dict) or set(server["proxy"]) != set(DEFAULTS["proxy"])):
            errors.append(f"server {position} is malformed")
            continue
        if not isinstance(server["id"], str) or not re.fullmatch(r"[a-z0-9]{1,16}", server["id"]) \
                or server["id"] in seen:
            errors.append(f"server {position} has a bad or repeated id")
            continue
        seen.add(server["id"])
        if not isinstance(server["name"], str):
            errors.append(f"server {position}: the name must be text")
            continue
        server["name"] = " ".join("".join(ch for ch in server["name"] if ch.isprintable()).split())[:60]
        # The server in use was already checked as `proxy`: do not say everything twice.
        mirrored = server["id"] == cfg["active_server"] and server["proxy"] == proxy_before
        problems = []
        _normalise_proxy(server["proxy"], problems)
        if not mirrored:
            errors.extend(problems)
        if not problems and not server["proxy"]["host"]:
            errors.append("the server has no address")
    active = cfg["active_server"]
    if not isinstance(active, str):
        errors.append("'active_server' must be text")
        return
    if errors:
        return
    by_id = {server["id"]: server for server in servers}
    if active and active not in by_id:
        errors.append("'active_server' is not one of the saved servers")
    elif active:
        cfg["proxy"] = copy.deepcopy(by_id[active]["proxy"])
    elif cfg["proxy"]["host"] and not servers:
        # A configuration from before there was a list: its proxy becomes the first entry.
        servers.append({"id": "s1", "name": "", "proxy": copy.deepcopy(cfg["proxy"])})
        cfg["active_server"] = "s1"
    elif cfg["proxy"]["host"]:
        errors.append("no server is selected")


def save_server(cfg, server_id=None, name=None, proxy=None):
    """Add a server (no id) or change one. Returns (configuration patch source, id).

    The result still has to go through `validate`. Secrets set to None in
    *proxy* are kept as stored.
    """
    out = copy.deepcopy(cfg)
    if server_id is None:
        server = {"id": _next_server_id(out["servers"]), "name": "", "proxy": copy.deepcopy(DEFAULTS["proxy"])}
        out["servers"].append(server)
    else:
        server = next((item for item in out["servers"] if item["id"] == server_id), None)
        if server is None:
            raise ConfigError("that server no longer exists")
    if name is not None:
        server["name"] = name
    if proxy is not None:
        if not isinstance(proxy, dict):
            raise ConfigError("'proxy' must be an object")
        server["proxy"] = merge({"proxy": server["proxy"]}, {"proxy": proxy}, known={"proxy"})["proxy"]
    if not out["active_server"]:
        out["active_server"] = server["id"]       # the first server is the one in use
    if out["active_server"] == server["id"]:
        out["proxy"] = copy.deepcopy(server["proxy"])
    return out, server["id"]


def remove_server(cfg, server_id):
    out = copy.deepcopy(cfg)
    if not any(server["id"] == server_id for server in out["servers"]):
        raise ConfigError("that server no longer exists")
    out["servers"] = [server for server in out["servers"] if server["id"] != server_id]
    if out["active_server"] == server_id:
        out["active_server"] = ""
        out["proxy"] = copy.deepcopy(DEFAULTS["proxy"])
    return out


def select_server(cfg, server_id):
    out = copy.deepcopy(cfg)
    server = next((item for item in out["servers"] if item["id"] == server_id), None)
    if server is None:
        raise ConfigError("that server no longer exists")
    out["active_server"] = server_id
    out["proxy"] = copy.deepcopy(server["proxy"])
    return out


def validate(raw):
    """Return a normalised copy of *raw* or raise ConfigError listing every problem."""
    cfg = merge(defaults(), raw)
    errors = []

    before = copy.deepcopy(cfg["proxy"])
    _normalise_proxy(cfg["proxy"], errors)
    _normalise_servers(cfg, errors, before)

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

    for key in ("ip_check_url", "geo_url", "test_url"):
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
    if cfg["tcp_port"] == cfg["dns_port"]:
        errors.append("'tcp_port' and 'dns_port' must differ")
    if isinstance(cfg["engine_port"], int) and not isinstance(cfg["engine_port"], bool):
        helpers = range(cfg["engine_port"], cfg["engine_port"] + ENGINE_PORTS)
        if helpers[-1] > 65535 or cfg["tcp_port"] in helpers or cfg["dns_port"] in helpers:
            errors.append(f"'engine_port' and the {ENGINE_PORTS - 1} ports after it must be free of "
                          "'tcp_port' and 'dns_port', and below 65536")
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
    for server in out["servers"]:
        server["label"] = server_name(server)
        server["address"] = proxy_label(server)
    for proxy in [out["proxy"]] + [server["proxy"] for server in out["servers"]]:
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
