"""Share links (vless://, vmess://, trojan://, ss://) and the Xray configuration made from them.

SOCKS5 and HTTP proxies are spoken by ProxyWall itself. Everything else is
handed to Xray, which runs as a child process with a local SOCKS5 port that
only the daemon uses. This module is pure data handling: it parses a link into
a flat ``server`` dict and turns that dict into an Xray configuration.
"""

import base64
import binascii
import ipaddress
import json
import re
import uuid
from urllib.parse import parse_qsl, unquote, urlsplit

ENGINE_KINDS = ("vless", "vmess", "trojan", "shadowsocks")
SCHEMES = {"vless": "vless", "vmess": "vmess", "trojan": "trojan", "ss": "shadowsocks"}
# Protocols people will paste that Xray cannot speak: say so instead of failing obscurely.
UNSUPPORTED = {"hysteria": "Hysteria", "hysteria2": "Hysteria2", "hy2": "Hysteria2", "tuic": "TUIC",
               "wireguard": "WireGuard", "wg": "WireGuard", "naive+https": "NaiveProxy",
               "naive+quic": "NaiveProxy", "ssr": "ShadowsocksR", "juicity": "Juicity", "anytls": "AnyTLS"}
NETWORKS = {"tcp": "raw", "raw": "raw", "ws": "ws", "websocket": "ws", "grpc": "grpc", "gun": "grpc",
            "httpupgrade": "httpupgrade", "xhttp": "xhttp", "splithttp": "xhttp", "kcp": "kcp", "mkcp": "kcp"}
SS_METHODS = ("aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305",
              "xchacha20-poly1305", "xchacha20-ietf-poly1305", "none", "plain",
              "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305")
_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$")


class LinkError(ValueError):
    pass


def scheme_of(text):
    """The lower-case scheme of a link, or '' when it has none."""
    head, sep, _ = text.strip().partition("://")
    return head.lower() if sep and re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*", head) else ""


def is_engine_link(text):
    return scheme_of(text) in SCHEMES or scheme_of(text) in UNSUPPORTED


def _b64(text):
    """Decode standard or URL-safe base64, with or without padding."""
    cleaned = "".join(text.split()).replace("-", "+").replace("_", "/")
    try:
        return base64.b64decode(cleaned + "=" * (-len(cleaned) % 4), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        raise LinkError("the link is damaged (bad base64)") from None


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _host(value):
    host = str(value or "").strip().strip("[]").lower().rstrip(".")
    if not host:
        raise LinkError("the link has no server address")
    if not (_is_ip(host) or _HOST_RE.match(host)):
        raise LinkError(f"'{value}' is not a valid server address")
    return host


def _port(value):
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        raise LinkError("the link has no valid port") from None
    if not 1 <= port <= 65535:
        raise LinkError("the port must be between 1 and 65535")
    return port


def _uuid(value):
    text = str(value or "").strip()
    try:
        return str(uuid.UUID(text))
    except ValueError:
        if text and len(text.encode()) <= 30:
            return text  # Xray maps short non-UUID strings to a UUID itself
        raise LinkError("the user id in the link is not a UUID") from None


def _split(url):
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        raise LinkError("the link is not a valid address") from None
    query = {key.lower(): value for key, value in parse_qsl(parts.query, keep_blank_values=True)}
    return parts, port, query, unquote(parts.fragment or "").strip()


def _stream(server, query, default_security="none"):
    """Transport and TLS options, shared by vless and trojan links (v2rayN conventions)."""
    network = (query.get("type") or "tcp").lower()
    if network in ("http", "h2", "quic"):
        raise LinkError(f"the '{network}' transport is no longer supported by Xray")
    if network not in NETWORKS:
        raise LinkError(f"unknown transport '{network}'")
    security = (query.get("security") or default_security).lower()
    if security == "xtls":
        security = "tls"
    if security not in ("none", "tls", "reality"):
        raise LinkError(f"unknown security '{security}'")
    server.update(
        network=NETWORKS[network], security=security,
        sni=query.get("sni") or query.get("peer") or "",
        fingerprint=query.get("fp") or "",
        alpn=[item for item in (query.get("alpn") or "").split(",") if item],
        insecure=(query.get("allowinsecure") or query.get("insecure") or "") in ("1", "true"),
        public_key=query.get("pbk") or "", short_id=query.get("sid") or "", spider_x=query.get("spx") or "",
        host_header=query.get("host") or "", path=query.get("path") or "",
        service_name=query.get("servicename") or "", mode=query.get("mode") or "",
        header_type=(query.get("headertype") or "").lower(), seed=query.get("seed") or "",
        authority=query.get("authority") or "", extra=query.get("extra") or "",
    )
    if security == "reality" and not server["public_key"]:
        raise LinkError("a REALITY link needs a public key (pbk)")
    return server


def _base(kind, name, host, port):
    return {"kind": kind, "name": name[:80], "host": _host(host), "port": _port(port), "network": "raw",
            "security": "none", "sni": "", "fingerprint": "", "alpn": [], "insecure": False, "public_key": "",
            "short_id": "", "spider_x": "", "host_header": "", "path": "", "service_name": "", "mode": "",
            "header_type": "", "seed": "", "authority": "", "extra": ""}


def _parse_vless(url):
    parts, port, query, name = _split(url)
    server = _base("vless", name, parts.hostname, port)
    server["id"] = _uuid(unquote(parts.username or ""))
    server["encryption"] = query.get("encryption") or "none"
    server["flow"] = query.get("flow") or ""
    return _stream(server, query)


def _parse_trojan(url):
    parts, port, query, name = _split(url)
    server = _base("trojan", name, parts.hostname, port or 443)
    server["password"] = unquote(parts.username or "")
    if not server["password"]:
        raise LinkError("the trojan link has no password")
    return _stream(server, query, default_security="tls")


def _parse_vmess(url):
    body = url.strip()[len("vmess://"):]
    try:
        data = json.loads(_b64(body.split("#", 1)[0].split("?", 1)[0]))
    except ValueError as exc:
        if isinstance(exc, LinkError):
            raise
        raise LinkError("this vmess link is not in the usual (v2rayN) format") from None
    if not isinstance(data, dict):
        raise LinkError("this vmess link is not in the usual (v2rayN) format")
    data = {str(key).lower(): ("" if value is None else str(value)) for key, value in data.items()}
    server = _base("vmess", data.get("ps", ""), data.get("add"), data.get("port"))
    server["id"] = _uuid(data.get("id"))
    try:
        server["alter_id"] = int(data.get("aid") or 0)
    except ValueError:
        raise LinkError("the vmess link has a bad alterId") from None
    server["cipher"] = data.get("scy") or "auto"
    query = {"type": data.get("net") or "tcp", "security": "tls" if data.get("tls") in ("tls", "reality") else "none",
             "sni": data.get("sni", ""), "fp": data.get("fp", ""), "alpn": data.get("alpn", ""),
             "host": data.get("host", ""), "path": data.get("path", ""),
             "allowinsecure": data.get("allowinsecure", "") or data.get("skip-cert-verify", "")}
    kind = (data.get("type") or "").lower()
    if query["type"].lower() in ("grpc", "gun"):
        query["servicename"], query["mode"], query["path"] = data.get("path", ""), kind, ""
    elif query["type"].lower() in ("xhttp", "splithttp"):
        query["mode"] = kind
    else:
        query["headertype"] = "" if kind in ("none", "") else kind
    if query["type"].lower() in ("kcp", "mkcp"):
        query["seed"], query["path"] = data.get("path", ""), ""
    return _stream(server, query)


def _parse_ss(url):
    text = url.strip()
    body, _, fragment = text[len("ss://"):].partition("#")
    name = unquote(fragment).strip()
    body, _, query_text = body.partition("?")
    body = body.rstrip("/")
    query = {key.lower(): value for key, value in parse_qsl(query_text, keep_blank_values=True)}
    if query.get("plugin"):
        raise LinkError("Shadowsocks plugins (obfs, v2ray-plugin, ...) are not supported")
    if "@" not in body:
        body = _b64(body)  # the old form: base64(method:password@host:port)
        userinfo, _, address = body.rpartition("@")
    else:
        userinfo, _, address = body.rpartition("@")
        userinfo = unquote(userinfo)
        if ":" not in userinfo:
            userinfo = _b64(userinfo)
    method, sep, password = userinfo.partition(":")
    if not sep or not password:
        raise LinkError("the Shadowsocks link has no method or password")
    try:
        parts = urlsplit("//" + address)
        port = parts.port
    except ValueError:
        raise LinkError("the Shadowsocks link has no valid address") from None
    method = method.lower()
    if method not in SS_METHODS:
        raise LinkError(f"Shadowsocks cipher '{method}' is not supported")
    server = _base("shadowsocks", name, parts.hostname, port)
    server.update(method=method, password=password)
    return server


_PARSERS = {"vless": _parse_vless, "vmess": _parse_vmess, "trojan": _parse_trojan, "ss": _parse_ss}


def parse(url):
    """Share link -> server dict. Raises LinkError with a message fit for the user."""
    if not isinstance(url, str) or not url.strip():
        raise LinkError("paste a link first")
    if len(url) > 8192:
        raise LinkError("the link is too long")
    scheme = scheme_of(url)
    if scheme in UNSUPPORTED:
        raise LinkError(f"{UNSUPPORTED[scheme]} links are not supported: ProxyWall's engine (Xray) does not speak it")
    if scheme not in _PARSERS:
        raise LinkError("unknown kind of link (use vless://, vmess://, trojan:// or ss://)")
    return _PARSERS[scheme](url)


# ---------------------------------------------------------------- Xray configuration
def _stream_settings(server, mark):
    network, security = server["network"], server["security"]
    domain = "" if _is_ip(server["host"]) else server["host"]
    sni = server["sni"] or domain
    stream = {"network": network, "security": security}
    if security == "tls":
        tls = {"allowInsecure": bool(server["insecure"])}
        if sni:
            tls["serverName"] = sni
        if server["alpn"]:
            tls["alpn"] = server["alpn"]
        if server["fingerprint"]:
            tls["fingerprint"] = server["fingerprint"]
        stream["tlsSettings"] = tls
    elif security == "reality":
        stream["realitySettings"] = {
            "serverName": sni, "fingerprint": server["fingerprint"] or "chrome",
            "publicKey": server["public_key"], "shortId": server["short_id"], "spiderX": server["spider_x"]}
    # The address handed to Xray is an IP, so every place that would default
    # to "the address" has to be given the real name explicitly.
    host_header = server["host_header"] or sni
    path = server["path"] or "/"
    if network == "ws":
        stream["wsSettings"] = {"path": path, **({"host": host_header} if host_header else {})}
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": path, **({"host": host_header} if host_header else {})}
    elif network == "xhttp":
        settings = {"path": path, **({"host": host_header} if host_header else {})}
        if server["mode"]:
            settings["mode"] = server["mode"]
        if server["extra"]:
            try:
                extra = json.loads(server["extra"])
            except ValueError:
                raise LinkError("the 'extra' part of the link is not valid JSON") from None
            if isinstance(extra, dict):
                settings["extra"] = extra
        stream["xhttpSettings"] = settings
    elif network == "grpc":
        settings = {"serviceName": server["service_name"], "multiMode": server["mode"] == "multi"}
        if server["authority"]:
            settings["authority"] = server["authority"]
        stream["grpcSettings"] = settings
    elif network == "kcp":
        settings = {"header": {"type": server["header_type"] or "none"}}
        if server["seed"]:
            settings["seed"] = server["seed"]
        stream["kcpSettings"] = settings
    elif server["header_type"] == "http":
        request = {"path": [item for item in path.split(",") if item] or ["/"]}
        if host_header:
            request["headers"] = {"Host": [item for item in host_header.split(",") if item]}
        stream["rawSettings"] = {"header": {"type": "http", "request": request}}
    if mark:
        stream["sockopt"] = {"mark": mark}
    return stream


def xray_outbound(server, address, mark=0):
    """The Xray outbound for *server*, dialled at *address* (an IP the daemon resolved)."""
    kind, port = server["kind"], server["port"]
    if kind == "vless":
        user = {"id": server["id"], "encryption": server["encryption"] or "none"}
        if server["flow"]:
            user["flow"] = server["flow"]
        settings = {"vnext": [{"address": address, "port": port, "users": [user]}]}
    elif kind == "vmess":
        user = {"id": server["id"], "alterId": server["alter_id"], "security": server["cipher"] or "auto"}
        settings = {"vnext": [{"address": address, "port": port, "users": [user]}]}
    elif kind == "trojan":
        settings = {"servers": [{"address": address, "port": port, "password": server["password"]}]}
    elif kind == "shadowsocks":
        settings = {"servers": [{"address": address, "port": port, "method": server["method"],
                                 "password": server["password"]}]}
    else:
        raise LinkError(f"unknown server kind '{kind}'")
    return {"tag": "proxy", "protocol": kind, "settings": settings,
            "streamSettings": _stream_settings(server, mark)}


def xray_config(server, address, listen_port, user, password, mark=0, loglevel="warning"):
    """A complete configuration: one authenticated local SOCKS5 port, one way out."""
    return {
        "log": {"loglevel": loglevel},
        "inbounds": [{
            "tag": "local", "listen": "127.0.0.1", "port": listen_port, "protocol": "socks",
            "settings": {"auth": "password", "accounts": [{"user": user, "pass": password}], "udp": False},
        }],
        "outbounds": [xray_outbound(server, address, mark)],
    }


def label(server):
    host = f"[{server['host']}]" if ":" in server["host"] else server["host"]
    return f"{server['kind']}://{host}:{server['port']}"
