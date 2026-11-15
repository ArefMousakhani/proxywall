"""proxywall - command line control for the ProxyWall service."""

import argparse
import json
import os
import subprocess
import sys
import time

from . import __version__, config, geo
from .client import Client, DaemonError, DaemonUnavailable
from .firewall import TABLE

STATE_TEXT = {
    "connected": "Connected",
    "connecting": "Connecting",
    "unreachable": "Proxy unreachable - traffic is blocked",
    "country_blocked": "Blocked country - nothing is sent through the proxy",
    "checking": "Checking the exit country - traffic waits",
    "blocked": "Disconnected - kill switch is blocking traffic",
    "disconnected": "Disconnected",
    "error": "Error",
}


def human_bytes(count):
    value = float(count)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024


def _on_off(text):
    value = text.lower()
    if value in ("on", "yes", "true", "1"):
        return True
    if value in ("off", "no", "false", "0"):
        return False
    raise argparse.ArgumentTypeError("expected 'on' or 'off'")


def cmd_status(client, args):
    status = client.status()
    if args.json:
        print(json.dumps(status, indent=2))
        return 0
    print(f"Status       {STATE_TEXT.get(status['state'], status['state'])}")
    print(f"Proxy        {status['proxy'] or '(not set)'}")
    if status["state"] in ("connected", "country_blocked"):
        ip = status.get("public_ip")
        if ip:
            print(f"Public IP    {ip}" + (f" ({status['country']})" if status.get("country") else ""))
        place = geo.format_place(status)
        if place and status.get("latitude") is not None:
            coordinates = geo.format_coordinates(status["latitude"], status["longitude"])
            print(f"Location     {place} ({'' if status.get('location_exact') else 'about '}{coordinates})")
        elif place:
            print(f"Location     {place}")
        if status.get("latency_ms") is not None:
            print(f"Latency      {status['latency_ms']} ms to the server")
        if status.get("internet_ok") is not None:
            host = status.get("test_host") or "the test page"
            print(f"Internet     {status['internet_ms']} ms to {host}" if status["internet_ok"]
                  else f"Internet     {host} does not answer through this server")
    if status.get("blocked_countries"):
        print(f"Blocked      {', '.join(status['blocked_countries'])}")
    print(f"Kill switch  {'on' if status['kill_switch'] else 'off'}")
    print(f"Allow LAN    {'on' if status['allow_lan'] else 'off'}")
    print(f"Exclusions   {status['excluded']}")
    stats = status["stats"]
    print(f"Traffic      down {human_bytes(stats['down'])}, up {human_bytes(stats['up'])}, "
          f"{stats['active']} open connection(s)")
    if status.get("error"):
        print(f"Last error   {status['error']}")
    return 0 if status["state"] in ("connected", "connecting", "disconnected") else 3


def cmd_connect(client, args):
    client.connect()
    deadline = time.monotonic() + args.wait
    status = client.status()
    while status["state"] in ("connecting", "checking") and time.monotonic() < deadline:
        time.sleep(0.3)
        status = client.status()
    print(STATE_TEXT.get(status["state"], status["state"]))
    if status["state"] != "connected" and status.get("error"):
        print(status["error"], file=sys.stderr)
    return 0 if status["state"] == "connected" else 3


def cmd_disconnect(client, _args):
    client.disconnect()
    print(STATE_TEXT[client.status()["state"]])
    return 0


def cmd_set_proxy(client, args):
    proxy = config.parse_proxy_url(args.url)
    if args.key:
        if proxy["type"] != "ssh":
            print("--key is only for ssh:// servers", file=sys.stderr)
            return 2
        try:
            with open(os.path.expanduser(args.key), encoding="utf-8") as handle:
                proxy["private_key"] = handle.read()
        except (OSError, UnicodeDecodeError) as exc:
            print(f"cannot read {args.key}: {exc}", file=sys.stderr)
            return 2
    elif proxy["type"] == "ssh":
        proxy["private_key"] = ""
    client.set_config({"proxy": proxy})
    print(f"Proxy set to {client.status()['proxy']}")
    return 0


def cmd_kill_switch(client, args):
    client.set_config({"kill_switch": args.value})
    print(f"Kill switch {'on' if args.value else 'off'}")
    return 0


def cmd_lan(client, args):
    client.set_config({"allow_lan": args.value})
    print(f"Allow LAN {'on' if args.value else 'off'}")
    return 0


def cmd_exclude(client, args):
    current = client.get_config()["exclude"]
    if args.action == "list":
        print("\n".join(current) if current else "(no exclusions)")
        return 0
    if not args.entries:
        print("nothing to do: give at least one domain, IP or network", file=sys.stderr)
        return 2
    if args.action == "add":
        updated = current + args.entries
    else:
        from .rules import normalize_list
        drop, errors = normalize_list(args.entries)
        if errors:
            raise config.ConfigError(errors)
        keys = {e.lstrip("*.") for e in drop}
        updated = [e for e in current if e.lstrip("*.") not in keys]
    print("\n".join(client.set_config({"exclude": updated})["exclude"]) or "(no exclusions)")
    return 0


def cmd_connections(client, args):
    """Open connections by site (`proxywall exclude add SITE` sends one outside the proxy)."""
    rows = client.status().get("connections")
    if rows is None:
        print("the running service is too old to list connections: restart it", file=sys.stderr)
        return 1
    if not rows:
        print("(no open connections)")
        return 0
    width = max(len(row["host"]) for row in rows)
    for row in rows:
        state = "connecting" if row["pending"] == row["count"] else "open"
        print(f"{row['host']:<{width}}  {row['count']:>3}  {state:<10}  {row['route']:<6}  "
              f"down {human_bytes(row['down'])}, up {human_bytes(row['up'])}")
    return 0


def country_code(text):
    """`ir`, `IR` or `Iran` -> `IR`. Raises ConfigError for anything unknown."""
    wanted = text.strip()
    if wanted.upper() in geo.COUNTRIES:
        return wanted.upper()
    for code, entry in geo.COUNTRIES.items():
        if entry[0].lower() == wanted.lower():
            return code
    raise config.ConfigError(f"'{text}' is not a country code or name (see: proxywall block-country codes)")


def _test_text(result):
    if not result:
        return "not tested"
    if result["state"] != "done":
        return "testing..."
    parts = [f"ping {result['ping_ms']} ms" if result["ping_ms"] is not None else "no ping"]
    if result["reach"]:
        parts.append(f"internet {result['reach_ms']} ms")
    elif result["reach"] is False:
        parts.append("internet unreachable")
    if result.get("country"):
        parts.append(result["country"])
    if result.get("error"):
        parts.append(result["error"])
    return ", ".join(parts)


def _server_id(client, text):
    """A server by id, by position in the list (1, 2, ...) or by exact name."""
    servers = client.status()["servers"]
    for server in servers:
        if text in (server["id"], server["name"]):
            return server["id"]
    if text.isdigit() and 1 <= int(text) <= len(servers):
        return servers[int(text) - 1]["id"]
    raise config.ConfigError(f"no server '{text}' (see: proxywall server list)")


def cmd_server(client, args):
    if args.action == "add":
        if not args.items:
            print("give at least one address or link", file=sys.stderr)
            return 2
        for url in args.items:
            client.server_save(None, args.name if len(args.items) == 1 else None, config.parse_proxy_url(url))
    elif args.action in ("use", "remove"):
        if len(args.items) != 1:
            print(f"usage: proxywall server {args.action} SERVER", file=sys.stderr)
            return 2
        server = _server_id(client, args.items[0])
        (client.server_select if args.action == "use" else client.server_remove)(server)
    elif args.action == "test":
        ids = [_server_id(client, item) for item in args.items] or None
        client.server_test(ids)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            tests = client.status()["tests"]
            wanted = ids or [server["id"] for server in client.status()["servers"]]
            if all(tests.get(server, {}).get("state") == "done" for server in wanted):
                break
            time.sleep(0.4)
    status = client.status()
    if not status["servers"]:
        print("(no servers)")
    for number, server in enumerate(status["servers"], 1):
        mark = "*" if server["id"] == status["active_server"] else " "
        line = f"{mark} {number:>2}  {server['name']:<24.24}  {server['address']:<38.38}"
        if args.action == "test" or status["tests"].get(server["id"]):
            line += "  " + _test_text(status["tests"].get(server["id"]))
        print(line.rstrip())
    return 0


def cmd_block_country(client, args):
    if args.action == "codes":
        for code, entry in geo.COUNTRIES.items():
            print(f"{code}  {entry[0]}")
        return 0
    current = client.get_config().get("blocked_countries", [])
    if args.action != "list":
        if not args.countries:
            print("nothing to do: give at least one country code, e.g. IR", file=sys.stderr)
            return 2
        codes = {country_code(text) for text in args.countries}
        updated = sorted(set(current) | codes) if args.action == "add" else [c for c in current if c not in codes]
        current = client.set_config({"blocked_countries": updated})["blocked_countries"]
    print("\n".join(f"{code}  {geo.country_name(code)}" for code in current) or "(no blocked countries)")
    return 0


def cmd_config(client, args):
    if args.assignments:
        patch = {}
        for item in args.assignments:
            key, sep, value = item.partition("=")
            if not sep:
                print(f"expected key=value, got '{item}'", file=sys.stderr)
                return 2
            try:
                parsed = json.loads(value)
            except ValueError:
                parsed = value
            target = patch
            parts = key.split(".")
            for part in parts[:-1]:
                target = target.setdefault(part, {})
            target[parts[-1]] = parsed
        client.set_config(patch)
    print(json.dumps(client.get_config(), indent=2, ensure_ascii=False))
    return 0


def cmd_logs(client, args):
    for line in client.logs(args.count):
        stamp = time.strftime("%H:%M:%S", time.localtime(line["time"]))
        print(f"{stamp} {line['level']:<7} {line['message']}")
    return 0


def cmd_reset_firewall(_client, _args):
    """Emergency exit that works even when the service is broken or gone."""
    if os.geteuid() != 0:
        print("reset-firewall must run as root:  sudo proxywall reset-firewall", file=sys.stderr)
        return 1
    subprocess.run(["systemctl", "stop", "proxywall.service"], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    from . import paths
    for path in (paths.BOOT_RULES_FILE, paths.STATE_FILE):
        try:
            os.unlink(path)
        except OSError:
            pass
    proc = subprocess.run(["nft", "-f", "-"], input=f"table inet {TABLE}\ndelete table inet {TABLE}\n",
                          text=True, capture_output=True, check=False)
    if proc.returncode != 0:
        print(proc.stderr.strip(), file=sys.stderr)
        return 1
    print("Firewall removed and service stopped. Direct networking is restored.\n"
          "Note: if the kill switch is enabled it returns when the service starts again.\n"
          "Start it with:  sudo systemctl start proxywall")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="proxywall", description="Control the ProxyWall service (system-wide proxy with a kill switch).")
    parser.add_argument("--version", action="version", version=f"proxywall {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p = sub.add_parser("status", help="show the connection status")
    p.add_argument("--json", action="store_true", help="machine readable output")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("connect", help="send all traffic through the proxy")
    p.add_argument("--wait", type=float, default=10.0, metavar="SECONDS",
                   help="how long to wait for the proxy to answer (default 10)")
    p.set_defaults(func=cmd_connect)

    p = sub.add_parser("disconnect", help="stop using the proxy")
    p.set_defaults(func=cmd_disconnect)

    p = sub.add_parser("set-proxy", help="set the server: socks5://, http://, ssh://user:pass@host, "
                                         "or a vless://, vmess://, trojan://, ss:// link")
    p.add_argument("url", metavar="URL")
    p.add_argument("--key", metavar="FILE", help="private key for an ssh:// server")
    p.set_defaults(func=cmd_set_proxy)

    p = sub.add_parser("kill-switch", help="block all traffic whenever the proxy is not connected")
    p.add_argument("value", type=_on_off, metavar="on|off")
    p.set_defaults(func=cmd_kill_switch)

    p = sub.add_parser("lan", help="let local network traffic bypass the proxy")
    p.add_argument("value", type=_on_off, metavar="on|off")
    p.set_defaults(func=cmd_lan)

    p = sub.add_parser("exclude", help="manage destinations that bypass the proxy")
    p.add_argument("action", choices=("list", "add", "remove"))
    p.add_argument("entries", nargs="*", metavar="ENTRY", help="domain (*.ir), IP or network (10.0.0.0/8)")
    p.set_defaults(func=cmd_exclude)

    p = sub.add_parser("connections", help="show the connections that are open right now, by site")
    p.set_defaults(func=cmd_connections)

    p = sub.add_parser("server", help="saved servers: list, add, use, remove, test")
    p.add_argument("action", choices=("list", "add", "use", "remove", "test"))
    p.add_argument("items", nargs="*", metavar="SERVER", help="address or link (add); number, id or name (others)")
    p.add_argument("--name", help="a name for the server being added")
    p.set_defaults(func=cmd_server)

    p = sub.add_parser("block-country",
                       help="never send traffic while the proxy comes out in these countries")
    p.add_argument("action", choices=("list", "add", "remove", "codes"))
    p.add_argument("countries", nargs="*", metavar="COUNTRY", help="code or name, e.g. IR")
    p.set_defaults(func=cmd_block_country)

    p = sub.add_parser("config", help="show the configuration, or change it with key=value")
    p.add_argument("assignments", nargs="*", metavar="KEY=VALUE")
    p.set_defaults(func=cmd_config)

    p = sub.add_parser("logs", help="show recent service messages")
    p.add_argument("-n", "--count", type=int, default=100)
    p.set_defaults(func=cmd_logs)

    p = sub.add_parser("reset-firewall", help="emergency: remove the firewall and stop the service (root)")
    p.set_defaults(func=cmd_reset_firewall)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    try:
        return args.func(Client(), args)
    except DaemonUnavailable:
        print("The ProxyWall service is not running.\n"
              "Start it with:  sudo systemctl start proxywall", file=sys.stderr)
        return 4
    except DaemonError as exc:
        for message in exc.errors:
            print(f"error: {message}", file=sys.stderr)
        return 1
    except config.ConfigError as exc:
        for message in exc.errors:
            print(f"error: {message}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
