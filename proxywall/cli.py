"""proxywall - command line control for the ProxyWall service."""

import argparse
import json
import os
import subprocess
import sys
import time

from . import __version__, config
from .client import Client, DaemonError, DaemonUnavailable
from .firewall import TABLE

STATE_TEXT = {
    "connected": "Connected",
    "connecting": "Connecting",
    "unreachable": "Proxy unreachable - traffic is blocked",
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
    if status["state"] == "connected":
        ip = status.get("public_ip")
        if ip:
            print(f"Public IP    {ip}" + (f" ({status['country']})" if status.get("country") else ""))
        if status.get("latency_ms") is not None:
            print(f"Latency      {status['latency_ms']} ms")
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
    while status["state"] == "connecting" and time.monotonic() < deadline:
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
    client.set_config({"proxy": config.parse_proxy_url(args.url)})
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

    p = sub.add_parser("set-proxy", help="set the proxy, e.g. socks5://user:pass@192.168.1.5:1080")
    p.add_argument("url", metavar="URL")
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
