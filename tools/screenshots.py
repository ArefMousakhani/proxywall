#!/usr/bin/env python3
"""Render the interface off-screen to PNG files (used for docs/ and for design review).

    python3 tools/screenshots.py docs/images
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import GLib, Gtk  # noqa: E402

from proxywall.gui import app as gui  # noqa: E402

STATS = {"up": 0, "down": 0, "active": 14, "total": 0, "proxied": 0, "direct": 0, "blocked": 0, "failed": 0}
SERVERS = [
    {"id": "s1", "name": "Frankfurt", "type": "vless", "address": "vless://de.example.com:443"},
    {"id": "s2", "name": "Home office", "type": "socks5", "address": "socks5://192.168.1.5:1080"},
    {"id": "s3", "name": "Amsterdam", "type": "trojan", "address": "trojan://nl.example.net:443"},
    {"id": "s4", "name": "My VPS", "type": "ssh", "address": "ssh://vps.example.org:22"},
    {"id": "s5", "name": "Tokyo", "type": "shadowsocks", "address": "shadowsocks://jp.example.com:8388"},
    {"id": "s6", "name": "Old server", "type": "vmess", "address": "vmess://old.example.com:443"},
]


def test(ping, reach_ms=None, country=None, reach=True, error=None, state="done"):
    return {"state": state, "at": time.time(), "ping_ms": ping, "reach": reach if state == "done" else None,
            "reach_ms": reach_ms, "ip": None, "country": country, "error": error}


TESTS = {
    "s1": test(48, 182, "DE"),
    "s2": test(3, 96, "NL"),
    "s3": test(61, 240, "NL"),
    "s4": test(112, 410, "US"),
    "s5": test(None, state="testing"),
    "s6": test(None, reach=None, error="the server does not answer (timed out)"),
}
def site(host, count, down, up, pending=0, route="proxy", names=()):
    return {"host": host, "route": route, "exclude": host, "count": count, "pending": pending, "up": up,
            "down": down, "since": time.time(), "names": list(names)}


CONNECTIONS = [
    site("github.com", 3, 1_840_000, 96_000, names=("api.github.com", "github.com")),
    site("google.com", 5, 412_000, 38_000, pending=1, names=("mail.google.com", "www.google.com")),
    site("shop.ir", 2, 96_000, 12_000, route="direct"),
    site("wikipedia.org", 1, 0, 0, pending=1),
    site("youtube.com", 3, 26_400_000, 310_000),
]
BASE = {"version": gui.__version__, "enabled": True, "kill_switch": True, "allow_lan": True, "firewall_active": True,
        "proxy": "vless://de.example.com:443", "proxy_configured": True, "since": 0, "latency_ms": 48,
        "internet_ms": 182, "internet_ok": True, "test_host": "www.google.com",
        "public_ip": "203.0.113.42", "country": "DE", "country_name": "Germany", "city": "Frankfurt",
        "latitude": 50.1109, "longitude": 8.6821, "location_exact": True,
        "error": None, "stats": STATS, "excluded": 2, "blocked_countries": ["IR"],
        "servers": SERVERS, "active_server": "s1", "tests": TESTS, "connections": CONNECTIONS}
IDLE = dict(public_ip=None, latency_ms=None, internet_ms=None, internet_ok=None, connections=[])
SCENES = {
    "connected": dict(BASE, state="connected"),
    "connecting": dict(BASE, state="connecting", **IDLE),
    "unreachable": dict(BASE, state="unreachable", **IDLE,
                        error="no answer through the server (timed out)"),
    "blocked": dict(BASE, state="blocked", enabled=False, **IDLE),
    "country-blocked": dict(BASE, state="country_blocked", **dict(IDLE, public_ip="198.51.100.24"), country="IR",
                            country_name="Iran", city="Tehran", latitude=35.6944, longitude=51.4215,
                            error="The proxy comes out in Iran (198.51.100.24), a blocked country"),
    "off": dict(BASE, state="disconnected", enabled=False, kill_switch=False, firewall_active=False, **IDLE),
}


def proxy(kind, host, port, **extra):
    return dict({"type": kind, "host": host, "port": port, "username": "", "password_set": False,
                 "key_set": False, "link_set": kind in ("vless", "trojan", "vmess", "shadowsocks"), "name": ""}, **extra)


CONFIG = {"proxy": proxy("vless", "de.example.com", 443, name="Frankfurt"),
          "servers": [{"id": "s1", "name": "Frankfurt", "proxy": proxy("vless", "de.example.com", 443, name="Frankfurt")},
                      {"id": "s4", "name": "My VPS", "proxy": proxy("ssh", "vps.example.org", 22, username="me",
                                                                   key_set=True)}],
          "exclude": ["*.ir", "example.com", "10.1.0.0/16"], "allow_lan": True, "blocked_countries": ["IR"]}


class NoWorker:
    def submit(self, func, done=None):
        pass


def shoot(name, out_dir, status=None, page=None):
    panel = gui.Panel(NoWorker())
    window = Gtk.OffscreenWindow()
    window.get_style_context().add_class("pw-root")
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
    panel.header.set_show_close_button(False)
    box.pack_start(panel.header, False, False, 0)
    box.pack_start(panel.root, True, True, 0)
    window.add(box)
    window.set_size_request(*gui.WINDOW_SIZE)
    panel.stack.set_transition_type(Gtk.StackTransitionType.NONE)
    window.show_all()
    if status:
        panel.render(dict(status, stats=dict(STATS)))
        moving = status["state"] == "connected"
        panel.render(dict(status, stats=dict(STATS, up=180_000 if moving else 0, down=2_400_000 if moving else 0,
                                             active=14 if moving else 0)))
        if status["state"] == "connecting":
            panel.power._angle = 4.0
    if page in ("settings", "countries"):
        panel.show_settings()
        panel._fill_settings(CONFIG, None)
        if page == "countries":
            panel.show_countries()
    elif page in ("server-link", "server-ssh", "server-new"):
        panel.show_server_form({"server-link": "s1", "server-ssh": "s4", "server-new": None}[page])
        panel._fill_server(CONFIG, None)

    def save():
        window.get_pixbuf().savev(os.path.join(out_dir, name + ".png"), "png", [], [])
        Gtk.main_quit()
        return False

    GLib.timeout_add(350, save)
    Gtk.main()
    window.destroy()


def tray_strip(out_dir):
    """A piece of a desktop panel with the flag icon in it, as it looks while connected."""
    import cairo
    scale, width, height, icon = 2, 190, 34, 22
    surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, width * scale, height * scale)
    cr = cairo.Context(surface)
    cr.scale(scale, scale)
    cr.set_source_rgb(0.16, 0.17, 0.19)
    cr.paint()
    x = 12
    for code in ("DE", "NL", "US", "JP"):
        flag = gui.draw_tray_flag(gui.flag_pixbuf(code), icon * scale)
        cr.save()
        cr.translate(x, (height - icon) / 2)
        cr.scale(1 / scale, 1 / scale)
        cr.set_source_surface(flag, 0, 0)
        cr.paint()
        cr.restore()
        x += icon + 12
    cr.set_source_rgb(0.86, 0.88, 0.92)
    cr.select_font_face("sans-serif", cairo.FONT_SLANT_NORMAL, cairo.FONT_WEIGHT_NORMAL)
    cr.set_font_size(11.5)
    cr.move_to(width - 12 - cr.text_extents("14:05").x_advance, height / 2 + 4)
    cr.show_text("14:05")
    surface.write_to_png(os.path.join(out_dir, "tray.png"))


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(out_dir, exist_ok=True)
    gui.load_css("dark")
    for name, status in SCENES.items():
        shoot(name, out_dir, status=status)
    connected = SCENES["connected"]
    shoot("settings", out_dir, status=connected, page="settings")
    shoot("countries", out_dir, status=connected, page="countries")
    shoot("server-link", out_dir, status=connected, page="server-link")
    shoot("server-ssh", out_dir, status=connected, page="server-ssh")
    shoot("empty", out_dir, status=dict(SCENES["off"], servers=[], tests={}, active_server="", proxy="",
                                        proxy_configured=False))
    tray_strip(out_dir)
    gui.load_css("light")                       # the same window in the light look
    shoot("connected-light", out_dir, status=connected)


if __name__ == "__main__":
    main()
