#!/usr/bin/env python3
"""Render the interface off-screen to PNG files (used for docs/ and for design review).

    python3 tools/screenshots.py docs/images
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import GLib, Gtk  # noqa: E402

from proxywall.gui import app as gui  # noqa: E402

STATS = {"up": 0, "down": 0, "active": 14, "total": 0, "proxied": 0, "direct": 0, "blocked": 0, "failed": 0}
BASE = {"version": gui.__version__, "enabled": True, "kill_switch": True, "allow_lan": True, "firewall_active": True,
        "proxy": "socks5://192.168.1.5:1080", "proxy_configured": True, "since": 0, "latency_ms": 23,
        "public_ip": "203.0.113.42", "country": "DE", "country_name": "Germany", "city": "Frankfurt",
        "latitude": 50.1109, "longitude": 8.6821, "location_exact": True,
        "error": None, "stats": STATS, "excluded": 2}
SCENES = {
    "connected": dict(BASE, state="connected"),
    "connecting": dict(BASE, state="connecting", public_ip=None, latency_ms=None),
    "unreachable": dict(BASE, state="unreachable", public_ip=None, latency_ms=None,
                        error="cannot reach the proxy at 192.168.1.5:1080: Connection refused"),
    "blocked": dict(BASE, state="blocked", enabled=False, public_ip=None, latency_ms=None),
    "country-blocked": dict(BASE, state="country_blocked", public_ip="198.51.100.24", country="IR",
                            country_name="Iran", city="Tehran", latitude=35.6944, longitude=51.4215,
                            blocked_countries=["IR"], latency_ms=None,
                            error="The proxy comes out in Iran (198.51.100.24), a blocked country"),
    "off": dict(BASE, state="disconnected", enabled=False, kill_switch=False, firewall_active=False,
                public_ip=None, latency_ms=None),
}
CONFIG = {"proxy": {"type": "socks5", "host": "192.168.1.5", "port": 1080, "username": "", "password_set": False},
          "exclude": ["*.ir", "example.com", "10.1.0.0/16"], "allow_lan": True, "blocked_countries": ["IR"]}


class NoWorker:
    def submit(self, func, done=None):
        pass


LINK_CONFIG = {"proxy": {"type": "vless", "host": "example.com", "port": 443, "username": "", "password_set": False,
                         "key_set": False, "link_set": True, "name": "Frankfurt"},
               "exclude": ["*.ir"], "allow_lan": True, "blocked_countries": ["IR"]}


def shoot(name, out_dir, settings=False, status=None, countries=False, config=None):
    panel = gui.Panel(NoWorker())
    window = Gtk.OffscreenWindow()
    window.get_style_context().add_class("pw-root")
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
    panel.header.set_show_close_button(False)
    box.pack_start(panel.header, False, False, 0)
    box.pack_start(panel.stack, True, True, 0)
    window.add(box)
    window.set_size_request(372, 716)
    panel.stack.set_transition_type(Gtk.StackTransitionType.NONE)
    window.show_all()
    if status:
        panel.render(dict(status, stats=dict(STATS)))
        moving = status["state"] == "connected"
        panel.render(dict(status, stats=dict(STATS, up=180_000 if moving else 0, down=2_400_000 if moving else 0,
                                             active=14 if moving else 0)))
        if status["state"] == "connecting":
            panel.power._angle = 4.0
    if settings:
        panel.show_settings()
        panel._fill_settings(config or CONFIG, None)
    if countries:
        panel.show_countries()

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
    settings = Gtk.Settings.get_default()
    settings.set_property("gtk-application-prefer-dark-theme", True)
    gui.load_css()
    for name, status in SCENES.items():
        shoot(name, out_dir, status=status)
    shoot("settings", out_dir, settings=True, status=SCENES["connected"])
    shoot("countries", out_dir, settings=True, countries=True, status=SCENES["connected"])
    shoot("settings-link", out_dir, settings=True, status=SCENES["connected"], config=LINK_CONFIG)
    shoot("stopped", out_dir)
    tray_strip(out_dir)


if __name__ == "__main__":
    main()
