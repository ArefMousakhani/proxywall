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
BASE = {"version": "1.0.0", "enabled": True, "kill_switch": True, "allow_lan": True, "firewall_active": True,
        "proxy": "socks5://192.168.1.5:1080", "proxy_configured": True, "since": 0, "latency_ms": 23,
        "public_ip": "203.0.113.42", "country": "DE", "error": None, "stats": STATS, "excluded": 2}
SCENES = {
    "connected": dict(BASE, state="connected"),
    "connecting": dict(BASE, state="connecting", public_ip=None, latency_ms=None),
    "unreachable": dict(BASE, state="unreachable", public_ip=None, latency_ms=None,
                        error="cannot reach the proxy at 192.168.1.5:1080: Connection refused"),
    "blocked": dict(BASE, state="blocked", enabled=False, public_ip=None, latency_ms=None),
    "off": dict(BASE, state="disconnected", enabled=False, kill_switch=False, firewall_active=False,
                public_ip=None, latency_ms=None),
}
CONFIG = {"proxy": {"type": "socks5", "host": "192.168.1.5", "port": 1080, "username": "", "password_set": False},
          "exclude": ["*.ir", "example.com", "10.1.0.0/16"], "allow_lan": True}


class NoWorker:
    def submit(self, func, done=None):
        pass


def shoot(name, out_dir, settings=False, status=None):
    panel = gui.Panel(NoWorker())
    window = Gtk.OffscreenWindow()
    window.get_style_context().add_class("pw-root")
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
    panel.header.set_show_close_button(False)
    box.pack_start(panel.header, False, False, 0)
    box.pack_start(panel.stack, True, True, 0)
    window.add(box)
    window.set_size_request(372, 660)
    panel.stack.set_transition_type(Gtk.StackTransitionType.NONE)
    window.show_all()
    if status:
        panel.render(dict(status, stats=dict(STATS)))
        panel.render(dict(status, stats=dict(STATS, up=180_000, down=2_400_000)))
        if status["state"] == "connecting":
            panel.power._angle = 4.0
    if settings:
        panel.show_settings()
        panel._fill_settings(CONFIG, None)

    def save():
        window.get_pixbuf().savev(os.path.join(out_dir, name + ".png"), "png", [], [])
        Gtk.main_quit()
        return False

    GLib.timeout_add(350, save)
    Gtk.main()
    window.destroy()


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(out_dir, exist_ok=True)
    settings = Gtk.Settings.get_default()
    settings.set_property("gtk-application-prefer-dark-theme", True)
    gui.load_css()
    for name, status in SCENES.items():
        shoot(name, out_dir, status=status)
    shoot("settings", out_dir, settings=True, status=SCENES["connected"])
    shoot("stopped", out_dir)


if __name__ == "__main__":
    main()
