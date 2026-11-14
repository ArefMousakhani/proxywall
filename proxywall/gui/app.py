"""ProxyWall desktop interface (GTK 3).

The window is only a remote control: connecting, the firewall and all traffic
handling live in the system service, so closing the window changes nothing.
"""

import math
import os
import queue
import sys
import threading

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
from gi.repository import Gdk, Gio, GLib, Gtk, Pango  # noqa: E402

from .. import APP_ID, APP_NAME, __version__, config  # noqa: E402
from ..cli import human_bytes  # noqa: E402
from ..client import Client, DaemonUnavailable  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ICON_DIRS = (os.path.join(HERE, "..", "..", "data", "icons"), "/usr/share/proxywall/icons")
AUTOSTART_FILE = os.path.join(GLib.get_user_config_dir(), "autostart", "proxywall.desktop")
AUTOSTART_ENTRY = """[Desktop Entry]
Type=Application
Name=ProxyWall
Comment=Show the ProxyWall tray icon
Exec=proxywall-gui --hidden
Icon=proxywall
X-GNOME-Autostart-enabled=true
"""

GREEN, AMBER, RED, GREY = (0.184, 0.831, 0.498), (0.965, 0.718, 0.235), (1.0, 0.42, 0.42), (0.47, 0.53, 0.64)

# state -> (headline, css class, colour, tray icon, explanation)
STATES = {
    "connected": ("CONNECTED", "on", GREEN, "on", "All traffic goes through the proxy"),
    "connecting": ("CONNECTING", "wait", AMBER, "wait", "Reaching the proxy…"),
    "unreachable": ("NO PROXY", "bad", RED, "blocked", "Traffic is blocked until the proxy is back"),
    "blocked": ("BLOCKED", "bad", RED, "blocked", "Firewall is on: connect to use the internet"),
    "disconnected": ("OFF", "off", GREY, "off", "Your traffic is not using the proxy"),
    "error": ("ERROR", "bad", RED, "blocked", "Something went wrong"),
    "stopped": ("SERVICE STOPPED", "off", GREY, "off", "Start it with: sudo systemctl start proxywall"),
}


def icon_path(name):
    for directory in ICON_DIRS:
        path = os.path.abspath(os.path.join(directory, name + ".svg"))
        if os.path.exists(path):
            return path
    return None


class Worker:
    """Runs blocking calls to the service off the UI thread, strictly in order."""

    def __init__(self, client=None):
        self.client = client or Client(timeout=25)
        self._jobs = queue.Queue()
        threading.Thread(target=self._loop, daemon=True, name="proxywall-worker").start()

    def submit(self, func, done=None):
        self._jobs.put((func, done))

    def _loop(self):
        while True:
            func, done = self._jobs.get()
            try:
                result, error = func(self.client), None
            except Exception as exc:  # reported to the UI, never fatal
                result, error = None, exc
            if done is not None:
                GLib.idle_add(done, result, error)


class PowerButton(Gtk.Button):
    """The one big control. Drawn by hand so it can glow and animate."""

    SIZE = 176

    def __init__(self):
        super().__init__()
        self.get_style_context().add_class("pw-power")
        self.set_relief(Gtk.ReliefStyle.NONE)
        self.set_halign(Gtk.Align.CENTER)
        self.set_tooltip_text("Connect / disconnect")
        self.get_accessible().set_name("Connect or disconnect")
        self._colour = GREY
        self._lit = False
        self._spinning = False
        self._angle = 0.0
        self._timer = None
        area = Gtk.DrawingArea()
        area.set_size_request(self.SIZE, self.SIZE)
        area.connect("draw", self._draw)
        self.add(area)
        self._area = area
        self.connect("state-flags-changed", lambda *_: area.queue_draw())
        self.connect("destroy", lambda *_: self._stop_timer())

    def set_visual(self, colour, lit, spinning):
        self._colour, self._lit = colour, lit
        if spinning and not self._spinning:
            self._timer = GLib.timeout_add(30, self._tick)
        elif not spinning:
            self._stop_timer()
        self._spinning = spinning
        self._area.queue_draw()

    def _stop_timer(self):
        if self._timer is not None:
            GLib.source_remove(self._timer)
            self._timer = None

    def _tick(self):
        self._angle = (self._angle + 0.11) % (2 * math.pi)
        self._area.queue_draw()
        return True

    def _draw(self, area, cr):
        import cairo
        width, height = area.get_allocated_width(), area.get_allocated_height()
        cx, cy = width / 2, height / 2
        radius = min(width, height) / 2 - 20
        r, g, b = self._colour
        hover = bool(self.get_state_flags() & Gtk.StateFlags.PRELIGHT)

        if self._lit:  # soft halo
            halo = cairo.RadialGradient(cx, cy, radius * 0.7, cx, cy, radius + 20)
            halo.add_color_stop_rgba(0, r, g, b, 0.30)
            halo.add_color_stop_rgba(1, r, g, b, 0.0)
            cr.set_source(halo)
            cr.arc(cx, cy, radius + 20, 0, 2 * math.pi)
            cr.fill()

        disc = cairo.LinearGradient(0, cy - radius, 0, cy + radius)
        top, bottom = (0.135, 0.185, 0.30), (0.085, 0.12, 0.205)
        if hover:
            top, bottom = (0.16, 0.215, 0.34), (0.10, 0.14, 0.235)
        disc.add_color_stop_rgb(0, *top)
        disc.add_color_stop_rgb(1, *bottom)
        cr.set_source(disc)
        cr.arc(cx, cy, radius - 7, 0, 2 * math.pi)
        cr.fill()

        cr.set_line_width(5)
        cr.set_line_cap(cairo.LINE_CAP_ROUND)
        if self._spinning:
            cr.set_source_rgba(1, 1, 1, 0.10)
            cr.new_sub_path()
            cr.arc(cx, cy, radius, 0, 2 * math.pi)
            cr.close_path()
            cr.stroke()
            cr.set_source_rgb(r, g, b)
            cr.arc(cx, cy, radius, self._angle, self._angle + 1.9)
            cr.stroke()
        else:
            cr.set_source_rgba(r, g, b, 1.0 if self._lit else 0.45)
            cr.new_sub_path()
            cr.arc(cx, cy, radius, 0, 2 * math.pi)
            cr.close_path()
            cr.stroke()

        # power symbol
        glyph = radius * 0.34
        cr.set_line_width(6.5)
        cr.set_source_rgba(r, g, b, 1.0 if (self._lit or self._spinning) else 0.85)
        cr.arc(cx, cy + 2, glyph, math.radians(-60), math.radians(240))
        cr.stroke()
        cr.move_to(cx, cy + 2 - glyph * 1.28)
        cr.line_to(cx, cy + 2 - glyph * 0.30)
        cr.stroke()
        return False


def _label(text="", css=None, xalign=0.0, wrap=False, selectable=False):
    label = Gtk.Label(label=text, xalign=xalign)
    if css:
        label.get_style_context().add_class(css)
    if wrap:
        label.set_line_wrap(True)
        label.set_line_wrap_mode(Pango.WrapMode.WORD_CHAR)
        label.set_max_width_chars(38)
        if xalign == 0.5:
            label.set_justify(Gtk.Justification.CENTER)
    label.set_selectable(selectable)
    return label


def _card():
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=9)
    box.get_style_context().add_class("pw-card")
    return box


class Panel:
    """All widgets and behaviour, independent of the window that hosts them."""

    def __init__(self, worker, on_state_change=None):
        self.worker = worker
        self.on_state_change = on_state_change or (lambda *_: None)
        self.status = None
        self.state = None
        self._busy = False
        self._polling = False
        self._last_stats = None
        self._password_dirty = False
        self._loading = False

        self.header = Gtk.HeaderBar()
        self.header.set_show_close_button(True)
        self.title = _label(APP_NAME.upper(), "pw-title", 0.5)
        self.header.set_custom_title(self.title)
        self.back = Gtk.Button.new_from_icon_name("go-previous-symbolic", Gtk.IconSize.BUTTON)
        self.back.set_tooltip_text("Back")
        self.back.connect("clicked", lambda *_: self.show_main())
        self.back.set_no_show_all(True)
        self.header.pack_start(self.back)
        self.gear = Gtk.Button.new_from_icon_name("emblem-system-symbolic", Gtk.IconSize.BUTTON)
        self.gear.set_tooltip_text("Settings")
        self.gear.connect("clicked", lambda *_: self.show_settings())
        self.gear.set_no_show_all(True)
        self.gear.show()
        self.header.pack_end(self.gear)

        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)
        self.stack.set_transition_duration(180)
        self.stack.add_named(self._build_main(), "main")
        self.stack.add_named(self._build_settings(), "settings")
        self.render_stopped()

    # ------------------------------------------------------------ main page
    def _build_main(self):
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        page.set_border_width(20)

        self.power = PowerButton()
        self.power.connect("clicked", self._on_power)
        page.pack_start(self.power, False, False, 0)

        self.state_label = _label("", "pw-state", 0.5)
        self.state_label.set_margin_top(4)
        page.pack_start(self.state_label, False, False, 0)
        self.sub_label = _label("", "pw-sub", 0.5, wrap=True)
        self.sub_label.set_margin_top(6)
        page.pack_start(self.sub_label, False, False, 0)
        self.error_label = _label("", "pw-error", 0.5, wrap=True, selectable=True)
        self.error_label.set_margin_top(6)
        self.error_label.set_no_show_all(True)
        page.pack_start(self.error_label, False, False, 0)

        info = _card()
        info.set_margin_top(20)
        self.values = {}
        for key, title in (("proxy", "Proxy"), ("ip", "IP address"), ("latency", "Latency")):
            row = Gtk.Box(spacing=12)
            row.pack_start(_label(title, "pw-key"), False, False, 0)
            value = _label("—", "pw-value", 1.0, selectable=True)
            value.set_ellipsize(Pango.EllipsizeMode.MIDDLE)
            row.pack_end(value, True, True, 0)
            info.pack_start(row, False, False, 0)
            self.values[key] = value
        page.pack_start(info, False, False, 0)

        firewall = _card()
        firewall.set_margin_top(12)
        row = Gtk.Box(spacing=12)
        text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        text.pack_start(_label("Firewall", "pw-row-title"), False, False, 0)
        self.firewall_hint = _label("Never go online without the proxy", "pw-key", wrap=True)
        text.pack_start(self.firewall_hint, False, False, 0)
        row.pack_start(text, True, True, 0)
        self.kill_switch = Gtk.Switch(valign=Gtk.Align.CENTER)
        self.kill_switch.get_accessible().set_name("Firewall (kill switch)")
        self._kill_handler = self.kill_switch.connect("notify::active", self._on_kill_switch)
        row.pack_end(self.kill_switch, False, False, 0)
        firewall.pack_start(row, False, False, 0)
        page.pack_start(firewall, False, False, 0)

        self.footer = _label("", "pw-footer", 0.5)
        self.footer.set_margin_top(14)
        page.pack_end(self.footer, False, False, 0)
        return page

    # ------------------------------------------------------------ settings page
    def _build_settings(self):
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        page.set_border_width(20)

        def section(title, top=14):
            label = _label(title, "pw-section")
            label.set_margin_top(top)
            page.pack_start(label, False, False, 0)

        section("PROXY", 0)
        segment = Gtk.Box()
        segment.get_style_context().add_class("pw-seg")
        self.type_socks = Gtk.RadioButton.new_with_label(None, "SOCKS5")
        self.type_http = Gtk.RadioButton.new_with_label_from_widget(self.type_socks, "HTTP")
        for button in (self.type_socks, self.type_http):
            button.set_mode(False)
            segment.pack_start(button, True, True, 0)
        page.pack_start(segment, False, False, 0)

        address = Gtk.Box(spacing=8)
        self.host = Gtk.Entry(placeholder_text="Address, e.g. 192.168.1.5")
        self.host.set_input_purpose(Gtk.InputPurpose.URL)
        self.host.connect("focus-out-event", self._split_host)
        self.host.connect("activate", self._split_host)
        self.port = Gtk.Entry(placeholder_text="Port", width_chars=6, max_length=5)
        self.port.set_input_purpose(Gtk.InputPurpose.DIGITS)
        address.pack_start(self.host, True, True, 0)
        address.pack_start(self.port, False, False, 0)
        page.pack_start(address, False, False, 0)

        self.username = Gtk.Entry(placeholder_text="Username (optional)")
        page.pack_start(self.username, False, False, 0)
        self.password = Gtk.Entry(placeholder_text="Password (optional)", visibility=False)
        self.password.set_input_purpose(Gtk.InputPurpose.PASSWORD)
        self.password.set_icon_from_icon_name(Gtk.EntryIconPosition.SECONDARY, "view-reveal-symbolic")
        self.password.set_icon_tooltip_text(Gtk.EntryIconPosition.SECONDARY, "Show or hide the password")
        self.password.connect("icon-press", lambda entry, *_: entry.set_visibility(not entry.get_visibility()))
        self.password.connect("changed", self._on_password_changed)
        page.pack_start(self.password, False, False, 0)

        section("BYPASS THE PROXY")
        frame = Gtk.Box()
        frame.get_style_context().add_class("pw-textframe")
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.set_min_content_height(84)
        self.exclude = Gtk.TextView()
        self.exclude.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.exclude.set_accepts_tab(False)
        self.exclude.get_accessible().set_name("Destinations that bypass the proxy, one per line")
        scroller.add(self.exclude)
        frame.pack_start(scroller, True, True, 0)
        page.pack_start(frame, False, False, 0)
        page.pack_start(_label("One per line. Example:  *.ir   example.com   10.1.0.0/16", "pw-key", wrap=True),
                        False, False, 0)

        section("OPTIONS")
        options = _card()

        def switch_row(title, hint):
            row = Gtk.Box(spacing=12)
            text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
            text.pack_start(_label(title, "pw-row-title"), False, False, 0)
            text.pack_start(_label(hint, "pw-key", wrap=True), False, False, 0)
            row.pack_start(text, True, True, 0)
            switch = Gtk.Switch(valign=Gtk.Align.CENTER)
            switch.get_accessible().set_name(title)
            row.pack_end(switch, False, False, 0)
            options.pack_start(row, False, False, 0)
            return switch

        self.allow_lan = switch_row("Allow local network", "Printers and local devices stay reachable")
        self.autostart = switch_row("Open at login", "Show the tray icon when you sign in")
        page.pack_start(options, False, False, 0)

        page.pack_start(_label(f"{APP_NAME} {__version__}", "pw-footer", 0.5), False, False, 4)

        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.add(page)

        # Save stays visible below the scrolling form.
        bottom = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        bottom.set_border_width(20)
        bottom.set_margin_top(-8)
        self.settings_error = _label("", "pw-error", wrap=True, selectable=True)
        self.settings_error.set_no_show_all(True)
        bottom.pack_start(self.settings_error, False, False, 0)
        self.save = Gtk.Button(label="Save")
        self.save.get_style_context().add_class("pw-primary")
        self.save.connect("clicked", self._on_save)
        bottom.pack_start(self.save, False, False, 0)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        outer.pack_start(scroller, True, True, 0)
        outer.pack_start(bottom, False, False, 0)
        return outer

    # ------------------------------------------------------------ navigation
    def show_main(self):
        self.stack.set_visible_child_name("main")
        self.back.hide()
        self.gear.show()
        self.title.set_text(APP_NAME.upper())

    def show_settings(self):
        self.settings_error.hide()
        self.save.set_sensitive(False)
        self.stack.set_visible_child_name("settings")
        self.gear.hide()
        self.back.show()
        self.title.set_text("SETTINGS")
        self.worker.submit(lambda client: client.get_config(), self._fill_settings)

    # ------------------------------------------------------------ status
    def poll(self):
        if not self._polling:
            self._polling = True
            self.worker.submit(lambda client: client.status(), self._on_status)
        return True

    def _on_status(self, status, error):
        self._polling = False
        if error is not None:
            self.render_stopped(None if isinstance(error, DaemonUnavailable) else str(error))
        else:
            self.render(status)
        return False

    def render_stopped(self, detail=None):
        self.status = None
        self._last_stats = None
        self._apply_state("stopped", detail=detail)
        for value in self.values.values():
            value.set_text("—")
        self.kill_switch.set_sensitive(False)
        self.footer.set_text("")

    def render(self, status):
        self.status = status
        state = status["state"] if status["state"] in STATES else "error"
        explanation = None
        if state == "disconnected" and not status["proxy_configured"]:
            explanation = "Add your proxy in settings to get started"
        elif state == "connecting":
            explanation = f"Reaching {status['proxy']}…"
        detail = status.get("error") if state in ("unreachable", "error") else None
        self._apply_state(state, explanation, detail)

        self.values["proxy"].set_text(status["proxy"] or "Not set")
        ip = status.get("public_ip")
        if ip and status.get("country"):
            ip = f"{ip}  ·  {status['country']}"
        self.values["ip"].set_text(ip or "—")
        latency = status.get("latency_ms")
        self.values["latency"].set_text(f"{latency} ms" if latency is not None and state == "connected" else "—")

        self.kill_switch.set_sensitive(True)
        if self.kill_switch.get_active() != status["kill_switch"]:
            self.kill_switch.handler_block(self._kill_handler)
            self.kill_switch.set_active(status["kill_switch"])
            self.kill_switch.handler_unblock(self._kill_handler)

        stats = status["stats"]
        now = GLib.get_monotonic_time() / 1e6
        if self._last_stats and status["firewall_active"]:
            then, up, down = self._last_stats
            span = max(now - then, 0.2)
            self.footer.set_text(
                f"↓ {human_bytes(max(stats['down'] - down, 0) / span)}/s    "
                f"↑ {human_bytes(max(stats['up'] - up, 0) / span)}/s    "
                f"{stats['active']} open")
        else:
            self.footer.set_text("")
        self._last_stats = (now, stats["up"], stats["down"])

    def _apply_state(self, state, explanation=None, detail=None):
        headline, css, colour, _icon, default_text = STATES[state]
        context = self.state_label.get_style_context()
        for name in ("on", "wait", "bad", "off"):
            context.remove_class(name)
        context.add_class(css)
        self.state_label.set_text(headline)
        self.sub_label.set_text(explanation or default_text)
        self.error_label.set_text(detail or "")
        self.error_label.set_visible(bool(detail))
        self.power.set_visual(colour, lit=state in ("connected", "unreachable", "blocked", "error"),
                              spinning=state == "connecting" or self._busy)
        self.power.set_sensitive(state != "stopped")
        if state != self.state:
            previous, self.state = self.state, state
            self.on_state_change(previous, state)

    # ------------------------------------------------------------ actions
    def _on_power(self, _button):
        status = self.status
        if status is None or self._busy:
            return
        if not status["proxy_configured"]:
            self.show_settings()
            return
        self.toggle()

    def toggle(self):
        if self.status is None or self._busy:
            return
        disconnect = self.status["enabled"]
        self._busy = True
        self.power.set_visual(AMBER, lit=False, spinning=True)
        self.worker.submit(lambda client: client.disconnect() if disconnect else client.connect(),
                           self._after_action)

    def _after_action(self, _result, error):
        self._busy = False
        self._polling = False
        self.poll()
        if error is not None and not isinstance(error, DaemonUnavailable):
            self.error_label.set_text(str(error))
            self.error_label.show()
        return False

    def _on_kill_switch(self, switch, _param):
        value = switch.get_active()
        self.worker.submit(lambda client: client.set_config({"kill_switch": value}), self._after_action)

    # ------------------------------------------------------------ settings logic
    def _fill_settings(self, cfg, error):
        if error is not None:
            self._settings_message(["The service is not running" if isinstance(error, DaemonUnavailable)
                                    else str(error)])
            return False
        self._loading = True
        proxy = cfg["proxy"]
        (self.type_http if proxy["type"] == "http" else self.type_socks).set_active(True)
        self.host.set_text(proxy["host"])
        self.port.set_text(str(proxy["port"]))
        self.username.set_text(proxy["username"])
        self.password.set_text("")
        self.password.set_visibility(False)
        self.password.set_placeholder_text(
            "Password saved — type to replace" if proxy.get("password_set") else "Password (optional)")
        self._password_dirty = False
        buffer = self.exclude.get_buffer()
        buffer.set_text("\n".join(cfg["exclude"]))
        buffer.place_cursor(buffer.get_start_iter())
        self.allow_lan.set_active(cfg["allow_lan"])
        self.autostart.set_active(os.path.exists(AUTOSTART_FILE))
        self._loading = False
        self.save.set_sensitive(True)
        return False

    def _on_password_changed(self, _entry):
        if not self._loading:
            self._password_dirty = True

    def _split_host(self, *_args):
        """`socks5://user:pass@host:port` or `host:port` typed or pasted into the
        address box is spread over the right fields (when the box loses focus)."""
        text = self.host.get_text().strip()
        if self._loading or not text:
            return False
        has_scheme, has_user = "://" in text, "@" in text
        plain_port = text.count(":") == 1 and text.rsplit(":", 1)[1].isdigit()
        if not (has_scheme or has_user or plain_port):
            return False
        try:
            proxy = config.parse_proxy_url(text)
        except config.ConfigError:
            return False
        self._loading = True
        if has_scheme:
            (self.type_http if proxy["type"] == "http" else self.type_socks).set_active(True)
        if has_scheme or plain_port or ":" in text.rsplit("@", 1)[-1]:
            self.port.set_text(str(proxy["port"]))
        if proxy["username"]:
            self.username.set_text(proxy["username"])
            self.password.set_text(proxy["password"])
            self._password_dirty = True
        self.host.set_text(proxy["host"])
        self._loading = False
        return False

    def _settings_message(self, lines):
        self.settings_error.set_text("\n".join(lines))
        self.settings_error.set_visible(bool(lines))

    def _on_save(self, _button):
        self._split_host()
        buffer = self.exclude.get_buffer()
        text = buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), False)
        username = self.username.get_text().strip()
        password = self.password.get_text() if self._password_dirty else None
        if not username:
            password = ""
        port = self.port.get_text().strip()
        patch = {
            "proxy": {
                "type": "http" if self.type_http.get_active() else "socks5",
                "host": self.host.get_text().strip(),
                "port": int(port) if port.isdigit() else (port or 1080),
                "username": username,
                "password": password,
            },
            "exclude": [line.strip() for line in text.replace(",", "\n").splitlines() if line.strip()],
            "allow_lan": self.allow_lan.get_active(),
        }
        autostart = self.autostart.get_active()
        self.save.set_sensitive(False)
        self._settings_message([])
        self.worker.submit(lambda client: client.set_config(patch),
                           lambda cfg, error: self._after_save(cfg, error, autostart))

    def _after_save(self, _cfg, error, autostart):
        self.save.set_sensitive(True)
        if error is not None:
            if isinstance(error, DaemonUnavailable):
                self._settings_message(["The service is not running"])
            else:
                self._settings_message([m[:1].upper() + m[1:] for m in getattr(error, "errors", [str(error)])])
            return False
        try:
            if autostart:
                os.makedirs(os.path.dirname(AUTOSTART_FILE), exist_ok=True)
                with open(AUTOSTART_FILE, "w", encoding="utf-8") as handle:
                    handle.write(AUTOSTART_ENTRY)
            elif os.path.exists(AUTOSTART_FILE):
                os.unlink(AUTOSTART_FILE)
        except OSError as exc:
            self._settings_message([f"Could not change the login setting: {exc}"])
            return False
        self.show_main()
        self._polling = False
        self.poll()
        return False


def load_css():
    provider = Gtk.CssProvider()
    provider.load_from_path(os.path.join(HERE, "style.css"))
    Gtk.StyleContext.add_provider_for_screen(Gdk.Screen.get_default(), provider,
                                             Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION + 1)


class Tray:
    """Status icon: XApp on Cinnamon/MATE/Xfce, AppIndicator elsewhere."""

    def __init__(self, app):
        self.app = app
        self.icon = None
        self.kind = None
        self.menu = Gtk.Menu()
        self.status_item = Gtk.MenuItem(label=APP_NAME)
        self.status_item.set_sensitive(False)
        self.toggle_item = Gtk.MenuItem(label="Connect")
        self.toggle_item.connect("activate", lambda *_: app.panel.toggle())
        show = Gtk.MenuItem(label="Open ProxyWall")
        show.connect("activate", lambda *_: app.present())
        leave = Gtk.MenuItem(label="Quit (the connection stays as it is)")
        leave.connect("activate", lambda *_: app.quit())
        for item in (self.status_item, Gtk.SeparatorMenuItem(), self.toggle_item, show,
                     Gtk.SeparatorMenuItem(), leave):
            self.menu.append(item)
        self.menu.show_all()
        try:
            gi.require_version("XApp", "1.0")
            from gi.repository import XApp
            self.icon = XApp.StatusIcon()
            self.icon.set_name("proxywall")
            self.icon.set_secondary_menu(self.menu)
            self.icon.connect("activate", self._on_activate)
            self.kind = "xapp"
        except (ValueError, ImportError, AttributeError):
            try:
                gi.require_version("AyatanaAppIndicator3", "0.1")
                from gi.repository import AyatanaAppIndicator3 as AppIndicator
                self.icon = AppIndicator.Indicator.new(
                    "proxywall", "proxywall", AppIndicator.IndicatorCategory.APPLICATION_STATUS)
                self.icon.set_status(AppIndicator.IndicatorStatus.ACTIVE)
                self.icon.set_menu(self.menu)
                self.kind = "indicator"
            except (ValueError, ImportError, AttributeError):
                self.icon = None
        self.update("stopped", None)

    @property
    def available(self):
        return self.icon is not None

    def _on_activate(self, _icon, button, _time):
        if button == 1:
            self.app.toggle_window()

    def update(self, state, status):
        headline, _css, _colour, icon, text = STATES[state]
        self.status_item.set_label(f"{APP_NAME}: {headline.capitalize()}")
        self.toggle_item.set_label("Disconnect" if status and status["enabled"] else "Connect")
        self.toggle_item.set_sensitive(bool(status and status["proxy_configured"]))
        if self.icon is None:
            return
        path = icon_path(f"proxywall-tray-{icon}")
        if self.kind == "xapp":
            self.icon.set_icon_name(path or "proxywall")
            self.icon.set_tooltip_text(f"{APP_NAME}: {text}")
        elif path:
            self.icon.set_icon_theme_path(os.path.dirname(path))
            self.icon.set_icon_full(os.path.splitext(os.path.basename(path))[0], text)


class Application(Gtk.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.HANDLES_COMMAND_LINE)
        self.add_main_option("hidden", 0, GLib.OptionFlags.NONE, GLib.OptionArg.NONE,
                             "Start in the tray without opening the window", None)
        self.add_main_option("version", ord("v"), GLib.OptionFlags.NONE, GLib.OptionArg.NONE,
                             "Print the version and exit", None)
        self.window = None
        self.panel = None
        self.tray = None

    def do_handle_local_options(self, options):
        if options.contains("version"):
            print(f"proxywall-gui {__version__}")
            return 0
        return -1

    def do_startup(self):
        Gtk.Application.do_startup(self)
        settings = Gtk.Settings.get_default()
        if settings is not None:
            settings.set_property("gtk-application-prefer-dark-theme", True)
        load_css()
        app_icon = icon_path("proxywall")
        if app_icon:
            try:
                Gtk.Window.set_default_icon_from_file(app_icon)
            except GLib.Error:
                pass
        else:
            Gtk.Window.set_default_icon_name("proxywall")

        self.panel = Panel(Worker(), self._on_state_change)
        self.window = Gtk.ApplicationWindow(application=self, title=APP_NAME)
        self.window.get_style_context().add_class("pw-root")
        self.window.set_titlebar(self.panel.header)
        self.window.add(self.panel.stack)
        self.window.set_default_size(372, 660)
        self.window.set_resizable(False)
        self.window.set_position(Gtk.WindowPosition.CENTER)
        self.window.connect("delete-event", self._on_close)
        self.window.connect("key-press-event", self._on_key)
        self.panel.header.show_all()
        self.panel.stack.show_all()

        self.tray = Tray(self)
        if self.tray.available:
            self.hold()  # keep running in the tray when the window is closed
        self.panel.poll()
        GLib.timeout_add(1000, self.panel.poll)

    def do_command_line(self, command_line):
        hidden = command_line.get_options_dict().contains("hidden")
        if not (hidden and self.tray.available and not command_line.get_is_remote()):
            self.present()
        return 0

    def do_activate(self):
        self.present()

    def present(self):
        self.window.show()
        self.window.present()

    def toggle_window(self):
        if self.window.get_visible() and self.window.is_active():
            self.window.hide()
        else:
            self.present()

    def _on_close(self, *_args):
        if self.tray.available:
            self.window.hide()
            return True
        return False

    def _on_key(self, _window, event):
        if event.keyval == Gdk.KEY_Escape and self.panel.stack.get_visible_child_name() == "settings":
            self.panel.show_main()
            return True
        return False

    def _on_state_change(self, previous, state):
        if self.tray is None or self.panel is None:
            return  # still starting up
        self.tray.update(state, self.panel.status)
        messages = {
            ("connected", "unreachable"): ("Proxy unreachable", "Your traffic is blocked until the proxy is back."),
            ("unreachable", "connected"): ("Connected again", "Traffic is flowing through the proxy."),
            ("connecting", "unreachable"): ("Proxy unreachable", "Your traffic is blocked until the proxy answers."),
        }
        if (previous, state) in messages:
            title, body = messages[(previous, state)]
            notification = Gio.Notification.new(title)
            notification.set_body(body)
            self.send_notification("state", notification)


def main(argv=None):
    GLib.set_prgname("proxywall-gui")
    GLib.set_application_name(APP_NAME)
    return Application().run(sys.argv if argv is None else argv)


if __name__ == "__main__":
    sys.exit(main())
