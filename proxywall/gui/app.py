"""ProxyWall desktop interface (GTK 3).

The window is only a remote control: connecting, the firewall and all traffic
handling live in the system service, so closing the window changes nothing.
"""

import math
import os
import queue
import re
import sys
import threading

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
gi.require_version("GdkPixbuf", "2.0")
from gi.repository import Gdk, GdkPixbuf, Gio, GLib, Gtk, Pango  # noqa: E402

from .. import APP_ID, APP_NAME, __version__, config, geo, links  # noqa: E402
from ..geodata import COUNTRIES, LAND  # noqa: E402
from ..cli import human_bytes  # noqa: E402
from ..client import Client, DaemonUnavailable  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ICON_DIRS = (os.path.join(HERE, "..", "..", "data", "icons"), "/usr/share/proxywall/icons")
FLAG_DIRS = (os.path.join(HERE, "..", "..", "data", "flags"), "/usr/share/proxywall/flags")
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
    "country_blocked": ("COUNTRY BLOCKED", "bad", RED, "blocked", "Nothing is sent while the proxy comes out there"),
    "checking": ("CHECKING", "wait", AMBER, "wait", "Checking the exit country. Traffic waits."),
    "blocked": ("BLOCKED", "bad", RED, "blocked", "Firewall is on: connect to use the internet"),
    "disconnected": ("OFF", "off", GREY, "off", "Your traffic is not using the proxy"),
    "error": ("ERROR", "bad", RED, "blocked", "Something went wrong"),
    "stopped": ("SERVICE STOPPED", "off", GREY, "off", "Start it with: sudo systemctl start proxywall"),
}


TRAY_FLAG_STYLE = "v1"  # part of the cached file name: change it when the drawing changes


def icon_path(name):
    for directory in ICON_DIRS:
        path = os.path.abspath(os.path.join(directory, name + ".svg"))
        if os.path.exists(path):
            return path
    return None


_flags = {}


def flag_pixbuf(code):
    """The flag of an ISO country code as a pixbuf, or None."""
    if not isinstance(code, str) or not re.fullmatch(r"[A-Za-z]{2}", code):
        return None
    code = code.lower()
    if code not in _flags:
        _flags[code] = None
        for directory in FLAG_DIRS:
            path = os.path.join(directory, code + ".png")
            if os.path.exists(path):
                try:
                    _flags[code] = GdkPixbuf.Pixbuf.new_from_file(path)
                except GLib.Error:
                    pass
                break
    return _flags[code]


def _rounded(cr, x, y, width, height, radius):
    cr.new_sub_path()
    cr.arc(x + width - radius, y + radius, radius, -math.pi / 2, 0)
    cr.arc(x + width - radius, y + height - radius, radius, 0, math.pi / 2)
    cr.arc(x + radius, y + height - radius, radius, math.pi / 2, math.pi)
    cr.arc(x + radius, y + radius, radius, math.pi, 1.5 * math.pi)
    cr.close_path()


def _paint_flag(cr, pixbuf, x, y, width, height, radius):
    cr.save()
    _rounded(cr, x, y, width, height, radius)
    cr.clip()
    cr.translate(x, y)
    cr.scale(width / pixbuf.get_width(), height / pixbuf.get_height())
    Gdk.cairo_set_source_pixbuf(cr, pixbuf, 0, 0)
    cr.paint()
    cr.restore()


def draw_tray_flag(pixbuf, size=48, colour=None):
    """The panel icon: a flag inside a coloured frame (green unless told otherwise)."""
    import cairo
    unit = size / 48
    height = 38 * unit  # frame around a 4:3 flag
    border, top = 3.5 * unit, (size - height) / 2
    surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, size, size)
    cr = cairo.Context(surface)
    cr.set_source_rgb(*(colour or GREEN))
    _rounded(cr, 0, top, size, height, 8 * unit)
    cr.fill()
    _paint_flag(cr, pixbuf, border, top + border, size - 2 * border, height - 2 * border, 4.5 * unit)
    return surface


def tray_flag_icon(code, blocked=False):
    """Path of a panel icon showing the flag in a green (or, blocked, red) frame, or None.

    Panels take an icon file, so the picture is composed once per country and
    kept in the user's cache directory.
    """
    pixbuf = flag_pixbuf(code)
    if pixbuf is None:
        return None
    directory = os.path.join(GLib.get_user_cache_dir(), "proxywall")
    kind = "blocked" if blocked else "on"
    path = os.path.join(directory, f"proxywall-tray-flag-{code.lower()}-{kind}-{TRAY_FLAG_STYLE}.png")
    if os.path.exists(path):
        return path
    try:
        os.makedirs(directory, exist_ok=True)
        temporary = f"{path}.{os.getpid()}.tmp"
        draw_tray_flag(pixbuf, colour=RED if blocked else GREEN).write_to_png(temporary)
        os.replace(temporary, path)
    except Exception:  # an odd cache directory must never take the tray down
        return None
    return path


class WorldMap(Gtk.DrawingArea):
    """A small dotted world map with one glowing point: where the traffic comes out."""

    WIDTH = 296

    def __init__(self):
        super().__init__()
        self._point = None
        self._colour = GREEN
        self.set_size_request(self.WIDTH, math.ceil(self.WIDTH * geo.MAP_ROWS / geo.MAP_COLS))
        self.connect("draw", self._draw)

    def set_point(self, latitude=None, longitude=None, colour=GREEN):
        point = None if latitude is None or longitude is None else (latitude, longitude)
        if (point, colour) != (self._point, self._colour):
            self._point, self._colour = point, colour
            self.queue_draw()

    def _draw(self, area, cr):
        import cairo
        width, height = area.get_allocated_width(), area.get_allocated_height()
        pitch = min(width / geo.MAP_COLS, height / geo.MAP_ROWS)
        left = (width - geo.MAP_COLS * pitch) / 2
        top = (height - geo.MAP_ROWS * pitch) / 2
        radius = pitch * 0.30
        for row, line in enumerate(LAND):
            cy = top + (row + 0.5) * pitch
            for column, cell in enumerate(line):
                if cell == "#":
                    cx = left + (column + 0.5) * pitch
                    cr.new_sub_path()
                    cr.arc(cx, cy, radius, 0, 2 * math.pi)
        cr.set_source_rgba(1, 1, 1, 0.20 if self._point else 0.13)
        cr.fill()
        if self._point is None:
            return False
        column, row = geo.map_cell(*self._point)
        cx = min(max(left + column * pitch, 6), width - 6)
        cy = min(max(top + row * pitch, 6), height - 6)
        r, g, b = self._colour
        halo = cairo.RadialGradient(cx, cy, 2, cx, cy, 17)
        halo.add_color_stop_rgba(0, r, g, b, 0.45)
        halo.add_color_stop_rgba(1, r, g, b, 0.0)
        cr.set_source(halo)
        cr.arc(cx, cy, 17, 0, 2 * math.pi)
        cr.fill()
        cr.set_source_rgba(r, g, b, 0.55)
        cr.set_line_width(1.2)
        cr.arc(cx, cy, 7.5, 0, 2 * math.pi)
        cr.stroke()
        cr.set_source_rgb(0.055, 0.082, 0.149)
        cr.arc(cx, cy, 4.6, 0, 2 * math.pi)
        cr.fill()
        cr.set_source_rgb(r, g, b)
        cr.arc(cx, cy, 3.3, 0, 2 * math.pi)
        cr.fill()
        return False


class FlagView(Gtk.DrawingArea):
    """A small flag with rounded corners."""

    def __init__(self, width=24, height=18):
        super().__init__()
        self._pixbuf = None
        self.set_size_request(width, height)
        self.set_valign(Gtk.Align.CENTER)
        self.set_no_show_all(True)
        self.connect("draw", self._draw)

    def set_country(self, code):
        pixbuf = flag_pixbuf(code)
        if pixbuf is not self._pixbuf:
            self._pixbuf = pixbuf
            self.queue_draw()
        self.set_visible(pixbuf is not None)

    def _draw(self, area, cr):
        if self._pixbuf is not None:
            width, height = area.get_allocated_width(), area.get_allocated_height()
            _paint_flag(cr, self._pixbuf, 0, 0, width, height, 3.5)
            cr.set_source_rgba(1, 1, 1, 0.18)
            cr.set_line_width(1)
            _rounded(cr, 0.5, 0.5, width - 1, height - 1, 3.5)
            cr.stroke()
        return False


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

    SIZE = 150

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

    def __init__(self, worker, on_state_change=None, on_country_change=None):
        self.worker = worker
        self.on_state_change = on_state_change or (lambda *_: None)
        self.on_country_change = on_country_change or (lambda *_: None)
        self.country = None
        self._blocked = set()          # country codes being edited in the settings
        self._gate_supported = False   # does the running service know about blocked countries
        self._countries_filled = False
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
        self.back.connect("clicked", lambda *_: self.go_back())
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
        self.stack.add_named(self._build_countries(), "countries")
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

        location = _card()
        location.set_margin_top(18)
        self.map = WorldMap()
        location.pack_start(self.map, False, False, 0)
        row = Gtk.Box(spacing=8)
        self.flag = FlagView()
        row.pack_start(self.flag, False, False, 0)
        self.place = _label("", "pw-value")
        self.place.set_ellipsize(Pango.EllipsizeMode.END)
        row.pack_start(self.place, True, True, 0)
        self.coordinates = _label("", "pw-key", 1.0, selectable=True)
        row.pack_end(self.coordinates, False, False, 0)
        location.pack_start(row, False, False, 0)
        page.pack_start(location, False, False, 0)

        info = _card()
        info.set_margin_top(12)
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
        self.type_ssh = Gtk.RadioButton.new_with_label_from_widget(self.type_socks, "SSH")
        self.type_link = Gtk.RadioButton.new_with_label_from_widget(self.type_socks, "LINK")
        self.type_link.set_tooltip_text("VLESS, VMess, Trojan or Shadowsocks: paste the share link")
        for button in (self.type_socks, self.type_http, self.type_ssh, self.type_link):
            button.set_mode(False)
            button.connect("toggled", self._on_type_changed)
            segment.pack_start(button, True, True, 0)
        page.pack_start(segment, False, False, 0)

        # Share link (VLESS, VMess, Trojan, Shadowsocks): one box instead of the form.
        self.link = Gtk.Entry(placeholder_text="vless://  vmess://  trojan://  ss://")
        self.link.set_input_purpose(Gtk.InputPurpose.URL)
        self.link.set_no_show_all(True)
        self.link.connect("changed", self._on_link_changed)
        page.pack_start(self.link, False, False, 0)
        self.link_hint = _label("", "pw-key", wrap=True)
        self.link_hint.set_no_show_all(True)
        page.pack_start(self.link_hint, False, False, 0)

        address = Gtk.Box(spacing=8)
        self.address_row = address
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

        # SSH only: a private key instead of (or next to) the password.
        self.key_row = Gtk.Box(spacing=8)
        self.key_row.set_no_show_all(True)
        self.key_button = Gtk.Button()
        self.key_button.get_style_context().add_class("pw-rowbutton")
        self.key_label = _label("", "pw-key")
        self.key_label.set_ellipsize(Pango.EllipsizeMode.MIDDLE)
        self.key_button.add(self.key_label)
        self.key_button.connect("clicked", self._choose_key)
        self.key_row.pack_start(self.key_button, True, True, 0)
        self.key_clear = Gtk.Button.new_from_icon_name("edit-clear-symbolic", Gtk.IconSize.MENU)
        self.key_clear.get_style_context().add_class("pw-rowbutton")
        self.key_clear.set_tooltip_text("Do not use a private key")
        self.key_clear.connect("clicked", lambda *_: self._set_key(""))
        self.key_row.pack_start(self.key_clear, False, False, 0)
        page.pack_start(self.key_row, False, False, 0)
        self._key = None         # None: keep what the service has; "": none; text: a new key
        self._key_saved = False
        self._link_saved = ""    # description of the link the service has, if any

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

        section("BLOCKED COUNTRIES")
        self.countries_button = Gtk.Button()
        self.countries_button.get_style_context().add_class("pw-rowbutton")
        self.countries_button.get_accessible().set_name("Choose blocked countries")
        row = Gtk.Box(spacing=8)
        self.countries_flags = Gtk.Box(spacing=4)
        self.countries_flags.set_valign(Gtk.Align.CENTER)
        row.pack_start(self.countries_flags, False, False, 0)
        self.countries_label = _label("None", "pw-value")
        self.countries_label.set_ellipsize(Pango.EllipsizeMode.END)
        row.pack_start(self.countries_label, True, True, 0)
        row.pack_end(Gtk.Image.new_from_icon_name("go-next-symbolic", Gtk.IconSize.MENU), False, False, 0)
        self.countries_button.add(row)
        self.countries_button.connect("clicked", lambda *_: self.show_countries())
        page.pack_start(self.countries_button, False, False, 0)
        page.pack_start(_label("Nothing is sent while the proxy comes out in one of these countries.",
                               "pw-key", wrap=True), False, False, 0)

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

    # ------------------------------------------------------------ countries page
    def _build_countries(self):
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        page.set_border_width(20)
        self.country_search = Gtk.SearchEntry(placeholder_text="Search countries")
        self.country_search.connect("search-changed", lambda *_: self.country_list.invalidate_filter())
        page.pack_start(self.country_search, False, False, 0)

        frame = Gtk.Box()
        frame.get_style_context().add_class("pw-textframe")
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.country_list = Gtk.ListBox()
        self.country_list.get_style_context().add_class("pw-countries")
        self.country_list.set_selection_mode(Gtk.SelectionMode.NONE)
        self.country_list.set_activate_on_single_click(True)
        self.country_list.set_filter_func(self._country_filter)
        self.country_list.set_sort_func(self._country_sort)
        self.country_list.connect("row-activated", self._on_country_row)
        self.country_list.get_accessible().set_name("Countries to block")
        scroller.add(self.country_list)
        frame.pack_start(scroller, True, True, 0)
        page.pack_start(frame, True, True, 0)

        self.countries_done = Gtk.Button(label="Done")
        self.countries_done.get_style_context().add_class("pw-primary")
        self.countries_done.connect("clicked", lambda *_: self.go_back())
        page.pack_start(self.countries_done, False, False, 0)
        self._country_ticks = {}
        self._country_top = frozenset()
        return page

    def _fill_countries(self):
        """Built on first use: 250 rows are not worth paying for at start-up."""
        self._countries_filled = True
        for code, (name, _latitude, _longitude) in COUNTRIES.items():
            row = Gtk.ListBoxRow()
            row.set_name(code)
            box = Gtk.Box(spacing=10)
            flag = FlagView(26, 19)
            flag.set_country(code)
            box.pack_start(flag, False, False, 0)
            box.pack_start(_label(name, "pw-country"), True, True, 0)
            tick = Gtk.Image.new_from_icon_name("object-select-symbolic", Gtk.IconSize.MENU)
            tick.get_style_context().add_class("pw-tick")
            tick.set_no_show_all(True)
            box.pack_end(tick, False, False, 0)
            row.add(box)
            row.show_all()
            self._country_ticks[code] = tick
            self.country_list.add(row)

    def _country_filter(self, row):
        text = self.country_search.get_text().strip().lower()
        code = row.get_name()
        return not text or text == code.lower() or text in COUNTRIES[code][0].lower()

    def _country_sort(self, first, second):
        def key(row):
            code = row.get_name()
            return (code not in self._country_top, COUNTRIES[code][0])
        a, b = key(first), key(second)
        return (a > b) - (a < b)

    def _on_country_row(self, _list, row):
        code = row.get_name()
        self._blocked.symmetric_difference_update({code})
        self._show_blocked()

    def _show_blocked(self):
        """Bring every view of the selection in line with `self._blocked`."""
        chosen = sorted(self._blocked, key=lambda code: COUNTRIES[code][0])
        for code, tick in self._country_ticks.items():
            tick.set_visible(code in self._blocked)
        self.countries_done.set_label(f"Done  ·  {len(chosen)} blocked" if chosen else "Done")
        for child in self.countries_flags.get_children():
            self.countries_flags.remove(child)
        for code in chosen[:4]:
            flag = FlagView(22, 16)
            flag.set_country(code)
            self.countries_flags.pack_start(flag, False, False, 0)
        self.countries_flags.set_visible(bool(chosen))
        names = ", ".join(COUNTRIES[code][0] for code in chosen)
        self.countries_label.set_text(names or "None")
        self.countries_label.set_tooltip_text(names or None)
        context = self.countries_label.get_style_context()
        (context.remove_class if chosen else context.add_class)("pw-dim")

    def show_countries(self):
        if not self._countries_filled:
            self._fill_countries()
        self._country_top = frozenset(self._blocked)  # chosen ones first, as they were on opening
        self.country_search.set_text("")
        self.country_list.invalidate_sort()
        self.country_list.invalidate_filter()
        self._show_blocked()
        self.stack.set_visible_child_name("countries")
        self.title.set_text("BLOCK COUNTRIES")
        adjustment = self.country_list.get_parent().get_parent().get_vadjustment()
        adjustment.set_value(adjustment.get_lower())

    def go_back(self):
        if self.stack.get_visible_child_name() == "countries":
            self.stack.set_visible_child_name("settings")
            self.title.set_text("SETTINGS")
        else:
            self.show_main()

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
        self._render_location({}, "stopped")
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
        detail = status.get("error") if state in ("unreachable", "error", "country_blocked", "checking") else None
        self._apply_state(state, explanation, detail)

        self.values["proxy"].set_text(status["proxy"] or "Not set")
        ip = status.get("public_ip")
        if ip and status.get("country"):
            ip = f"{ip}  ·  {status['country']}"
        self.values["ip"].set_text(ip or "—")
        latency = status.get("latency_ms")
        self.values["latency"].set_text(f"{latency} ms" if latency is not None and state == "connected" else "—")
        self._render_location(status, state)

        blocked = status.get("blocked_countries") or []
        hint = "Never go online without the proxy"
        if blocked:
            hint = "Blocks exits in " + ", ".join(blocked[:5]) + (f" +{len(blocked) - 5}" if len(blocked) > 5 else "")
        self.firewall_hint.set_text(hint)
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

    def _render_location(self, status, state):
        connected = state in ("connected", "country_blocked")
        country = status.get("country") if connected else None
        latitude, longitude = (status.get("latitude"), status.get("longitude")) if connected else (None, None)
        place = geo.format_place(status) if connected else None
        self.flag.set_country(country)
        if latitude is not None and longitude is not None:
            self.map.set_point(latitude, longitude, RED if state == "country_blocked" else GREEN)
            text = geo.format_coordinates(latitude, longitude)
            self.coordinates.set_text(text if status.get("location_exact") else "≈ " + text)
            self.coordinates.set_tooltip_text(
                "Where your traffic comes out" if status.get("location_exact")
                else "Only the country is known: this is its capital")
        else:
            self.map.set_point()
            self.coordinates.set_text("")
            self.coordinates.set_tooltip_text(None)
        if connected:
            self.place.set_text(place or ("Finding the location…" if status.get("public_ip") else "Location unknown"))
        else:
            self.place.set_text({"connecting": "Connecting…", "checking": "Checking the exit country…",
                                 "stopped": "—"}.get(state, "Not connected"))
        self.place.set_tooltip_text(place)
        context = self.place.get_style_context()
        (context.remove_class if place else context.add_class)("pw-dim")
        if country != self.country:
            self.country = country
            self.on_country_change()

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
        self.power.set_visual(colour, lit=state in ("connected", "unreachable", "blocked", "error", "country_blocked"),
                              spinning=state in ("connecting", "checking") or self._busy)
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
        by_link = proxy["type"] in links.ENGINE_KINDS
        self._type_button("link" if by_link else proxy["type"]).set_active(True)
        self.host.set_text("" if by_link else proxy["host"])
        self.port.set_text("" if by_link else str(proxy["port"]))
        self.username.set_text(proxy["username"])
        self.link.set_text("")
        self._link_saved = ""
        if by_link and proxy.get("link_set"):
            self._link_saved = " · ".join(part for part in (
                proxy["type"].upper(), f"{proxy['host']}:{proxy['port']}", proxy.get("name")) if part)
        self._key, self._key_saved = None, bool(proxy.get("key_set"))
        self.password.set_text("")
        self.password.set_visibility(False)
        self.password.set_placeholder_text(
            "Password saved — type to replace" if proxy.get("password_set") else "Password (optional)")
        self._password_dirty = False
        buffer = self.exclude.get_buffer()
        buffer.set_text("\n".join(cfg["exclude"]))
        buffer.place_cursor(buffer.get_start_iter())
        self._gate_supported = "blocked_countries" in cfg
        self._blocked = {code for code in cfg.get("blocked_countries", []) if code in COUNTRIES}
        self.countries_button.set_sensitive(self._gate_supported)
        self._show_blocked()
        self.allow_lan.set_active(cfg["allow_lan"])
        self.autostart.set_active(os.path.exists(AUTOSTART_FILE))
        self._on_type_changed()
        self._loading = False
        self.save.set_sensitive(True)
        return False

    # ------------------------------------------------------------ kinds of server
    def _type_button(self, kind):
        return {"http": self.type_http, "ssh": self.type_ssh, "link": self.type_link}.get(kind, self.type_socks)

    def _proxy_type(self):
        for kind in ("http", "ssh", "link"):
            if self._type_button(kind).get_active():
                return kind
        return "socks5"

    def _on_type_changed(self, button=None):
        """Show the fields that belong to the chosen kind of server."""
        if button is not None and not button.get_active():
            return  # the radio button that was just switched off
        kind = self._proxy_type()
        by_link, ssh = kind == "link", kind == "ssh"
        self.link.set_visible(by_link)
        self.link_hint.set_visible(by_link)
        for widget in (self.address_row, self.username, self.password):
            widget.set_visible(not by_link)
        self.key_row.set_visible(ssh)
        self.username.set_placeholder_text("Username" if ssh else "Username (optional)")
        if not self._loading:  # a sensible port for the kind that was just chosen
            default = {"socks5": "1080", "http": "8080", "ssh": "22"}.get(kind)
            if default and self.port.get_text().strip() in ("", "1080", "8080", "22"):
                self.port.set_text(default)
        self._on_link_changed()
        self._show_key()

    def _on_link_changed(self, *_args):
        text = self.link.get_text().strip()
        self.link.set_placeholder_text("Link saved — paste a new one to replace it" if self._link_saved
                                       else "vless://  vmess://  trojan://  ss://")
        if not text:
            self.link_hint.set_text(self._link_saved or "Paste the link you were given for your server.")
            return
        try:
            server = links.parse(text)
        except links.LinkError as exc:
            message = str(exc)
            self.link_hint.set_text(message[:1].upper() + message[1:])
            return
        self.link_hint.set_text(" · ".join(part for part in (
            server["kind"].upper(), f"{server['host']}:{server['port']}",
            server["network"].upper() if server["network"] != "raw" else "",
            server["security"].upper() if server["security"] != "none" else "", server["name"]) if part))

    def _show_key(self):
        if self._key:
            text = "Private key chosen"
        elif self._key is None and self._key_saved:
            text = "Private key saved — click to replace"
        else:
            text = "Private key file (optional)…"
        self.key_label.set_text(text)
        self.key_clear.set_visible(bool(self._key) or (self._key is None and self._key_saved))

    def _set_key(self, text):
        self._key = text
        self._show_key()

    def _choose_key(self, _button):
        dialog = Gtk.FileChooserNative.new("Private key", self.stack.get_toplevel(),
                                           Gtk.FileChooserAction.OPEN, "Use this key", "Cancel")
        ssh_dir = os.path.expanduser("~/.ssh")
        if os.path.isdir(ssh_dir):
            dialog.set_current_folder(ssh_dir)
        if dialog.run() == Gtk.ResponseType.ACCEPT:
            try:
                with open(dialog.get_filename(), encoding="utf-8") as handle:
                    text = handle.read(20001)
                if "PRIVATE KEY-----" not in text or len(text) > 20000:
                    raise ValueError("that file is not a private key")
                self._set_key(text)
                self._settings_message([])
            except (OSError, ValueError) as exc:
                self._settings_message([f"Could not use that file: {exc}"])
        dialog.destroy()

    def _on_password_changed(self, _entry):
        if not self._loading:
            self._password_dirty = True

    def _split_host(self, *_args):
        """`socks5://user:pass@host:port` or `host:port` typed or pasted into the
        address box is spread over the right fields (when the box loses focus)."""
        text = self.host.get_text().strip()
        if self._loading or not text:
            return False
        if links.is_engine_link(text):  # a share link pasted into the address box
            self.host.set_text("")
            self.type_link.set_active(True)
            self.link.set_text(text)
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
            self._type_button(proxy["type"]).set_active(True)
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
        kind = self._proxy_type()
        if kind == "link":
            # Nothing typed means "keep the link the service already has".
            proxy = {"type": "link", "link": self.link.get_text().strip() or None}
        else:
            proxy = {
                "type": kind,
                "host": self.host.get_text().strip(),
                "port": int(port) if port.isdigit() else (port or {"http": 8080, "ssh": 22}.get(kind, 1080)),
                "username": username,
                "password": password,
            }
            if kind == "ssh":
                proxy["private_key"] = self._key
        patch = {
            "proxy": proxy,
            "exclude": [line.strip() for line in text.replace(",", "\n").splitlines() if line.strip()],
            "allow_lan": self.allow_lan.get_active(),
        }
        if self._gate_supported:
            patch["blocked_countries"] = sorted(self._blocked)
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
        place = geo.format_place(status) if status and state in ("connected", "country_blocked") else None
        if place:
            text = f"{text}, out in {place}" if state == "connected" else f"Blocked country: {place}"
        self.status_item.set_label(f"{APP_NAME}: {headline.capitalize()}" + (f" ({place})" if place else ""))
        self.toggle_item.set_label("Disconnect" if status and status["enabled"] else "Connect")
        self.toggle_item.set_sensitive(bool(status and status["proxy_configured"]))
        if self.icon is None:
            return
        path = None
        if status and state in ("connected", "country_blocked"):  # the flag of the exit country
            path = tray_flag_icon(status.get("country"), blocked=state != "connected")
        path = path or icon_path(f"proxywall-tray-{icon}")
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

        self.panel = Panel(Worker(), self._on_state_change, self._on_country_change)
        self.window = Gtk.ApplicationWindow(application=self, title=APP_NAME)
        self.window.get_style_context().add_class("pw-root")
        self.window.set_titlebar(self.panel.header)
        self.window.add(self.panel.stack)
        self.window.set_default_size(372, 716)
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
        if event.keyval == Gdk.KEY_Escape and self.panel.stack.get_visible_child_name() != "main":
            self.panel.go_back()
            return True
        return False

    def _on_country_change(self):
        if self.tray is not None and self.panel is not None and self.panel.state is not None:
            self.tray.update(self.panel.state, self.panel.status)

    def _on_state_change(self, previous, state):
        if self.tray is None or self.panel is None:
            return  # still starting up
        self.tray.update(state, self.panel.status)
        messages = {
            ("connected", "unreachable"): ("Proxy unreachable", "Your traffic is blocked until the proxy is back."),
            ("unreachable", "connected"): ("Connected again", "Traffic is flowing through the proxy."),
            ("connecting", "unreachable"): ("Proxy unreachable", "Your traffic is blocked until the proxy answers."),
        }
        if state == "country_blocked" and previous != "country_blocked":
            place = geo.format_place(self.panel.status or {}) or "a blocked country"
            messages[(previous, state)] = ("Blocked country", f"The proxy comes out in {place}. Nothing is sent.")
        elif previous == "country_blocked" and state == "connected":
            messages[(previous, state)] = ("Connected again", "The proxy no longer comes out in a blocked country.")
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
