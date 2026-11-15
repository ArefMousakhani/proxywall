"""Light and dark looks: the two palettes, the saved choice, and what "system" means.

Nothing here needs GTK, so it can be tested anywhere. `app.py` applies the result.
"""

import json
import os

CHOICES = ("system", "light", "dark")
STYLE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "style.css")

# Names used by style.css. `pw_ink` is the colour overlays are made of (hover,
# dividers, scrollbars): white on the dark surface, navy on the light one.
PALETTES = {
    "dark": {
        "pw_bg": "#0e1526",
        "pw_text": "#e8edf7",
        "pw_muted": "#8f9bb3",
        "pw_faint": "#6f7c96",
        "pw_soft": "#c9d3e6",
        "pw_strong": "#ffffff",
        "pw_ink": "#ffffff",
        "pw_card": "rgba(255, 255, 255, 0.045)",
        "pw_card_border": "rgba(255, 255, 255, 0.06)",
        "pw_field": "rgba(255, 255, 255, 0.06)",
        "pw_field_border": "rgba(255, 255, 255, 0.10)",
        "pw_track": "rgba(255, 255, 255, 0.16)",
        "pw_on": "#2fd47f",
        "pw_wait": "#f6b73c",
        "pw_bad": "#ff6b6b",
        "pw_error": "#ff8f8f",
        "pw_off": "#9aa6bd",
        "pw_action": "#2f7bff",
        "pw_action_hover": "#4a8cff",
        "placeholder_text_color": "#6f7c96",
    },
    "light": {
        "pw_bg": "#f2f4f9",
        "pw_text": "#1a2338",
        "pw_muted": "#5b6781",
        "pw_faint": "#7a869d",
        "pw_soft": "#3b4761",
        "pw_strong": "#0e1526",
        "pw_ink": "#16203a",
        "pw_card": "#ffffff",
        "pw_card_border": "rgba(22, 32, 58, 0.10)",
        "pw_field": "#ffffff",
        "pw_field_border": "rgba(22, 32, 58, 0.18)",
        "pw_track": "rgba(22, 32, 58, 0.24)",
        "pw_on": "#0d9a55",
        "pw_wait": "#b57800",
        "pw_bad": "#d43a3a",
        "pw_error": "#c22f2f",
        "pw_off": "#6f7c96",
        "pw_action": "#2468e8",
        "pw_action_hover": "#3b7bf2",
        "placeholder_text_color": "#8b95a9",
    },
}

# The same looks for what the window draws itself (map, power button, marks):
# red, green, blue from 0 to 1. `disc` is the power button's face, top to bottom;
# `gap` the ring between the point on the map and its outline (the card's colour).
DRAWING = {
    "dark": {
        "ink": (1.0, 1.0, 1.0),
        "gap": (0.055, 0.082, 0.149),
        "disc": ((0.135, 0.185, 0.30), (0.085, 0.12, 0.205)),
        "disc_hover": ((0.16, 0.215, 0.34), (0.10, 0.14, 0.235)),
        "land": 0.13,
        "on": (0.184, 0.831, 0.498),
        "wait": (0.965, 0.718, 0.235),
        "bad": (1.0, 0.42, 0.42),
        "off": (0.47, 0.53, 0.64),
    },
    "light": {
        "ink": (0.086, 0.125, 0.227),
        "gap": (1.0, 1.0, 1.0),
        "disc": ((1.0, 1.0, 1.0), (0.905, 0.925, 0.96)),
        "disc_hover": ((1.0, 1.0, 1.0), (0.94, 0.955, 0.98)),
        "land": 0.17,
        "on": (0.07, 0.66, 0.375),
        "wait": (0.87, 0.60, 0.05),
        "bad": (0.87, 0.26, 0.26),
        "off": (0.55, 0.60, 0.69),
    },
}


def choice_file():
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "proxywall", "gui.json")


def load_choice(path=None):
    """The look the user picked: "system" (also when nothing or nonsense is saved), "light" or "dark"."""
    try:
        with open(path or choice_file(), encoding="utf-8") as handle:
            choice = json.load(handle).get("theme")
    except (OSError, ValueError, AttributeError):
        return "system"
    return choice if choice in CHOICES else "system"


def save_choice(choice, path=None):
    if choice not in CHOICES:
        raise ValueError(f"unknown look: {choice!r}")
    path = path or choice_file()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            data = {}
    except (OSError, ValueError):
        data = {}
    data["theme"] = choice
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")
    os.replace(temporary, path)


def system_is_dark(colour_scheme=None, theme_name="", prefers_dark=False):
    """Does the desktop ask for a dark look?

    *colour_scheme* is the desktop portal's answer (1 dark, 2 light, 0 or
    None: no opinion). Without an opinion the GTK theme decides: a theme
    whose name says "dark", or the classic "prefer dark" setting.
    """
    if colour_scheme == 1:
        return True
    if colour_scheme == 2:
        return False
    return bool(prefers_dark) or "dark" in (theme_name or "").lower()


def resolve(choice, system_dark):
    """"dark" or "light" for a choice; "system" follows the desktop."""
    if choice in ("light", "dark"):
        return choice
    return "dark" if system_dark else "light"


def stylesheet(look):
    """The complete CSS for a look: its colour names, then style.css."""
    names = "".join(f"@define-color {name} {value};\n" for name, value in PALETTES[look].items())
    with open(STYLE_FILE, encoding="utf-8") as handle:
        return names + handle.read()
