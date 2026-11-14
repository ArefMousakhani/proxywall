#!/usr/bin/env python3
"""Regenerate data/flags/*.png from the flag-icons project (MIT licence).

    npm pack flag-icons && tar xzf flag-icons-*.tgz
    python3 tools/gen_flags.py package/flags/4x3
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import gi

gi.require_version("GdkPixbuf", "2.0")
from gi.repository import GdkPixbuf  # noqa: E402

from proxywall.geodata import COUNTRIES  # noqa: E402

WIDTH, HEIGHT = 80, 60
EXTRA = ("EU", "UN")


def main():
    source = sys.argv[1]
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "flags")
    os.makedirs(out, exist_ok=True)
    count = 0
    for code in sorted(set(COUNTRIES) | set(EXTRA)):
        svg = os.path.join(source, code.lower() + ".svg")
        if not os.path.exists(svg):
            print(f"no flag for {code}", file=sys.stderr)
            continue
        pixbuf = GdkPixbuf.Pixbuf.new_from_file_at_scale(svg, WIDTH, HEIGHT, False)
        pixbuf.savev(os.path.join(out, code.lower() + ".png"), "png", ["compression"], ["9"])
        count += 1
    print(f"{out}: {count} flags")


if __name__ == "__main__":
    main()
