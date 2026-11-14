#!/usr/bin/env python3
"""Regenerate proxywall/geodata.py (country table and the dotted world map).

Inputs, all public domain:
  * Natural Earth 1:110m "populated places (simple)" and "land" as GeoJSON
    (https://github.com/nvkelso/natural-earth-vector, directory geojson/)
  * the tz database tables zone.tab and iso3166.tab (/usr/share/zoneinfo)

    python3 tools/gen_geodata.py ne_110m_populated_places_simple.geojson ne_110m_land.geojson
"""

import json
import os
import re
import sys

import cairo

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
ZONEINFO = "/usr/share/zoneinfo"

# The map: plate carree, cut in the Bering Strait, without the empty polar rows.
COLS, ROWS = 75, 28
LON_LEFT, LAT_TOP, CELL = -168.0, 78.0, 4.8
SUPERSAMPLE = 10
LAND_THRESHOLD = 0.34

NAMES = {
    "BN": "Brunei", "BQ": "Caribbean Netherlands", "CC": "Cocos Islands", "CD": "DR Congo",
    "CG": "Congo", "CI": "Ivory Coast", "CZ": "Czechia", "GB": "United Kingdom",
    "KP": "North Korea", "KR": "South Korea", "MF": "Saint Martin", "MM": "Myanmar",
    "AS": "American Samoa", "WS": "Samoa", "SX": "Sint Maarten", "TL": "Timor-Leste",
    "VG": "British Virgin Islands", "VI": "US Virgin Islands", "FM": "Micronesia",
    "SH": "Saint Helena", "PS": "Palestine", "SZ": "Eswatini", "HK": "Hong Kong", "MO": "Macau",
    "TC": "Turks & Caicos Islands", "GS": "South Georgia", "UM": "US Outlying Islands",
}
EXTRA = {"XK": ("Kosovo", 42.66, 21.17)}


def tz_coordinate(text):
    match = re.fullmatch(r"([+-])(\d\d)(\d\d)(\d\d)?([+-])(\d\d\d)(\d\d)(\d\d)?", text)
    sign_lat, d1, m1, s1, sign_lon, d2, m2, s2 = match.groups()
    lat = int(d1) + int(m1) / 60 + int(s1 or 0) / 3600
    lon = int(d2) + int(m2) / 60 + int(s2 or 0) / 3600
    return (-lat if sign_lat == "-" else lat), (-lon if sign_lon == "-" else lon)


def countries(places_file):
    names, fallback = {}, {}
    with open(os.path.join(ZONEINFO, "iso3166.tab"), encoding="utf-8") as handle:
        for line in handle:
            if not line.startswith("#"):
                code, name = line.rstrip("\n").split("\t")[:2]
                names[code] = NAMES.get(code) or re.sub(r"\s*\(.*\)$", "", name).replace("St ", "Saint ")
    with open(os.path.join(ZONEINFO, "zone.tab"), encoding="utf-8") as handle:
        for line in handle:
            if not line.startswith("#"):
                code, coordinate = line.split("\t")[:2]
                fallback.setdefault(code, tz_coordinate(coordinate))
    capitals = {}
    with open(places_file, encoding="utf-8") as handle:
        features = json.load(handle)["features"]
    rank = {"Admin-0 capital": 0, "Admin-0 region capital": 1, "Admin-0 capital alt": 2}
    # Where a country has several capitals, the most populous one stands for it.
    for feature in sorted(features, key=lambda f: (rank.get(f["properties"]["featurecla"], 9),
                                                   -(f["properties"].get("pop_max") or 0))):
        props = feature["properties"]
        code = props.get("iso_a2")
        if props["featurecla"] in rank and code in names:
            capitals.setdefault(code, (props["latitude"], props["longitude"]))
    table = dict(EXTRA)
    for code, name in names.items():
        position = capitals.get(code) or fallback.get(code)
        if position:
            table[code] = (name, round(position[0], 2), round(position[1], 2))
    return dict(sorted(table.items()))


def land_rows(land_file):
    width, height = COLS * SUPERSAMPLE, ROWS * SUPERSAMPLE
    surface = cairo.ImageSurface(cairo.FORMAT_A8, width, height)
    cr = cairo.Context(surface)
    scale = SUPERSAMPLE / CELL
    with open(land_file, encoding="utf-8") as handle:
        features = json.load(handle)["features"]
    for shift in (-360, 0, 360):
        for feature in features:
            geometry = feature["geometry"]
            polygons = geometry["coordinates"] if geometry["type"] == "MultiPolygon" else [geometry["coordinates"]]
            for polygon in polygons:
                for ring in polygon:
                    for index, (lon, lat) in enumerate(ring):
                        x, y = (lon + shift - LON_LEFT) * scale, (LAT_TOP - lat) * scale
                        (cr.line_to if index else cr.move_to)(x, y)
                    cr.close_path()
                cr.fill()
    surface.flush()
    data, stride = surface.get_data(), surface.get_stride()
    rows = []
    for row in range(ROWS):
        line = ""
        for col in range(COLS):
            total = 0
            for y in range(row * SUPERSAMPLE, (row + 1) * SUPERSAMPLE):
                offset = y * stride + col * SUPERSAMPLE
                total += sum(data[offset:offset + SUPERSAMPLE])
            line += "#" if total / (255 * SUPERSAMPLE * SUPERSAMPLE) >= LAND_THRESHOLD else "."
        rows.append(line)
    return rows


def main():
    places_file, land_file = sys.argv[1:3]
    table = countries(places_file)
    rows = land_rows(land_file)
    out = [
        '"""Country names, capital coordinates and a coarse land mask for the map.',
        "",
        "Generated by tools/gen_geodata.py from Natural Earth and the tz database",
        '(both public domain). Do not edit by hand."""',
        "",
        "# ISO 3166-1 alpha-2 code -> (name, latitude, longitude of the capital)",
        "COUNTRIES = {",
    ]
    out += [f'    "{code}": ("{name}", {lat}, {lon}),' for code, (name, lat, lon) in table.items()]
    out += [
        "}",
        "",
        "# Plate carree grid: '#' is land. The left edge is MAP_LON_LEFT degrees east,",
        "# the top edge MAP_LAT_TOP degrees north, every cell MAP_CELL degrees wide and high.",
        f"MAP_LON_LEFT, MAP_LAT_TOP, MAP_CELL = {LON_LEFT}, {LAT_TOP}, {CELL}",
        "LAND = (",
    ]
    out += [f'    "{row}",' for row in rows]
    out += [")", ""]
    path = os.path.join(ROOT, "proxywall", "geodata.py")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(out))
    print(f"{path}: {len(table)} countries, {len(rows)}x{len(rows[0])} map")


if __name__ == "__main__":
    main()
