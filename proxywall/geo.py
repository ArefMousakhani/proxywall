"""Where is the public IP: reply parsing, country fallback and map geometry."""

import ipaddress
import json
import math
import re

from .geodata import COUNTRIES, LAND, MAP_CELL, MAP_LAT_TOP, MAP_LON_LEFT

MAP_COLS, MAP_ROWS = len(LAND[0]), len(LAND)
__all__ = ["COUNTRIES", "MAP_COLS", "MAP_ROWS", "country_name", "describe", "format_coordinates",
           "format_place", "map_cell", "parse_reply"]


def _country_code(value):
    if isinstance(value, str) and re.fullmatch(r"[A-Za-z]{2}", value.strip()):
        return value.strip().upper()
    return None


def _number(value):
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _text(value, limit=60):
    if not isinstance(value, str):
        return None
    text = " ".join("".join(ch for ch in value if ch.isprintable()).split())
    return text[:limit] or None


def parse_reply(body):
    """Read the answer of an IP or geo-IP service.

    Understands the Cloudflare trace format, a bare address, and the JSON of
    the common services (ipwho.is, ipinfo.io, ip-api.com, ipapi.co). Returns
    a dict with ``ip``, ``country``, ``city``, ``latitude`` and ``longitude``;
    whatever the reply does not contain is None. ``ip`` is None when the reply
    is not usable at all.
    """
    out = {"ip": None, "country": None, "city": None, "latitude": None, "longitude": None}
    ip = None
    trace_ip = re.search(r"^ip=(\S+)$", body, re.M)
    if trace_ip:
        ip = trace_ip.group(1)
        loc = re.search(r"^loc=(\S+)$", body, re.M)
        out["country"] = _country_code(loc.group(1)) if loc else None
    else:
        text = body.strip()
        try:
            data = json.loads(text)
        except ValueError:
            data = None
            ip = text
        if isinstance(data, dict) and data.get("success") is not False and data.get("status") != "fail":
            ip = data.get("ip") or data.get("query")
            for key in ("country_code", "countryCode", "country"):
                out["country"] = out["country"] or _country_code(data.get(key))
            out["city"] = _text(data.get("city"))
            latitude = data.get("latitude", data.get("lat"))
            longitude = data.get("longitude", data.get("lon"))
            if latitude is None and isinstance(data.get("loc"), str) and "," in data["loc"]:
                latitude, longitude = data["loc"].split(",", 1)
            latitude, longitude = _number(latitude), _number(longitude)
            if (latitude is not None and longitude is not None and (latitude, longitude) != (0.0, 0.0)
                    and -90 <= latitude <= 90 and -180 <= longitude <= 180):
                out["latitude"], out["longitude"] = round(latitude, 4), round(longitude, 4)
    try:
        out["ip"] = str(ipaddress.ip_address(str(ip).strip()))
    except ValueError:
        return dict.fromkeys(out)
    return out


def country_name(code):
    entry = COUNTRIES.get(code or "")
    return entry[0] if entry else None


def describe(country, found=None):
    """Location fields of the status reply.

    *found* is a parsed geo-IP reply with coordinates, if there is one.
    Without it the country's capital stands in and ``location_exact`` is False.
    """
    out = {"country": country, "country_name": country_name(country), "city": None,
           "latitude": None, "longitude": None, "location_exact": False}
    if found and found.get("latitude") is not None:
        out.update(city=found.get("city"), latitude=found["latitude"], longitude=found["longitude"],
                   location_exact=True)
    elif country in COUNTRIES:
        out["latitude"], out["longitude"] = COUNTRIES[country][1:]
    return out


def format_coordinates(latitude, longitude):
    """``(-27.468, 153.028)`` -> ``27.47° S, 153.03° E``."""
    return (f"{abs(latitude):.2f}° {'S' if latitude < 0 else 'N'}, "
            f"{abs(longitude):.2f}° {'W' if longitude < 0 else 'E'}")


def format_place(status):
    """``Brisbane, Australia``, or as much of it as is known. None when nothing is."""
    country = status.get("country_name") or status.get("country")
    parts = [part for part in (status.get("city"), country) if part]
    return ", ".join(parts) or None


def map_cell(latitude, longitude):
    """Position on the LAND grid as (column, row) fractions, clamped to the grid."""
    column = ((longitude - MAP_LON_LEFT) % 360.0) / MAP_CELL
    row = (MAP_LAT_TOP - latitude) / MAP_CELL
    return min(max(column, 0.0), MAP_COLS), min(max(row, 0.0), MAP_ROWS)
