"""
MaxMind GeoLite2-Country lookup.

Database file must be placed at:  <data_folder>/GeoLite2-Country.mmdb

If the file is missing, or the geoip2 library is not installed,
all lookups silently return an empty string.

Free download (requires free MaxMind account):
  https://www.maxmind.com/en/geolite2/signup
"""
from __future__ import annotations
import os

_reader = None
_db_path_tried: str | None = None


def _get_reader(data_folder: str):
    global _reader, _db_path_tried
    db_path = os.path.join(data_folder, "GeoLite2-Country.mmdb")
    if db_path == _db_path_tried:
        return _reader          # already attempted (may be None)
    _db_path_tried = db_path
    _reader = None
    if not os.path.exists(db_path):
        return None
    try:
        import geoip2.database
        _reader = geoip2.database.Reader(db_path)
    except Exception:
        pass
    return _reader


def lookup_country(ip: str, data_folder: str) -> str:
    """Return the ISO 3166-1 alpha-2 country code (e.g. 'US') or ''."""
    reader = _get_reader(data_folder)
    if not reader:
        return ""
    try:
        response = reader.country(ip)
        return response.country.iso_code or ""
    except Exception:
        return ""


def flag_emoji(iso_code: str) -> str:
    """Convert a 2-letter ISO code to a flag emoji (e.g. 'US' → '🇺🇸')."""
    if not iso_code or len(iso_code) != 2:
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in iso_code.upper())
