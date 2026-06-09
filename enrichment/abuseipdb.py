"""
Known-C2 blocklist checker (no API key required).

Sources:
  • Feodo Tracker (Abuse.ch)  — https://feodotracker.abuse.ch/downloads/ipblocklist.txt
  • CINS Army Score            — http://cinsscore.com/list/ci-badguys.txt

Both lists are downloaded on first use and refreshed if older than 24 hours.
If download fails, an existing cached file is used; if none exists, returns False.
"""
from __future__ import annotations
import os
import time

_TTL = 86_400   # 24 hours

_SOURCES = [
    ("feodo_blocklist.txt", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"),
    ("cins_blocklist.txt",  "http://cinsscore.com/list/ci-badguys.txt"),
]

# Module-level cache: data_folder -> (loaded_at, set_of_ips)
_cache: dict[str, tuple[float, frozenset[str]]] = {}


def _maybe_download(url: str, path: str) -> None:
    """Download url → path if the file is missing or older than TTL."""
    if os.path.exists(path):
        if time.time() - os.path.getmtime(path) < _TTL:
            return   # fresh enough
    try:
        import requests
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            with open(path, "w", encoding="utf-8") as f:
                f.write(resp.text)
    except Exception:
        pass   # use whatever is already on disk


def _build_set(data_folder: str) -> frozenset[str]:
    ips: set[str] = set()
    for filename, url in _SOURCES:
        path = os.path.join(data_folder, filename)
        _maybe_download(url, path)
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        # First whitespace-delimited token is the IP
                        ip = line.split()[0]
                        if ip:
                            ips.add(ip)
        except Exception:
            pass
    return frozenset(ips)


def _get_blocklist(data_folder: str) -> frozenset[str]:
    now = time.time()
    cached = _cache.get(data_folder)
    if cached and now - cached[0] < _TTL:
        return cached[1]
    blocklist = _build_set(data_folder)
    _cache[data_folder] = (now, blocklist)
    return blocklist


def is_known_c2(ip: str, data_folder: str) -> bool:
    """Return True if ip appears on Feodo or CINS blocklist."""
    return ip in _get_blocklist(data_folder)


def known_c2_set(data_folder: str) -> frozenset[str]:
    """Return the full set of known-C2 IPs (useful for bulk checks)."""
    return _get_blocklist(data_folder)
