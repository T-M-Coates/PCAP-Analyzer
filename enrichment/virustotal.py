"""
VirusTotal API v3 enrichment.

Rate limit: 4 requests/minute on the free tier — we sleep 15 s between
actual API calls, but cache hits are served instantly (24-hour TTL).
"""
from __future__ import annotations
import json
import os
import time

_VT_BASE = "https://www.virustotal.com/api/v3"
_CACHE_TTL = 86_400  # 24 hours


# ── Cache helpers ─────────────────────────────────────────────────
def _load_cache(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_cache(path: str, cache: dict) -> None:
    try:
        with open(path, "w") as f:
            json.dump(cache, f)
    except Exception:
        pass


def _get_cached(cache: dict, key: str) -> dict | None:
    entry = cache.get(key)
    if entry and time.time() - entry.get("ts", 0) < _CACHE_TTL:
        return entry.get("data")
    return None


# ── Low-level request ─────────────────────────────────────────────
def _vt_get(endpoint: str, api_key: str) -> dict | None:
    try:
        import requests
        resp = requests.get(
            f"{_VT_BASE}/{endpoint}",
            headers={"x-apikey": api_key},
            timeout=12,
        )
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code in (401, 403):
            raise RuntimeError("VT API key invalid or unauthorised.")
        # 429 = quota exceeded — treat as empty, not an error
        return None
    except RuntimeError:
        raise
    except Exception:
        return None


def _parse_attrs(raw: dict | None) -> dict:
    if not raw:
        return {}
    attrs = raw.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    total = sum(stats.values())
    return {
        "malicious_count":  stats.get("malicious", 0),
        "suspicious_count": stats.get("suspicious", 0),
        "total_engines":    total if total > 0 else 90,
        "last_analysis_date": attrs.get("last_analysis_date"),
        "country":    attrs.get("country", ""),
        "as_owner":   attrs.get("as_owner", ""),
        "registrar":  attrs.get("registrar", ""),
        "creation_date": attrs.get("creation_date"),
    }


# ── Public API ────────────────────────────────────────────────────
def lookup_ip(ip: str, cache_path: str, api_key: str = "") -> dict:
    """Return VT analysis dict for an IP, or {} on failure/missing key."""
    key = os.getenv("VT_API_KEY", api_key)
    if not key:
        return {}
    cache = _load_cache(cache_path)
    hit = _get_cached(cache, ip)
    if hit is not None:
        return hit
    try:
        raw = _vt_get(f"ip_addresses/{ip}", key)
        data = _parse_attrs(raw)
        if data:
            cache[ip] = {"ts": time.time(), "data": data}
            _save_cache(cache_path, cache)
        return data
    except Exception:
        return {}


def lookup_domain(domain: str, cache_path: str, api_key: str = "") -> dict:
    """Return VT analysis dict for a domain, or {} on failure/missing key."""
    key = os.getenv("VT_API_KEY", api_key)
    if not key:
        return {}
    cache = _load_cache(cache_path)
    hit = _get_cached(cache, domain)
    if hit is not None:
        return hit
    try:
        raw = _vt_get(f"domains/{domain}", key)
        data = _parse_attrs(raw)
        if data:
            cache[domain] = {"ts": time.time(), "data": data}
            _save_cache(cache_path, cache)
        return data
    except Exception:
        return {}


def batch_lookup(iocs: list[dict], cache_path: str) -> dict[str, dict]:
    """
    Look up a list of {"type": "ip"|"domain", "value": "..."} objects.
    Returns a dict keyed by value.  Skips cached entries without sleeping.
    """
    api_key = os.getenv("VT_API_KEY", "")
    if not api_key:
        return {}

    results: dict[str, dict] = {}
    cache = _load_cache(cache_path)
    last_real_call = 0.0

    for ioc in iocs:
        ioc_type = ioc.get("type", "")
        value    = ioc.get("value", "").strip()
        if not value or value in results:
            continue

        # Serve from cache without sleeping
        hit = _get_cached(cache, value)
        if hit is not None:
            results[value] = hit
            continue

        # Real API call — honour 4 req/min rate limit
        elapsed = time.time() - last_real_call
        if last_real_call > 0 and elapsed < 15:
            time.sleep(15 - elapsed)

        if ioc_type == "ip":
            data = lookup_ip(value, cache_path, api_key)
        elif ioc_type == "domain":
            data = lookup_domain(value, cache_path, api_key)
        else:
            continue

        last_real_call = time.time()
        if data:
            results[value] = data

    return results
