"""
ASN / network-owner lookup via ipwhois.

Results are cached to <data_folder>/whois_cache.json with a 7-day TTL.
If the ipwhois library is not installed, all lookups return {}.
Lookups time out after 5 seconds to avoid stalling analysis.
"""
from __future__ import annotations
import json
import os
import time

_CACHE_TTL = 7 * 86_400   # 7 days


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


def lookup_asn_batch(ips: list, cache_path: str, max_workers: int = 8) -> dict:
    """
    Parallel batch ASN lookup.  Loads the cache once, fires concurrent
    network requests for cache misses, saves the cache once at the end.
    Returns {ip: {"asn": ..., "asn_description": ..., "network_name": ...}}.
    """
    if not ips:
        return {}

    from concurrent.futures import ThreadPoolExecutor, as_completed

    cache = _load_cache(cache_path)
    now   = time.time()
    result: dict = {}
    miss_ips: list = []

    for ip in ips:
        entry = cache.get(ip)
        if entry and now - entry.get("ts", 0) < _CACHE_TTL:
            data = entry.get("data", {})
            if data:
                result[ip] = data
        else:
            miss_ips.append(ip)

    if not miss_ips:
        return result

    def _lookup_one(ip: str):
        try:
            from ipwhois import IPWhois
            obj = IPWhois(ip, timeout=5)
            raw = obj.lookup_rdap(asn_timeout=5)
            data = {
                "asn":             raw.get("asn", ""),
                "asn_description": raw.get("asn_description", ""),
                "network_name":    (raw.get("network") or {}).get("name", ""),
            }
            return ip, data
        except Exception:
            return ip, {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_lookup_one, ip): ip for ip in miss_ips}
        for future in as_completed(futures):
            ip, data = future.result()
            cache[ip] = {"ts": now, "data": data}
            if data:
                result[ip] = data

    _save_cache(cache_path, cache)
    return result


def lookup_asn(ip: str, cache_path: str) -> dict:
    """
    Return {"asn": str, "asn_description": str, "network_name": str}
    or {} on failure / library not installed.
    """
    cache = _load_cache(cache_path)
    entry = cache.get(ip)
    if entry and time.time() - entry.get("ts", 0) < _CACHE_TTL:
        return entry.get("data", {})

    try:
        from ipwhois import IPWhois
        obj = IPWhois(ip, timeout=5)
        raw = obj.lookup_rdap(asn_timeout=5)
        data = {
            "asn":             raw.get("asn", ""),
            "asn_description": raw.get("asn_description", ""),
            "network_name":    (raw.get("network") or {}).get("name", ""),
        }
        cache[ip] = {"ts": time.time(), "data": data}
        _save_cache(cache_path, cache)
        return data
    except Exception:
        # Cache the failure briefly so we don't retry every run
        cache[ip] = {"ts": time.time(), "data": {}}
        _save_cache(cache_path, cache)
        return {}
