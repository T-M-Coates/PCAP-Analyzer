"""
JA3 TLS fingerprinting and malware family matching.

JA3 algorithm: https://github.com/salesforce/ja3
Computes an MD5 hash of five fields extracted from a TLS ClientHello:
  SSLVersion, Ciphers, Extensions, EllipticCurves, EllipticCurvePointFormats
GREASE values (RFC 8701) are excluded from each field.
"""
import hashlib
import json
import os
import struct
from typing import Optional

# GREASE values to exclude (RFC 8701)
_GREASE = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
}

_DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')


# ── JA3 computation ───────────────────────────────────────────────────────────

def compute_ja3(data: bytes) -> Optional[str]:
    """
    Compute a JA3 fingerprint from raw TCP payload bytes.
    Returns the hex MD5 string, or None if the payload is not a TLS ClientHello.
    """
    try:
        # TLS record header: type(1) version(2) length(2)
        if len(data) < 9:
            return None
        if data[0] != 0x16:        # content type: Handshake
            return None
        if data[1] != 0x03:        # major version 3
            return None
        if data[5] != 0x01:        # handshake type: ClientHello
            return None

        pos = 9  # after TLS record header(5) + handshake header(4)

        if pos + 34 > len(data):
            return None

        # Client version (2 bytes)
        tls_version = struct.unpack('>H', data[pos:pos + 2])[0]
        pos += 2

        # Random (32 bytes)
        pos += 32

        # Session ID
        if pos >= len(data):
            return None
        session_id_len = data[pos]
        pos += 1 + session_id_len

        if pos + 2 > len(data):
            return None

        # Cipher suites
        cs_len = struct.unpack('>H', data[pos:pos + 2])[0]
        pos += 2
        ciphers = []
        for i in range(0, cs_len, 2):
            if pos + i + 2 > len(data):
                break
            cs = struct.unpack('>H', data[pos + i:pos + i + 2])[0]
            if cs not in _GREASE:
                ciphers.append(cs)
        pos += cs_len

        if pos >= len(data):
            return None

        # Compression methods
        comp_len = data[pos]
        pos += 1 + comp_len

        if pos + 2 > len(data):
            # No extensions block — still a valid ClientHello
            ja3_str = f"{tls_version},{'-'.join(str(c) for c in ciphers)},,,'"
            return hashlib.md5(ja3_str.encode()).hexdigest()

        # Extensions
        ext_total = struct.unpack('>H', data[pos:pos + 2])[0]
        pos += 2

        extensions = []
        curves = []
        point_formats = []
        ext_end = pos + ext_total

        while pos + 4 <= ext_end and pos + 4 <= len(data):
            ext_type = struct.unpack('>H', data[pos:pos + 2])[0]
            ext_len = struct.unpack('>H', data[pos + 2:pos + 4])[0]
            pos += 4

            if pos + ext_len > len(data):
                break
            ext_data = data[pos:pos + ext_len]
            pos += ext_len

            if ext_type not in _GREASE:
                extensions.append(ext_type)

            if ext_type == 0x000a and len(ext_data) >= 2:   # supported_groups
                list_len = struct.unpack('>H', ext_data[0:2])[0]
                for i in range(2, min(2 + list_len, len(ext_data)), 2):
                    if i + 2 <= len(ext_data):
                        curve = struct.unpack('>H', ext_data[i:i + 2])[0]
                        if curve not in _GREASE:
                            curves.append(curve)

            elif ext_type == 0x000b and len(ext_data) >= 1:  # ec_point_formats
                fmt_len = ext_data[0]
                for i in range(1, min(1 + fmt_len, len(ext_data))):
                    point_formats.append(ext_data[i])

        # JA3 string: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
        ja3_str = ','.join([
            str(tls_version),
            '-'.join(str(c) for c in ciphers),
            '-'.join(str(e) for e in extensions),
            '-'.join(str(c) for c in curves),
            '-'.join(str(p) for p in point_formats),
        ])
        return hashlib.md5(ja3_str.encode()).hexdigest()

    except (IndexError, struct.error):
        return None


# ── Blocklist / family matching ───────────────────────────────────────────────

def _load_json(filename: str) -> dict:
    path = os.path.join(_DATA_DIR, filename)
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def check_ja3_hashes(ja3_hits: list) -> list:
    """
    Check (hash, src_ip, dst_ip) tuples against the blocklist.
    Returns a deduplicated list of flag dicts.
    """
    blocklist = _load_json('ja3_blocklist.json').get('hashes', {})
    flags = []
    seen = set()
    for ja3_hash, src, dst in ja3_hits:
        if ja3_hash in blocklist and ja3_hash not in seen:
            seen.add(ja3_hash)
            entry = blocklist[ja3_hash]
            flags.append({
                'hash':   ja3_hash,
                'label':  entry.get('label', 'Unknown'),
                'family': entry.get('family', 'Unknown'),
                'src':    src,
                'dst':    dst,
            })
    return flags


def match_malware_families(
    beacon_candidates: list,
    http_requests: list,
    ja3_flags: list,
) -> list:
    """
    Score observed network behavior against malware family signatures.

    Args:
        beacon_candidates: list of {src, dst, port, interval_s, cv, packet_count}
        http_requests:     list of (ts, src, dst, host, req_line, ua, ref, full_url)
        ja3_flags:         output of check_ja3_hashes()

    Returns sorted list of match dicts {family, confidence, score, indicators}.
    """
    families = _load_json('malware_families.json').get('families', [])

    all_uas       = {r[5].lower() for r in http_requests if r[5]}
    all_req_lines = [r[4].lower() for r in http_requests]
    beacon_ivs    = {b['interval_s'] for b in beacon_candidates}
    beacon_ports  = {b['port'] for b in beacon_candidates}
    ja3_family_names = {j['family'].lower() for j in ja3_flags}

    matches = []
    for fam in families:
        score = 0
        indicators: list[str] = []

        # Beacon interval match
        if 'beacon_interval_range' in fam:
            lo, hi = fam['beacon_interval_range']
            for iv in beacon_ivs:
                if lo <= iv <= hi:
                    indicators.append(f"beacon interval ~{iv:.0f}s matches {fam['name']} range ({lo}-{hi}s)")
                    score += fam.get('beacon_weight', 2)
                    break

        # Beacon port match
        if 'beacon_ports' in fam:
            for port in beacon_ports:
                if port in fam['beacon_ports']:
                    indicators.append(f"beaconing on port {port}")
                    score += 1
                    break

        # URL/path pattern match
        for pattern in fam.get('url_patterns', []):
            for req in all_req_lines:
                if pattern.lower() in req:
                    indicators.append(f"URL pattern '{pattern}'")
                    score += fam.get('url_weight', 1)
                    break

        # User-Agent pattern match
        for pattern in fam.get('user_agent_patterns', []):
            if pattern.lower() and any(pattern.lower() in ua for ua in all_uas):
                indicators.append(f"User-Agent contains '{pattern}'")
                score += 2
                break

        # JA3 family name correlation
        if fam.get('name', '').lower() in ja3_family_names:
            indicators.append(f"JA3 fingerprint matches {fam['name']}")
            score += 3

        if score >= fam.get('min_score', 2) and indicators:
            confidence = 'HIGH' if score >= 5 else ('MEDIUM' if score >= 3 else 'LOW')
            matches.append({
                'family':     fam['name'],
                'confidence': confidence,
                'score':      score,
                'indicators': indicators,
            })

    # De-duplicate by family name, keep highest score
    best: dict[str, dict] = {}
    for m in matches:
        key = m['family']
        if key not in best or m['score'] > best[key]['score']:
            best[key] = m

    return sorted(best.values(), key=lambda x: x['score'], reverse=True)
