from __future__ import annotations
import datetime
import re
import urllib.parse

import dpkt

from .utils import ip_to_str, try_decode_b64

_HTTP_PORTS = {80, 8080}
_HTTP_VERBS = {b'GET', b'POST', b'HEAD', b'PUT', b'DELETE', b'OPTIONS', b'PATCH', b'CONNECT'}
_SUSP_PATHS = [
    '/spool/', 'gate.php', '.exe', '.zip', '.dll', '.ps1', '.bat',
    'update.php', 'check.php', '/ptm', 'cmd=', 'command=',
]
_SUSP_UA_SUBS = ['curl', 'wget', 'python', 'nikto', 'masscan', 'zgrab']
_B64_RE = re.compile(r'[A-Za-z0-9+/]{30,}={0,2}')
_SYSINFO_RE = re.compile(
    r'Windows\s+\d|Kaspersky|Norton|McAfee|Avast|ESET|Defender|MalwareBytes|'
    r'computername|username|hostname|systeminfo',
    re.IGNORECASE,
)


def _ts_str(ts: float) -> str:
    return datetime.datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')


def _is_http_verb(payload: bytes) -> bool:
    return any(payload.startswith(v + b' ') for v in _HTTP_VERBS)


def _extract_qs_b64(path: str) -> list[dict]:
    """Find base64-looking query string values and attempt to decode them."""
    found = []
    if '?' not in path:
        return found
    qs = path.split('?', 1)[1]
    for key, values in urllib.parse.parse_qs(qs, keep_blank_values=False).items():
        for val in values:
            if _B64_RE.fullmatch(val):
                decoded = try_decode_b64(val)
                if decoded["utf8"] or decoded["utf16le"]:
                    found.append({"param": key, **decoded})
    return found


class HttpAnalyzer:
    def __init__(self):
        self._requests: list[dict] = []
        self._post_requests: list[dict] = []
        self._flagged_requests: list[dict] = []
        self._decoded_params: list[dict] = []

    def feed(self, ts: float, buf: bytes, eth=None) -> None:
        try:
            if eth is None:
                eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                return
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                return
            if tcp.dport not in _HTTP_PORTS and tcp.sport not in _HTTP_PORTS:
                return
            if not tcp.data or not _is_http_verb(tcp.data):
                return
        except Exception:
            return

        try:
            src = ip_to_str(ip.src)
            dst = ip_to_str(ip.dst)

            # Parse with dpkt.http.Request; fall back to manual
            method = uri = host = user_agent = referer = body_snippet = ''
            try:
                req = dpkt.http.Request(tcp.data)
                method = req.method
                uri = req.uri
                headers = {k.lower(): v for k, v in req.headers.items()}
                host = headers.get('host', dst)
                user_agent = headers.get('user-agent', '')
                referer = headers.get('referer', '')
                body_snippet = req.body[:500].decode('latin-1', errors='replace') if req.body else ''
            except Exception:
                # Manual parse fallback
                lines = tcp.data.split(b'\r\n')
                parts = lines[0].split(b' ')
                if len(parts) >= 2:
                    method = parts[0].decode('latin-1', errors='replace')
                    uri = parts[1].decode('latin-1', errors='replace')
                headers_raw = {}
                for line in lines[1:]:
                    if b':' in line:
                        k, _, v = line.partition(b':')
                        headers_raw[k.strip().lower().decode('latin-1')] = v.strip().decode('latin-1', errors='replace')
                host = headers_raw.get('host', dst)
                user_agent = headers_raw.get('user-agent', '')
                referer = headers_raw.get('referer', '')
                if b'\r\n\r\n' in tcp.data:
                    body_raw = tcp.data.split(b'\r\n\r\n', 1)[1]
                    body_snippet = body_raw[:500].decode('latin-1', errors='replace') if method.upper() == 'POST' else ''

            full_url = f"http://{host}{uri}"

            record = {
                "ts": _ts_str(ts),
                "src": src,
                "dst": dst,
                "host": host,
                "method": method,
                "uri": uri,
                "url": full_url,
                "user_agent": user_agent,
                "referer": referer,
            }

            self._requests.append(record)

            if method.upper() == 'POST':
                post_record = {**record, "body_snippet": body_snippet}
                self._post_requests.append(post_record)

            # Flag: suspicious path patterns
            flags = []
            uri_lower = uri.lower()
            for pat in _SUSP_PATHS:
                if pat in uri_lower:
                    flags.append(f"SUSP_PATH:{pat}")

            # Flag: suspicious User-Agent
            ua_lower = user_agent.lower()
            for ua_sub in _SUSP_UA_SUBS:
                if ua_sub in ua_lower:
                    flags.append(f"SUSP_UA:{ua_sub}")

            # Flag: base64 in query params
            decoded_params = _extract_qs_b64(uri)
            if decoded_params:
                for dp in decoded_params:
                    dp["url"] = full_url
                    dp["ts"] = _ts_str(ts)
                    # Check for system info in decoded value
                    for decoded_val in [dp.get("utf8") or '', dp.get("utf16le") or '']:
                        if _SYSINFO_RE.search(decoded_val):
                            flags.append("SYSINFO_EXFIL")
                            break
                    flags.append("B64_PARAM")
                self._decoded_params.extend(decoded_params)

            # Flag: POST with body and no known host mapping (cross-ref done in runner after DNS)
            if method.upper() == 'POST' and body_snippet:
                flags.append("POST_WITH_BODY")

            if flags:
                self._flagged_requests.append({**record, "flags": flags, "body_snippet": body_snippet})

        except Exception:
            pass

    def get_state(self) -> dict:
        return {
            'requests':         list(self._requests),
            'post_requests':    list(self._post_requests),
            'flagged_requests': list(self._flagged_requests),
            'decoded_params':   list(self._decoded_params),
        }

    def merge_state(self, state: dict) -> None:
        self._requests.extend(state['requests'])
        self._post_requests.extend(state['post_requests'])
        self._flagged_requests.extend(state['flagged_requests'])
        self._decoded_params.extend(state['decoded_params'])

    def finalize(self, flagged_dns_domains: set[str] | None = None) -> dict:
        flagged_dns_domains = flagged_dns_domains or set()

        # Cross-reference flagged domains from DNS
        for req in self._requests:
            host = req.get("host", "")
            if any(host == d or host.endswith('.' + d) for d in flagged_dns_domains):
                already = next((f for f in self._flagged_requests if f["url"] == req["url"] and f["ts"] == req["ts"]), None)
                if already:
                    if "FLAGGED_DOMAIN" not in already["flags"]:
                        already["flags"].append("FLAGGED_DOMAIN")
                else:
                    self._flagged_requests.append({**req, "flags": ["FLAGGED_DOMAIN"], "body_snippet": ""})

        return {
            "requests": self._requests,
            "post_requests": self._post_requests,
            "flagged_requests": self._flagged_requests,
            "decoded_params": self._decoded_params,
        }
