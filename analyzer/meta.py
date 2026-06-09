from __future__ import annotations
import datetime
import re

import dpkt

from .utils import ip_to_str

_AD_SUFFIXES = ('.local', '.corp', '.lan', '.internal', '.ad', '.home', '.localdomain')
_AD_RE = re.compile(r'\.(?:local|corp|lan|internal|ad|home|localdomain)$', re.IGNORECASE)


def _build_packet_timeline(raw: dict) -> dict:
    """
    Re-bin 1-second raw buckets into an auto-scaled timeline for charting.
    Returns {"labels": [...], "values": [...], "step_s": N}.
    """
    if not raw:
        return {"labels": [], "values": [], "step_s": 1}
    keys = sorted(raw)
    t0 = keys[0]
    duration = keys[-1] - t0
    if duration <= 60:
        step = 1
    elif duration <= 300:
        step = 5
    elif duration <= 1800:
        step = 15
    elif duration <= 3600:
        step = 30
    else:
        step = 60
    # Merge into step-sized buckets (relative to first packet)
    merged: dict[int, int] = {}
    for k, v in raw.items():
        rb = ((k - t0) // step) * step
        merged[rb] = merged.get(rb, 0) + v
    max_rb = max(merged) if merged else 0
    labels: list[str] = []
    values: list[int] = []
    for rb in range(0, max_rb + step, step):
        if rb < 60:
            labels.append(f"+{rb}s")
        elif rb < 3600:
            m, s = divmod(rb, 60)
            labels.append(f"+{m}m{s:02d}s" if s else f"+{m}m")
        else:
            h, rem = divmod(rb, 3600)
            m = rem // 60
            labels.append(f"+{h}h{m:02d}m" if m else f"+{h}h")
        values.append(merged.get(rb, 0))
    return {"labels": labels, "values": values, "step_s": step}


class MetaAnalyzer:
    def __init__(self):
        self._first_ts: float | None = None
        self._last_ts: float | None = None
        self._total = 0
        self._tcp = 0
        self._udp = 0
        self._icmp = 0
        self._internal_domains: dict[str, int] = {}
        self._raw_buckets: dict[int, int] = {}   # floor(ts) → packet count

    def feed(self, ts: float, buf: bytes, eth=None) -> None:
        if self._first_ts is None:
            self._first_ts = ts
        self._last_ts = ts
        self._total += 1
        bucket = int(ts)
        self._raw_buckets[bucket] = self._raw_buckets.get(bucket, 0) + 1

        try:
            if eth is None:
                eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                return

            if isinstance(ip.data, dpkt.tcp.TCP):
                self._tcp += 1
            elif isinstance(ip.data, dpkt.udp.UDP):
                self._udp += 1
                udp = ip.data
                if udp.dport == 53 or udp.sport == 53:
                    self._parse_dns_name(udp.data)
            elif isinstance(ip.data, dpkt.icmp.ICMP):
                self._icmp += 1
        except Exception:
            pass

    def _parse_dns_name(self, payload: bytes) -> None:
        try:
            dns = dpkt.dns.DNS(payload)
            for q in dns.qd:
                name = q.name.rstrip('.').lower()
                if _AD_RE.search(name):
                    # Keep the root domain (last two labels)
                    parts = name.split('.')
                    root = '.'.join(parts[-2:])
                    self._internal_domains[root] = self._internal_domains.get(root, 0) + 1
        except Exception:
            pass

    def get_state(self) -> dict:
        return {
            'first_ts':        self._first_ts,
            'last_ts':         self._last_ts,
            'total':           self._total,
            'tcp':             self._tcp,
            'udp':             self._udp,
            'icmp':            self._icmp,
            'internal_domains': dict(self._internal_domains),
            'raw_buckets':     dict(self._raw_buckets),
        }

    def merge_state(self, state: dict) -> None:
        other_first = state['first_ts']
        other_last  = state['last_ts']
        if other_first is not None:
            if self._first_ts is None or other_first < self._first_ts:
                self._first_ts = other_first
        if other_last is not None:
            if self._last_ts is None or other_last > self._last_ts:
                self._last_ts = other_last
        self._total += state['total']
        self._tcp   += state['tcp']
        self._udp   += state['udp']
        self._icmp  += state['icmp']
        for domain, count in state['internal_domains'].items():
            self._internal_domains[domain] = self._internal_domains.get(domain, 0) + count
        for bucket, count in state['raw_buckets'].items():
            self._raw_buckets[bucket] = self._raw_buckets.get(bucket, 0) + count

    def finalize(self) -> dict:
        start_utc = (
            datetime.datetime.utcfromtimestamp(self._first_ts).strftime('%Y-%m-%d %H:%M:%S UTC')
            if self._first_ts else 'unknown'
        )
        duration_s = (
            round(self._last_ts - self._first_ts, 3)
            if self._first_ts and self._last_ts else 0
        )
        internal_domain = (
            max(self._internal_domains, key=self._internal_domains.get)
            if self._internal_domains else None
        )
        return {
            "start_time": start_utc,
            "duration_s": duration_s,
            "total_packets": self._total,
            "tcp_packets": self._tcp,
            "udp_packets": self._udp,
            "icmp_packets": self._icmp,
            "internal_domain": internal_domain,
            "packet_timeline": _build_packet_timeline(self._raw_buckets),
        }
