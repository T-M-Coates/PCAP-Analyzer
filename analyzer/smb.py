from __future__ import annotations
from datetime import datetime

import dpkt

from .utils import ip_to_str, is_internal

_SMB_PORTS = {139, 445}


def _ts_str(ts: float) -> str:
    return datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')


class SmbAnalyzer:
    def __init__(self):
        # (src, dst, port) -> count
        self._flows: dict[tuple, int] = {}
        # (src, dst, port) -> first-seen Unix timestamp
        self._pair_first_ts: dict[tuple, float] = {}
        # dst_ip -> count (for DC identification)
        self._dst_counts: dict[str, int] = {}
        self._external_smb: list[str] = []

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
            if tcp.dport not in _SMB_PORTS and tcp.sport not in _SMB_PORTS:
                return

            src = ip_to_str(ip.src)
            dst = ip_to_str(ip.dst)
            port = tcp.dport if tcp.dport in _SMB_PORTS else tcp.sport

            key = (src, dst, port)
            self._flows[key] = self._flows.get(key, 0) + 1
            if key not in self._pair_first_ts:
                self._pair_first_ts[key] = ts
            self._dst_counts[dst] = self._dst_counts.get(dst, 0) + 1

            # Flag external IPs initiating SMB connections
            if not is_internal(src) and tcp.dport in _SMB_PORTS and src not in self._external_smb:
                self._external_smb.append(src)

        except Exception:
            pass

    def get_state(self) -> dict:
        return {
            'flows':         dict(self._flows),
            'pair_first_ts': dict(self._pair_first_ts),
            'dst_counts':    dict(self._dst_counts),
            'external_smb':  list(self._external_smb),
        }

    def merge_state(self, state: dict) -> None:
        for key, count in state['flows'].items():
            self._flows[key] = self._flows.get(key, 0) + count
        for key, ts in state['pair_first_ts'].items():
            if key not in self._pair_first_ts or ts < self._pair_first_ts[key]:
                self._pair_first_ts[key] = ts
        for ip, count in state['dst_counts'].items():
            self._dst_counts[ip] = self._dst_counts.get(ip, 0) + count
        for ip in state['external_smb']:
            if ip not in self._external_smb:
                self._external_smb.append(ip)

    def finalize(self) -> dict:
        pairs = [
            {"src": s, "dst": d, "port": p, "packet_count": cnt,
             "first_ts": _ts_str(self._pair_first_ts.get((s, d, p), 0))}
            for (s, d, p), cnt in sorted(self._flows.items(), key=lambda x: -x[1])
        ]

        # DC candidate: internal IP receiving the most SMB
        dc_candidate = None
        best = 0
        for ip, cnt in self._dst_counts.items():
            if is_internal(ip) and cnt > best:
                best = cnt
                dc_candidate = ip

        return {
            "pairs": pairs,
            "dc_candidate": dc_candidate,
            "external_smb_sources": self._external_smb,
        }
