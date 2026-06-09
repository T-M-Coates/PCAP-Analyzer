from __future__ import annotations
import math
from datetime import datetime

import dpkt

from .utils import ip_to_str


def _ts_str(ts: float) -> str:
    return datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')


class BeaconingAnalyzer:
    def __init__(self):
        # (src_ip, dst_ip, dst_port) -> [timestamps]
        self._flows: dict[tuple, list[float]] = {}

    def feed(self, ts: float, buf: bytes, eth=None) -> None:
        try:
            if eth is None:
                eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                return
            transport = ip.data
            if not isinstance(transport, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                return

            src = ip_to_str(ip.src)
            dst = ip_to_str(ip.dst)
            dport = transport.dport

            key = (src, dst, dport)
            if key not in self._flows:
                self._flows[key] = []
            self._flows[key].append(ts)

        except Exception:
            pass

    def get_state(self) -> dict:
        return {key: list(ts) for key, ts in self._flows.items()}

    def merge_state(self, state: dict) -> None:
        for key, timestamps in state.items():
            if key in self._flows:
                self._flows[key].extend(timestamps)
            else:
                self._flows[key] = list(timestamps)

    def finalize(self) -> dict:
        candidates = []

        for (src, dst, port), timestamps in self._flows.items():
            if len(timestamps) < 8:
                continue

            timestamps.sort()

            # Inter-packet intervals, ignoring very short gaps (< 0.5s — retransmissions/bursts)
            intervals = []
            for i in range(1, len(timestamps)):
                gap = timestamps[i] - timestamps[i - 1]
                if gap >= 0.5:
                    intervals.append(gap)

            if len(intervals) < 4:
                continue

            mean = sum(intervals) / len(intervals)
            if mean < 5 or mean > 3600:
                continue

            variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
            stdev = math.sqrt(variance)
            cv = stdev / mean if mean > 0 else float('inf')

            if cv >= 0.30:
                continue

            # Regularity score: 1.0 = perfectly regular, 0.0 = CV at threshold
            regularity_score = round(1.0 - (cv / 0.30), 4)

            candidates.append({
                "src": src,
                "dst": dst,
                "port": port,
                "interval_s": round(mean, 2),
                "packet_count": len(timestamps),
                "cv": round(cv, 4),
                "regularity_score": regularity_score,
                "first_ts": _ts_str(timestamps[0]),
            })

        # Sort by regularity (most regular first)
        candidates.sort(key=lambda c: c["cv"])

        return {"candidates": candidates}
