from __future__ import annotations

import dpkt

from .utils import ip_to_str, is_internal

_SMB_PORTS = {139, 445}
_DNS_PORT = 53


class HostsAnalyzer:
    def __init__(self):
        # {ip_str: {"sent": int, "received": int}}
        self._hosts: dict[str, dict] = {}
        # {ip_str: int} — how much SMB+DNS traffic an IP *received*
        self._dc_score: dict[str, int] = {}

    def _ensure(self, ip: str) -> None:
        if ip not in self._hosts:
            self._hosts[ip] = {"sent": 0, "received": 0}

    def feed(self, ts: float, buf: bytes, eth=None) -> None:
        try:
            if eth is None:
                eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                return

            src = ip_to_str(ip.src)
            dst = ip_to_str(ip.dst)
            self._ensure(src)
            self._ensure(dst)
            self._hosts[src]["sent"] += 1
            self._hosts[dst]["received"] += 1

            # Track DC candidacy
            transport = ip.data
            dst_port = None
            if isinstance(transport, dpkt.tcp.TCP):
                dst_port = transport.dport
            elif isinstance(transport, dpkt.udp.UDP):
                dst_port = transport.dport

            if dst_port in _SMB_PORTS or dst_port == _DNS_PORT:
                self._dc_score[dst] = self._dc_score.get(dst, 0) + 1

        except Exception:
            pass

    def get_state(self) -> dict:
        return {
            'hosts':    {ip: dict(c) for ip, c in self._hosts.items()},
            'dc_score': dict(self._dc_score),
        }

    def merge_state(self, state: dict) -> None:
        for ip, counts in state['hosts'].items():
            if ip not in self._hosts:
                self._hosts[ip] = {'sent': 0, 'received': 0}
            self._hosts[ip]['sent']     += counts['sent']
            self._hosts[ip]['received'] += counts['received']
        for ip, score in state['dc_score'].items():
            self._dc_score[ip] = self._dc_score.get(ip, 0) + score

    def finalize(self) -> dict:
        # Determine DC candidate: internal IP with highest SMB+DNS score
        dc_candidate = None
        best_score = 0
        for ip, score in self._dc_score.items():
            if is_internal(ip) and score > best_score:
                best_score = score
                dc_candidate = ip

        hosts = []
        for ip, counts in self._hosts.items():
            total = counts["sent"] + counts["received"]
            role = "dc_candidate" if ip == dc_candidate else ("internal" if is_internal(ip) else "external")
            hosts.append({
                "ip": ip,
                "type": "internal" if is_internal(ip) else "external",
                "packets_sent": counts["sent"],
                "packets_received": counts["received"],
                "packet_count": total,
                "role": role,
            })

        hosts.sort(key=lambda h: h["packet_count"], reverse=True)
        return {"hosts": hosts, "dc_candidate": dc_candidate}
