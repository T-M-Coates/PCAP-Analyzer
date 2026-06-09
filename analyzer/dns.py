from __future__ import annotations
import re
import socket
from datetime import datetime

import dpkt

from .utils import ip_to_str

_SUSP_TLDS = {'.ga', '.cf', '.ml', '.tk', '.pw', '.top', '.xyz', '.su'}
_HEX32_RE = re.compile(r'^[0-9a-f]{32}\.', re.IGNORECASE)


def _tld(name: str) -> str:
    parts = name.rsplit('.', 1)
    return '.' + parts[-1] if len(parts) > 1 else ''


def _ts_str(ts: float) -> str:
    return datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')


class DnsAnalyzer:
    def __init__(self):
        # domain -> {"count": int, "ips": set}
        self._queries: dict[str, dict] = {}
        # ip_str -> domain
        self._ip_to_domain: dict[str, str] = {}
        # PTR queries: ip_str -> count
        self._ptr_queries: dict[str, int] = {}
        # domain -> first-seen Unix timestamp (for timeline)
        self._domain_first_ts: dict[str, float] = {}

    def feed(self, ts: float, buf: bytes, eth=None) -> None:
        try:
            if eth is None:
                eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                return
            udp = ip.data
            if not isinstance(udp, dpkt.udp.UDP):
                return
            if udp.dport != 53 and udp.sport != 53:
                return

            dns = dpkt.dns.DNS(udp.data)

            # Questions
            for q in dns.qd:
                name = q.name.rstrip('.').lower()
                if q.type == dpkt.dns.DNS_PTR:
                    # .in-addr.arpa PTR lookup — reverse the octets to get original IP
                    arpa = name.replace('.in-addr.arpa', '')
                    try:
                        original_ip = '.'.join(reversed(arpa.split('.')))
                        self._ptr_queries[original_ip] = self._ptr_queries.get(original_ip, 0) + 1
                    except Exception:
                        pass
                else:
                    if name not in self._queries:
                        self._queries[name] = {"count": 0, "ips": set()}
                    self._queries[name]["count"] += 1
                    if name not in self._domain_first_ts:
                        self._domain_first_ts[name] = ts

            # Answers — map resolved IPs back to domain names
            for rr in dns.an:
                name = rr.name.rstrip('.').lower()
                if rr.type == dpkt.dns.DNS_A:
                    try:
                        resolved_ip = socket.inet_ntoa(rr.rdata)
                        if name in self._queries:
                            self._queries[name]["ips"].add(resolved_ip)
                        self._ip_to_domain[resolved_ip] = name
                    except Exception:
                        pass
                elif rr.type == dpkt.dns.DNS_PTR:
                    pass  # PTR answers don't need separate handling

        except Exception:
            pass

    def get_state(self) -> dict:
        return {
            'queries': {
                domain: {'count': data['count'], 'ips': list(data['ips'])}
                for domain, data in self._queries.items()
            },
            'ip_to_domain':    dict(self._ip_to_domain),
            'ptr_queries':     dict(self._ptr_queries),
            'domain_first_ts': dict(self._domain_first_ts),
        }

    def merge_state(self, state: dict) -> None:
        for domain, data in state['queries'].items():
            if domain not in self._queries:
                self._queries[domain] = {'count': 0, 'ips': set()}
            self._queries[domain]['count'] += data['count']
            self._queries[domain]['ips'].update(data['ips'])
        self._ip_to_domain.update(state['ip_to_domain'])
        for ip, count in state['ptr_queries'].items():
            self._ptr_queries[ip] = self._ptr_queries.get(ip, 0) + count
        for domain, ts in state['domain_first_ts'].items():
            if domain not in self._domain_first_ts or ts < self._domain_first_ts[domain]:
                self._domain_first_ts[domain] = ts

    def finalize(self) -> dict:
        # Build query list (convert sets to lists for JSON)
        query_list = []
        for domain, data in self._queries.items():
            query_list.append({
                "domain": domain,
                "query_count": data["count"],
                "resolved_ips": sorted(data["ips"]),
            })
        query_list.sort(key=lambda x: x["query_count"], reverse=True)

        # High-frequency threshold: top 5% by count
        if query_list:
            counts = sorted(q["query_count"] for q in query_list)
            threshold = counts[int(len(counts) * 0.95)] if len(counts) >= 20 else counts[-1] + 1
        else:
            threshold = 0

        # Build flagged list
        flagged = []
        seen_flags: set[str] = set()

        for q in query_list:
            domain = q["domain"]
            flags = []
            tld = _tld(domain)
            if tld in _SUSP_TLDS:
                flags.append("SUSP_TLD")
            if _HEX32_RE.match(domain):
                flags.append("HEX32")
            if q["query_count"] >= threshold and len(query_list) >= 20:
                flags.append("HIGH_FREQ")
            if flags:
                key = domain
                if key not in seen_flags:
                    seen_flags.add(key)
                    first_ts = self._domain_first_ts.get(domain)
                    flagged.append({
                        "domain": domain,
                        "flags": flags,
                        "query_count": q["query_count"],
                        "resolved_ips": q["resolved_ips"],
                        "first_seen": _ts_str(first_ts) if first_ts else "",
                    })

        # PTR queries as INFO flags
        for ip, count in self._ptr_queries.items():
            flagged.append({"domain": f"PTR:{ip}", "flags": ["PTR"], "query_count": count, "resolved_ips": []})

        return {
            "queries": query_list,
            "domain_ip_map": self._ip_to_domain,
            "flagged": flagged,
            "ptr_queries": {ip: cnt for ip, cnt in self._ptr_queries.items()},
        }
