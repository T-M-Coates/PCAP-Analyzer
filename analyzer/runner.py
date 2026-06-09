from __future__ import annotations
import collections
import json
import mmap
import multiprocessing
import os
import socket
import struct
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import dpkt

from .meta import MetaAnalyzer
from .hosts import HostsAnalyzer
from .dns import DnsAnalyzer
from .http import HttpAnalyzer
from .beaconing import BeaconingAnalyzer
from .smb import SmbAnalyzer
from .discovery import DiscoveryAnalyzer
from . import iocs as iocs_module
from .utils import is_internal, is_pcapng

# ── Optional deep-analysis modules ───────────────────────────────────
_DEEP_OK = False
try:
    from .fingerprint import compute_ja3, check_ja3_hashes, match_malware_families
    from .tls_certs import extract_certificates, is_suspicious_cert
    from .file_extractor import extract_http_files
    from .ai_summary import generate_narrative
    _DEEP_OK = True
except ImportError:
    pass

# ── Severity ordering (lowest → highest) ─────────────────────────
_SEV_ORDER = ["INFO", "MEDIUM", "HIGH", "CRITICAL"]
_SEV_RANK  = {s: i for i, s in enumerate(_SEV_ORDER)}


def _upgrade_severity(sev: str) -> str:
    idx = _SEV_RANK.get(sev, 0)
    return _SEV_ORDER[min(idx + 1, len(_SEV_ORDER) - 1)]


# ── Fast pcap offset pre-scanner ─────────────────────────────────
_MAGIC_LE_US = 0xa1b2c3d4
_MAGIC_LE_NS = 0xa1b23c4d
_MAGIC_BE_US = 0xd4c3b2a1
_MAGIC_BE_NS = 0x4d3cb2a1


def _scan_pcap_offsets(path: str) -> tuple[str, float, list[int]]:
    """
    Read only the 16-byte per-packet record headers to build a list of
    byte offsets for every packet.  For a 1 GB file this reads ~16 MB
    instead of 1 GB, making it ~60× faster than a full parse.

    Returns (endian_fmt, ts_divisor, offsets).
    endian_fmt : '<' or '>'
    ts_divisor : 1e6 (microseconds) or 1e9 (nanoseconds)
    offsets    : byte position of each packet record (ts_sec field)
    """
    offsets: list[int] = []
    with open(path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            return "<", 1e6, offsets

        magic = struct.unpack_from("<I", hdr, 0)[0]
        if magic == _MAGIC_LE_US:
            endian, ts_div = "<", 1e6
        elif magic == _MAGIC_LE_NS:
            endian, ts_div = "<", 1e9
        elif magic == _MAGIC_BE_US:
            endian, ts_div = ">", 1e6
        elif magic == _MAGIC_BE_NS:
            endian, ts_div = ">", 1e9
        else:
            return "<", 1e6, offsets  # unknown / pcapng — caller should not call us

        rec_fmt = f"{endian}IIII"
        while True:
            pos = f.tell()
            rec_hdr = f.read(16)
            if len(rec_hdr) < 16:
                break
            _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack(rec_fmt, rec_hdr)
            offsets.append(pos)
            try:
                f.seek(incl_len, 1)
            except OSError:
                break

    return endian, ts_div, offsets


# ── Worker process (must be top-level for Windows spawn compat) ───
def _worker_process(
    pcap_path: str,
    endian: str,
    ts_div: float,
    offsets: list[int],
    result_q,           # multiprocessing.Queue
) -> None:
    """
    Runs in a subprocess.  Opens the file, reads the packets at the given
    byte offsets, routes each packet to the appropriate analysers using the
    raw-bytes fast-path, then sends the merged state back via result_q.
    """
    # Absolute imports — sys.path inherited from parent via multiprocessing spawn.
    from analyzer.meta import MetaAnalyzer
    from analyzer.hosts import HostsAnalyzer
    from analyzer.dns import DnsAnalyzer
    from analyzer.http import HttpAnalyzer
    from analyzer.beaconing import BeaconingAnalyzer
    from analyzer.smb import SmbAnalyzer
    from analyzer.discovery import DiscoveryAnalyzer
    import dpkt, socket, struct, collections

    meta_an   = MetaAnalyzer()
    hosts_an  = HostsAnalyzer()
    dns_an    = DnsAnalyzer()
    http_an   = HttpAnalyzer()
    beacon_an = BeaconingAnalyzer()
    smb_an    = SmbAnalyzer()
    disc_an   = DiscoveryAnalyzer()

    tls_payloads: list = []
    http_streams: dict = collections.defaultdict(bytearray)

    rec_fmt = f"{endian}IIII"

    try:
        with open(pcap_path, "rb") as f:
            for offset in offsets:
                try:
                    f.seek(offset)
                    rec_hdr = f.read(16)
                    if len(rec_hdr) < 16:
                        continue
                    ts_sec, ts_usec, incl_len, _orig = struct.unpack(rec_fmt, rec_hdr)
                    buf = f.read(incl_len)
                    if len(buf) < incl_len:
                        continue

                    ts   = ts_sec + ts_usec / ts_div
                    _eth = None

                    # ── Raw-bytes fast-path routing ──────────────
                    if len(buf) >= 14:
                        ethertype = (buf[12] << 8) | buf[13]
                        if ethertype == 0x0800 and len(buf) >= 24:
                            ip_ihl   = (buf[14] & 0x0f) * 4
                            ip_proto = buf[23]
                            try:
                                _eth = dpkt.ethernet.Ethernet(buf)
                            except Exception:
                                _eth = None

                            toff = 14 + ip_ihl

                            if ip_proto == 6 and len(buf) >= toff + 4:   # TCP
                                src_port = (buf[toff]     << 8) | buf[toff + 1]
                                dst_port = (buf[toff + 2] << 8) | buf[toff + 3]
                                meta_an.feed(ts, buf, _eth)
                                hosts_an.feed(ts, buf, _eth)
                                beacon_an.feed(ts, buf, _eth)
                                if dst_port in (139, 445) or src_port in (139, 445):
                                    smb_an.feed(ts, buf, _eth)
                                elif dst_port in (80, 8080) or src_port in (80, 8080):
                                    http_an.feed(ts, buf, _eth)

                            elif ip_proto == 17 and len(buf) >= toff + 4:  # UDP
                                src_port = (buf[toff]     << 8) | buf[toff + 1]
                                dst_port = (buf[toff + 2] << 8) | buf[toff + 3]
                                meta_an.feed(ts, buf, _eth)
                                hosts_an.feed(ts, buf, _eth)
                                beacon_an.feed(ts, buf, _eth)
                                if dst_port == 53 or src_port == 53:
                                    dns_an.feed(ts, buf, _eth)
                                    if src_port == 53:
                                        disc_an.feed(ts, buf, _eth)
                                elif src_port in (5355, 5353, 137) or dst_port in (5355, 5353, 137):
                                    disc_an.feed(ts, buf, _eth)
                                elif src_port == 1900 or dst_port == 1900:  # SSDP/UPnP
                                    disc_an.feed(ts, buf, _eth)
                                elif src_port == 67 or dst_port == 67:  # DHCP
                                    disc_an.feed(ts, buf, _eth)

                            elif ip_proto == 1:  # ICMP
                                meta_an.feed(ts, buf, _eth)
                                hosts_an.feed(ts, buf, _eth)
                            else:
                                meta_an.feed(ts, buf, _eth)
                                hosts_an.feed(ts, buf, _eth)
                        else:
                            # Non-IPv4 (ARP, IPv6, LLDP, etc.)
                            if ethertype == 0x0806:  # ARP
                                if _eth is None:
                                    try:
                                        _eth = dpkt.ethernet.Ethernet(buf)
                                    except Exception:
                                        pass
                                if _eth is not None:
                                    disc_an.feed(ts, buf, _eth)
                            elif ethertype == 0x88CC:  # LLDP
                                if _eth is None:
                                    try:
                                        _eth = dpkt.ethernet.Ethernet(buf)
                                    except Exception:
                                        pass
                                if _eth is not None:
                                    disc_an.feed(ts, buf, _eth)
                            meta_an.feed(ts, buf, None)
                    else:
                        meta_an.feed(ts, buf, None)

                    # TLS / HTTP stream collection for deep analysis
                    if _eth is not None:
                        try:
                            ip = _eth.data
                            if isinstance(ip, dpkt.ip.IP):
                                tcp = ip.data
                                if isinstance(tcp, dpkt.tcp.TCP):
                                    payload = bytes(tcp.data)
                                    if payload:
                                        src_ip = socket.inet_ntoa(ip.src)
                                        dst_ip = socket.inet_ntoa(ip.dst)
                                        sport, dport = tcp.sport, tcp.dport
                                        if (len(payload) > 9
                                                and payload[0] == 0x16
                                                and payload[1] == 0x03):
                                            tls_payloads.append((src_ip, dst_ip, payload))
                                        if dport in (80, 8080, 8000) or sport in (80, 8080, 8000):
                                            key = (src_ip, dst_ip, sport, dport)
                                            if len(http_streams[key]) < 4 * 1024 * 1024:
                                                http_streams[key].extend(payload)
                        except Exception:
                            pass

                except Exception:
                    continue

    except Exception:
        pass

    result_q.put({
        "meta":         meta_an.get_state(),
        "hosts":        hosts_an.get_state(),
        "dns":          dns_an.get_state(),
        "http":         http_an.get_state(),
        "beaconing":    beacon_an.get_state(),
        "smb":          smb_an.get_state(),
        "discovery":    disc_an.get_state(),
        "tls_payloads": tls_payloads,
        "http_streams": {k: bytes(v) for k, v in http_streams.items()},
    })


# ── State merge (called in main process after workers finish) ─────
def _merge_states(
    meta_an: MetaAnalyzer,
    hosts_an: HostsAnalyzer,
    dns_an: DnsAnalyzer,
    http_an: HttpAnalyzer,
    beacon_an: BeaconingAnalyzer,
    smb_an: SmbAnalyzer,
    disc_an: DiscoveryAnalyzer,
    worker_states: list[dict],
) -> tuple[list, dict]:
    tls_payloads: list = []
    http_streams: dict = collections.defaultdict(bytearray)

    for state in worker_states:
        meta_an.merge_state(state["meta"])
        hosts_an.merge_state(state["hosts"])
        dns_an.merge_state(state["dns"])
        http_an.merge_state(state["http"])
        beacon_an.merge_state(state["beaconing"])
        smb_an.merge_state(state["smb"])
        if "discovery" in state:
            disc_an.merge_state(state["discovery"])

        tls_payloads.extend(state["tls_payloads"])
        for key, data in state["http_streams"].items():
            existing = http_streams[key]
            if len(existing) < 4 * 1024 * 1024:
                remaining = 4 * 1024 * 1024 - len(existing)
                http_streams[key].extend(data[:remaining])

    return tls_payloads, http_streams


# ── Enrichment phase ──────────────────────────────────────────────
def _enrich(results: dict, data_folder: str, jobs: dict, job_id: str) -> None:
    """
    Runs after core analysis.  Attaches country / ASN / VT / C2 data to
    hosts and IOCs, then upgrades IOC severity where warranted.
    All failures are swallowed so the core report is never lost.
    """
    from enrichment import virustotal, geoip, whois as whois_mod, abuseipdb

    hosts_list  = results["hosts"]["hosts"]
    ioc_list    = results["iocs"]["iocs"]
    vt_cache    = os.path.join(data_folder, "vt_cache.json")
    whois_cache = os.path.join(data_folder, "whois_cache.json")

    external_ips = [h["ip"] for h in hosts_list if h["type"] == "external"]

    # ── 1. C2 blocklist (fast – just set membership) ──────────────
    jobs[job_id]["progress"] = 95
    try:
        c2_set = abuseipdb.known_c2_set(data_folder)
    except Exception:
        c2_set = frozenset()

    # ── 2. GeoIP (fast if .mmdb present, silent skip if not) ──────
    jobs[job_id]["progress"] = 96
    geo_map: dict[str, str] = {}
    try:
        for ip in external_ips:
            geo_map[ip] = geoip.lookup_country(ip, data_folder)
    except Exception:
        pass

    # Attach country to every host
    for h in hosts_list:
        h["country"] = geo_map.get(h["ip"], "")

    # ── 3. WHOIS / ASN (parallel network calls, capped at 25 IPs) ─
    jobs[job_id]["progress"] = 97
    ioc_ips = list(dict.fromkeys(
        ioc["value"] for ioc in ioc_list
        if ioc["type"] == "ip" and ioc["value"] in {h["ip"] for h in hosts_list if h["type"] == "external"}
    ))[:25]

    try:
        whois_map: dict[str, dict] = whois_mod.lookup_asn_batch(ioc_ips, whois_cache)
    except Exception:
        whois_map = {}

    # Attach ASN to all hosts where we have data
    for h in hosts_list:
        w = whois_map.get(h["ip"], {})
        h["asn"]             = w.get("asn", "")
        h["asn_description"] = w.get("asn_description", "")

    # ── 4. VirusTotal batch lookup (rate-limited, IOC IPs/domains) ─
    jobs[job_id]["progress"] = 98
    ioc_domains = list(dict.fromkeys(
        ioc["value"] for ioc in ioc_list if ioc["type"] == "domain"
    ))[:12]

    vt_iocs = (
        [{"type": "ip",     "value": ip}     for ip     in ioc_ips[:15]] +
        [{"type": "domain", "value": domain} for domain in ioc_domains]
    )
    try:
        vt_map = virustotal.batch_lookup(vt_iocs, vt_cache)
    except Exception:
        vt_map = {}

    # ── 5. Attach enrichment to each IOC and upgrade severity ──────
    def _enrich_ioc(ioc: dict) -> dict:
        ioc_type = ioc["type"]
        value    = ioc["value"]
        enr: dict = {}

        if ioc_type == "ip":
            enr["country"]      = geo_map.get(value, "")
            enr["is_known_c2"]  = value in c2_set
            w = whois_map.get(value, {})
            enr["asn"]             = w.get("asn", "")
            enr["asn_description"] = w.get("asn_description", "")
            vt = vt_map.get(value, {})
            if vt:
                enr["vt_malicious"]  = vt.get("malicious_count", 0)
                enr["vt_suspicious"] = vt.get("suspicious_count", 0)
                enr["vt_total"]      = vt.get("total_engines", 90)

        elif ioc_type == "domain":
            enr["is_known_c2"] = False
            vt = vt_map.get(value, {})
            if vt:
                enr["vt_malicious"]  = vt.get("malicious_count", 0)
                enr["vt_suspicious"] = vt.get("suspicious_count", 0)
                enr["vt_total"]      = vt.get("total_engines", 90)

        elif ioc_type in ("url", "flow", "user_agent"):
            if ioc_type == "url":
                host = urlparse(value).hostname or ""
                vt = vt_map.get(host, {})
                if vt:
                    enr["vt_malicious"]  = vt.get("malicious_count", 0)
                    enr["vt_suspicious"] = vt.get("suspicious_count", 0)
                    enr["vt_total"]      = vt.get("total_engines", 90)
            if ioc_type == "flow" and " -> " in value:
                src_ip = value.split(" -> ")[0]
                enr["country"]     = geo_map.get(src_ip, "")
                enr["is_known_c2"] = src_ip in c2_set
            else:
                enr["is_known_c2"] = False

        ioc["enrichment"] = enr

        if enr.get("vt_malicious", 0) > 0 or enr.get("is_known_c2"):
            ioc["severity"] = _upgrade_severity(ioc["severity"])

        return ioc

    results["iocs"]["iocs"] = [_enrich_ioc(ioc) for ioc in ioc_list]

    results["iocs"]["iocs"].sort(key=lambda x: _SEV_RANK.get(x["severity"], 99), reverse=True)

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "INFO"):
        key = f"{sev.lower()}_count"
        results["iocs"][key] = sum(1 for i in results["iocs"]["iocs"] if i["severity"] == sev)


# ── Phase mapping (used by timeline and narrative) ────────────────
_ETYPE_PHASE: dict[str, str] = {
    "capture_start": "Capture",
    "capture_end":   "Capture",
    "dns_flagged":   "Reconnaissance",
    "http_request":  "Initial Contact",
    "http_flagged":  "Initial Contact",
    "exfil":         "Exfiltration",
    "beacon_start":  "Command & Control",
    "smb_external":  "Lateral Movement",
    "smb_dc":        "Lateral Movement",
    "mitm":          "Lateral Movement",
}

_PHASE_ORDER = [
    "Capture", "Reconnaissance", "Initial Contact",
    "Payload Delivery", "Command & Control", "Exfiltration",
    "Lateral Movement", "Activity",
]
_PHASE_RANK = {p: i for i, p in enumerate(_PHASE_ORDER)}

_PHASE_ICONS: dict[str, str] = {
    "Capture":           "\U0001f535",
    "Reconnaissance":    "\U0001f50d",
    "Initial Contact":   "\U0001f310",
    "Payload Delivery":  "\U0001f4e6",
    "Command & Control": "\U0001f4e1",
    "Exfiltration":      "\U0001f4e4",
    "Lateral Movement":  "↔",
}

_DOWNLOAD_FLAGS = frozenset({
    "EXE_DOWNLOAD", "DLL_DOWNLOAD", "ZIP_DOWNLOAD",
    "PS1_DOWNLOAD", "BAT_DOWNLOAD",
})


def _assign_phase(ev: dict) -> str:
    etype = ev.get("etype", "")
    if etype == "http_flagged":
        detail = ev.get("detail", "")
        if any(f in detail for f in _DOWNLOAD_FLAGS):
            return "Payload Delivery"
    return _ETYPE_PHASE.get(etype, "Activity")


# ── Timeline builder ─────────────────────────────────────────────
def _build_timeline(results: dict) -> list[dict]:
    from datetime import datetime, timedelta

    meta      = results["meta"]
    http      = results["http"]
    dns       = results["dns"]
    beacon    = results["beaconing"]
    smb       = results["smb"]
    discovery = results.get("discovery", {})

    start_ts_str = meta["start_time"].replace(" UTC", "")
    try:
        start_dt    = datetime.strptime(start_ts_str, "%Y-%m-%d %H:%M:%S")
        start_epoch = start_dt.timestamp()
    except Exception:
        start_dt    = None
        start_epoch = 0.0

    def _rel(ts_str: str) -> float:
        try:
            dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            return max(0.0, round(dt.timestamp() - start_epoch, 1))
        except Exception:
            return 0.0

    def _rel_str(seconds: float) -> str:
        s = int(seconds)
        if s < 60:
            return f"+{s}s"
        if s < 3600:
            return f"+{s // 60}m {s % 60}s"
        return f"+{s // 3600}h {(s % 3600) // 60}m"

    def _ev(ts: str, sev: str, etype: str, title: str, detail: str,
            source: str, suspicious: bool) -> dict:
        rel = _rel(ts)
        return {
            "ts":         ts,
            "ts_rel":     rel,
            "ts_rel_str": _rel_str(rel),
            "severity":   sev,
            "etype":      etype,
            "title":      title,
            "detail":     detail,
            "source":     source,
            "suspicious": suspicious,
        }

    events: list[dict] = []

    tcp  = meta.get("tcp_packets", 0)
    udp  = meta.get("udp_packets", 0)
    icmp = meta.get("icmp_packets", 0)
    events.append(_ev(
        start_ts_str, "INFO", "capture_start", "Capture started",
        f"{meta['total_packets']:,} packets · TCP {tcp:,} · UDP {udp:,} · ICMP {icmp:,}",
        "meta", False,
    ))

    _FLAG_SEV   = {"SUSP_TLD": "HIGH", "HEX32": "HIGH", "HIGH_FREQ": "MEDIUM"}
    _FLAG_LABEL = {
        "SUSP_TLD":  "Suspicious TLD",
        "HEX32":     "DGA pattern (hex32)",
        "HIGH_FREQ": "High-frequency queries",
    }
    for f in dns.get("flagged", []):
        if "PTR" in f.get("flags", []):
            continue
        first_seen = f.get("first_seen", "")
        if not first_seen:
            continue
        sev = max(
            (_FLAG_SEV.get(fl, "MEDIUM") for fl in f["flags"]),
            key=lambda s: _SEV_RANK.get(s, 0),
            default="MEDIUM",
        )
        flag_desc = " · ".join(_FLAG_LABEL.get(fl, fl) for fl in f["flags"])
        ips_str   = ", ".join(f.get("resolved_ips", [])[:3])
        detail    = flag_desc + (f" → {ips_str}" if ips_str else "")
        events.append(_ev(
            first_seen, sev, "dns_flagged",
            f"Suspicious DNS: {f['domain']}", detail, "dns", True,
        ))

    for dp in http.get("decoded_params", []):
        ts = dp.get("ts", "")
        if not ts:
            continue
        decoded = (dp.get("utf16le") or dp.get("utf8") or "")[:80]
        sev     = "CRITICAL" if dp.get("utf16le") else "HIGH"
        url     = dp.get("url", "")
        detail  = f"Param '{dp.get('param', '')}': {decoded}"
        if url:
            detail += f" — {url[:70]}"
        events.append(_ev(ts, sev, "exfil",
                          "Data exfiltrated via URL parameter", detail, "http", True))

    _HTTP_FLAG_SEV: dict[str, str] = {
        "EXE_DOWNLOAD": "HIGH", "DLL_DOWNLOAD": "HIGH",
        "ZIP_DOWNLOAD": "HIGH", "PS1_DOWNLOAD": "HIGH",
        "BAT_DOWNLOAD": "HIGH", "POST_WITH_ENCODED_PARAMS": "HIGH",
        "SYSINFO_EXFIL": "CRITICAL", "FLAGGED_DOMAIN": "HIGH",
        "SUSP_PATH": "MEDIUM", "SUSP_UA": "MEDIUM",
    }
    for req in http.get("flagged_requests", []):
        ts = req.get("ts", "")
        if not ts:
            continue
        flags  = req.get("flags", [])
        sev    = max(
            (_HTTP_FLAG_SEV.get(fl, "MEDIUM") for fl in flags),
            key=lambda s: _SEV_RANK.get(s, 0),
            default="MEDIUM",
        )
        flag_str = " · ".join(flags)
        host_uri = f"{req.get('host', '')}{req.get('uri', '')[:60]}"
        detail   = (f"{flag_str} — {host_uri}" if flag_str else host_uri)
        events.append(_ev(
            ts, sev, "http_flagged",
            f"{req.get('method','HTTP')} {req.get('host','')}",
            detail, "http", True,
        ))

    for req in http.get("requests", [])[:500]:
        ts = req.get("ts", "")
        if not ts:
            continue
        title  = f"{req.get('method','GET')} {req.get('host','')}"
        uri    = req.get("uri", "")[:60]
        ua     = req.get("user_agent", "")
        detail = uri + (f" — {ua}" if ua else "")
        events.append(_ev(ts, "INFO", "http_request", title, detail, "http", False))

    for c in beacon.get("candidates", []):
        first_ts = c.get("first_ts", "")
        if not first_ts:
            continue
        sev = "CRITICAL" if c["cv"] < 0.05 else "HIGH"
        detail = (
            f"Every {c['interval_s']}s · CV={c['cv']} · "
            f"{c['packet_count']} packets · regularity {round(c['regularity_score']*100)}%"
        )
        events.append(_ev(
            first_ts, sev, "beacon_start",
            f"Beaconing: {c['src']} → {c['dst']}:{c['port']}",
            detail, "beaconing", True,
        ))

    for src_ip in smb.get("external_smb_sources", []):
        first_ts = next(
            (p.get("first_ts", "") for p in smb.get("pairs", []) if p.get("src") == src_ip),
            start_ts_str,
        )
        events.append(_ev(
            first_ts or start_ts_str, "CRITICAL", "smb_external",
            f"External SMB: {src_ip}",
            "External IP communicating on TCP 139/445 — possible ransomware or lateral movement",
            "smb", True,
        ))

    dc = smb.get("dc_candidate")
    if dc:
        dc_pairs = [p for p in smb.get("pairs", []) if p.get("dst") == dc]
        if dc_pairs:
            first_ts   = dc_pairs[0].get("first_ts", start_ts_str)
            total_pkts = sum(p["packet_count"] for p in dc_pairs)
            events.append(_ev(
                first_ts or start_ts_str, "MEDIUM", "smb_dc",
                f"SMB traffic to DC {dc}",
                f"{total_pkts:,} packets — may indicate lateral movement or normal domain activity",
                "smb", False,
            ))

    for alert in discovery.get("mitm_alerts", []):
        ts_str = alert.get("ts") or start_ts_str
        atype  = alert.get("type", "MITM")
        sev    = alert.get("severity", "HIGH")
        detail = alert.get("detail", "")
        title_map = {
            "ARP_SPOOFING":              "ARP Spoofing detected",
            "MAC_CLAIMING_MULTIPLE_IPS": "MAC address impersonation",
            "GRATUITOUS_ARP":            "Gratuitous ARP detected",
            "DNS_CONFLICT":              "DNS conflict / possible spoofing",
            "NAME_SERVICE_SPOOFING":     "LLMNR/mDNS/NBNS spoofing suspect",
        }
        title = title_map.get(atype, "MITM indicator")
        events.append(_ev(ts_str, sev, "mitm", title, detail, "discovery", True))

    dur = meta.get("duration_s", 0)
    if start_dt:
        try:
            end_ts_str = (start_dt + timedelta(seconds=dur)).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            end_ts_str = start_ts_str
    else:
        end_ts_str = start_ts_str

    if dur >= 3600:
        dur_str = f"{int(dur/3600)}h {int((dur % 3600)/60)}m"
    elif dur >= 60:
        dur_str = f"{int(dur/60)}m {int(dur % 60)}s"
    else:
        dur_str = f"{dur}s"

    events.append(_ev(
        end_ts_str, "INFO", "capture_end", "Capture ended",
        f"Duration: {dur_str}", "meta", False,
    ))

    events.sort(key=lambda e: e["ts"])

    max_rank = 0
    for ev in events:
        intrinsic = _assign_phase(ev)
        rank = _PHASE_RANK.get(intrinsic, 0)
        if ev.get("suspicious") and rank > max_rank:
            max_rank = rank
        ev["phase"] = _PHASE_ORDER[max_rank]

    phases_with_suspicious = {ev["phase"] for ev in events if ev.get("suspicious")}

    final: list[dict] = []
    current_phase: str | None = None
    for ev in events:
        phase = ev["phase"]
        if phase != current_phase:
            current_phase = phase
            final.append({
                "is_phase_divider": True,
                "phase":      phase,
                "phase_icon": _PHASE_ICONS.get(phase, "•"),
                "suspicious": phase in phases_with_suspicious,
            })
        final.append(ev)

    return final


# ── Attack narrative builder ──────────────────────────────────────
def _build_narrative(results: dict) -> dict:
    from collections import Counter

    meta      = results.get("meta", {})
    http      = results.get("http", {})
    dns       = results.get("dns", {})
    beacon    = results.get("beaconing", {})
    smb       = results.get("smb", {})
    iocs      = results.get("iocs", {})
    timeline  = results.get("timeline", [])
    discovery = results.get("discovery", {})

    flagged_reqs   = http.get("flagged_requests", [])
    decoded_params = http.get("decoded_params", [])
    candidates     = beacon.get("candidates", [])

    src_counts: Counter = Counter()
    for req in flagged_reqs:
        src = req.get("src", "")
        if src and is_internal(src):
            src_counts[src] += 1

    infected_hosts = [ip for ip, _ in src_counts.most_common(3) if _ > 0]

    if not infected_hosts:
        for c in candidates:
            src = c.get("src", "")
            if src and is_internal(src) and src not in infected_hosts:
                infected_hosts.append(src)

    has_exfil      = bool(decoded_params)
    has_beaconing  = bool(candidates)
    has_mitm       = bool(discovery.get("mitm_alerts"))
    has_ext_smb    = bool(smb.get("external_smb_sources"))
    has_downloads  = any(
        any(f in req.get("flags", []) for f in _DOWNLOAD_FLAGS)
        for req in flagged_reqs
    )
    has_dga = any("HEX32" in f.get("flags", []) for f in dns.get("flagged", []))
    has_known_c2   = any(
        (ioc.get("enrichment") or {}).get("is_known_c2")
        for ioc in iocs.get("iocs", [])
    )
    critical_count = iocs.get("critical_count", 0)
    high_count     = iocs.get("high_count", 0)

    if has_ext_smb:
        attack_type, attack_label, sev = "ransomware_worm",  "Ransomware / Worm",                  "CRITICAL"
    elif has_mitm and (has_exfil or has_beaconing):
        attack_type, attack_label, sev = "mitm_active",      "Active MITM + Exfiltration",          "CRITICAL"
    elif has_exfil and has_beaconing:
        attack_type, attack_label, sev = "info_stealer",     "Info Stealer / Credential Harvester", "CRITICAL"
    elif has_exfil:
        attack_type, attack_label, sev = "data_exfil",       "Data Exfiltration",                   "HIGH"
    elif has_downloads:
        attack_type, attack_label, sev = "dropper",          "Malware Dropper",                     "HIGH"
    elif has_beaconing:
        attack_type, attack_label, sev = "c2_implant",       "C2 Implant",                          "HIGH"
    elif has_mitm:
        attack_type, attack_label, sev = "mitm",             "MITM / ARP Spoofing",                 "HIGH"
    elif has_dga:
        attack_type, attack_label, sev = "dga_malware",      "DGA Malware",                         "HIGH"
    elif has_known_c2:
        attack_type, attack_label, sev = "suspicious",       "Known C2 Contact",                    "HIGH"
    elif critical_count + high_count > 0:
        attack_type, attack_label, sev = "suspicious",       "Suspicious Activity",                 "MEDIUM"
    else:
        attack_type, attack_label, sev = "clean",            "No Indicators Found",                 "INFO"

    n_indicators = sum([has_exfil, has_beaconing, has_downloads,
                        has_ext_smb, has_dga, has_known_c2, has_mitm])
    if n_indicators >= 3 or (has_exfil and has_beaconing):
        confidence = "HIGH"
    elif n_indicators >= 2 or critical_count > 0:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    first_susp = next(
        (ev for ev in timeline
         if ev.get("suspicious") and not ev.get("is_phase_divider")),
        None,
    )
    first_susp_rel   = first_susp["ts_rel_str"] if first_susp else None
    first_susp_title = first_susp["title"]      if first_susp else None

    sentences: list[str] = []

    if attack_type == "clean":
        sentences.append("No strong indicators of compromise were found in this capture.")
    elif infected_hosts:
        hosts_str = " and ".join(infected_hosts[:2])
        sentences.append(
            f"An internal machine ({hosts_str}) appears to have been compromised during this capture."
        )
    else:
        sentences.append(
            "Suspicious activity was detected, though the source machine could not be clearly "
            "identified from the available traffic."
        )

    if first_susp_rel and first_susp_title:
        sentences.append(
            f"The first suspicious event occurred at {first_susp_rel}: {first_susp_title}."
        )

    if has_exfil:
        dst_hosts: set[str] = set()
        sample_text = ""
        for dp in decoded_params:
            val = (dp.get("utf16le") or dp.get("utf8") or "").strip()
            if val and not sample_text:
                sample_text = val[:80]
            url = dp.get("url", "")
            if url:
                try:
                    h = urlparse(url).hostname or ""
                    if h:
                        dst_hosts.add(h)
                except Exception:
                    pass
        n_e = len(decoded_params)
        n_s = len(dst_hosts) or 1
        if sample_text:
            sentences.append(
                f"System information was exfiltrated {n_e} time{'s' if n_e != 1 else ''} "
                f"to {n_s} server{'s' if n_s != 1 else ''} — "
                f"including data such as: \"{sample_text}\"."
            )
        else:
            sentences.append(
                f"Encoded data was exfiltrated {n_e} time{'s' if n_e != 1 else ''} "
                f"to {n_s} server{'s' if n_s != 1 else ''}."
            )

    if has_beaconing:
        best = candidates[0]
        interval = best["interval_s"]
        cv = best["cv"]
        reg_label = (
            "machine-perfect" if cv < 0.05 else
            "highly regular"  if cv < 0.15 else
            "regular"
        )
        n_b = len(candidates)
        sentences.append(
            f"A C2 beaconing connection was detected — checking in every {interval}s "
            f"with {reg_label} timing ({n_b} flow{'s' if n_b != 1 else ''} total)."
        )

    if has_downloads:
        dl_req = next(
            (r for r in flagged_reqs
             if any(f in r.get("flags", []) for f in _DOWNLOAD_FLAGS)),
            None,
        )
        if dl_req:
            ftype = next(
                (f.replace("_DOWNLOAD", "").lower()
                 for f in dl_req.get("flags", []) if "_DOWNLOAD" in f),
                "file",
            )
            sentences.append(
                f"A potentially malicious {ftype} file was downloaded from {dl_req.get('host', 'an external host')}."
            )

    if has_ext_smb:
        ext_ips = smb.get("external_smb_sources", [])
        ip_str  = ", ".join(ext_ips[:3])
        sentences.append(
            f"An external IP ({ip_str}) communicated over SMB (TCP 139/445) — "
            f"a strong indicator of ransomware, a worm, or external brute force."
        )

    if has_dga:
        dga_domains = [f["domain"] for f in dns.get("flagged", []) if "HEX32" in f.get("flags", [])]
        n_dga = len(dga_domains)
        sentences.append(
            f"The malware queried {n_dga} algorithmically-generated domain name{'s' if n_dga != 1 else ''} "
            f"(DGA) — a technique used to locate active C2 servers that are difficult to block."
        )

    if has_known_c2:
        c2_iocs = [
            ioc for ioc in iocs.get("iocs", [])
            if (ioc.get("enrichment") or {}).get("is_known_c2")
        ]
        if c2_iocs:
            sentences.append(
                f"At least one contacted IP ({c2_iocs[0]['value']}) appears on published "
                f"C2 blocklists (Feodo Tracker / CINS Army)."
            )

    if has_mitm:
        mitm_alerts = discovery.get("mitm_alerts", [])
        mac_flips   = discovery.get("mac_flips", [])
        dns_races   = discovery.get("dns_races", [])
        name_spoof  = discovery.get("name_spoofers", [])
        if mac_flips:
            flip = mac_flips[0]
            sentences.append(
                f"ARP spoofing was detected: the IP {flip['ip']} changed its MAC address "
                f"from {flip['old_mac']} to {flip['new_mac']}, a hallmark of a Man-in-the-Middle attack."
            )
        if dns_races:
            sentences.append(
                f"A DNS conflict was observed for {dns_races[0]['domain']}: two different servers "
                f"returned different IP addresses, which may indicate DNS spoofing."
            )
        if name_spoof:
            sentences.append(
                f"The host {name_spoof[0]['ip']} responded to {name_spoof[0]['name_count']} "
                f"unique name-resolution queries — consistent with an LLMNR/mDNS poisoning tool such as Responder."
            )

    key_facts: list[dict] = []

    if infected_hosts:
        extra = f" +{len(infected_hosts) - 1} more" if len(infected_hosts) > 1 else ""
        key_facts.append({"icon": "\U0001f5a5", "label": "Likely infected", "value": infected_hosts[0] + extra})

    if first_susp_rel:
        key_facts.append({"icon": "⏱", "label": "First suspicious", "value": first_susp_rel})

    if has_exfil:
        dst_hosts2: set[str] = set()
        for dp in decoded_params:
            url = dp.get("url", "")
            if url:
                try:
                    h = urlparse(url).hostname or ""
                    if h:
                        dst_hosts2.add(h)
                except Exception:
                    pass
        n_s2 = len(dst_hosts2) or 1
        key_facts.append({
            "icon": "\U0001f4e4",
            "label": "Exfil events",
            "value": f"{len(decoded_params)} to {n_s2} server{'s' if n_s2 != 1 else ''}",
        })

    if has_beaconing:
        intervals = sorted({c["interval_s"] for c in candidates})
        iv_str = f"{intervals[0]}s" if len(intervals) == 1 else f"{intervals[0]}–{intervals[-1]}s"
        key_facts.append({
            "icon": "\U0001f4e1",
            "label": "Beaconing",
            "value": f"{len(candidates)} flow{'s' if len(candidates) != 1 else ''} ({iv_str})",
        })

    if has_ext_smb:
        n_smb = len(smb.get("external_smb_sources", []))
        key_facts.append({
            "icon": "⚠",
            "label": "External SMB",
            "value": f"{n_smb} source{'s' if n_smb != 1 else ''}",
        })

    if has_mitm:
        mitm_alerts = discovery.get("mitm_alerts", [])
        mac_flips   = discovery.get("mac_flips", [])
        top_type = (
            "ARP Spoofing" if mac_flips else
            "DNS Conflict" if discovery.get("dns_races") else
            "Name Spoofing" if discovery.get("name_spoofers") else
            "Gratuitous ARP"
        )
        key_facts.append({
            "icon": "🕵",
            "label": "MITM Alerts",
            "value": f"{len(mitm_alerts)} alert{'s' if len(mitm_alerts) != 1 else ''} ({top_type})",
        })

    return {
        "infected_hosts":    infected_hosts,
        "attack_type":       attack_type,
        "attack_type_label": attack_label,
        "overall_severity":  sev,
        "confidence":        confidence,
        "sentences":         sentences,
        "key_facts":         key_facts,
    }


# ── Shared post-loop pipeline ─────────────────────────────────────
def _finish_analysis(
    pcap_path: str,
    job_id: str,
    jobs: dict,
    data_folder: str,
    meta_an: MetaAnalyzer,
    hosts_an: HostsAnalyzer,
    dns_an: DnsAnalyzer,
    http_an: HttpAnalyzer,
    beacon_an: BeaconingAnalyzer,
    smb_an: SmbAnalyzer,
    disc_an: DiscoveryAnalyzer,
    tls_payloads: list,
    http_streams,   # dict or defaultdict(bytearray)
) -> None:
    """
    Runs finalize(), deep analysis, enrichment, narrative, and JSON write.
    Called by both the single-threaded and multi-process paths.
    """
    jobs[job_id]["progress"] = 88

    meta_results  = meta_an.finalize()
    hosts_results = hosts_an.finalize()
    dns_results   = dns_an.finalize()

    flagged_dns_domains = {
        f["domain"] for f in dns_results.get("flagged", [])
        if "PTR" not in f.get("flags", [])
    }
    http_results   = http_an.finalize(flagged_dns_domains)
    beacon_results = beacon_an.finalize()
    smb_results    = smb_an.finalize()
    disc_results   = disc_an.finalize(http_results=http_results, hosts_results=hosts_results)

    jobs[job_id]["progress"] = 94

    ioc_results = iocs_module.aggregate(dns_results, http_results, beacon_results, smb_results, disc_results)

    # ── Deep analysis (JA3, TLS certs, file extraction, malware families) ──
    jobs[job_id]["status_label"] = "Deep analysis…"
    threat_intel: dict = {
        "ja3_flags": [], "cert_flags": [],
        "extracted_files": [], "malware_families": [],
    }
    if _DEEP_OK:
        try:
            def _do_ja3():
                hits = []
                for _src, _dst, _pl in tls_payloads:
                    _h = compute_ja3(_pl)
                    if _h:
                        hits.append((_h, _src, _dst))
                return hits

            def _do_certs():
                cert_list: list = []
                seen_fps: set   = set()
                for _src, _dst, _pl in tls_payloads:
                    for _c in extract_certificates(_pl, _src, _dst):
                        _fp = _c.get("fingerprint_sha256", "")
                        if _fp not in seen_fps and is_suspicious_cert(_c):
                            seen_fps.add(_fp)
                            cert_list.append(_c)
                return cert_list

            def _do_files():
                return extract_http_files(http_streams)

            with ThreadPoolExecutor(max_workers=3) as _deep_pool:
                _f_ja3  = _deep_pool.submit(_do_ja3)
                _f_cert = _deep_pool.submit(_do_certs)
                _f_file = _deep_pool.submit(_do_files)
                _ja3_hits                       = _f_ja3.result()
                threat_intel["cert_flags"]      = _f_cert.result()
                threat_intel["extracted_files"] = _f_file.result()

            threat_intel["ja3_flags"] = check_ja3_hashes(_ja3_hits)

            _http_tuples = [
                (r.get("ts", ""), r.get("src", ""), "",
                 r.get("host", ""),
                 f"{r.get('method', 'GET')} {r.get('uri', '')}",
                 r.get("user_agent", ""), r.get("referer", ""),
                 r.get("url", ""))
                for r in http_results.get("requests", [])
            ]
            threat_intel["malware_families"] = match_malware_families(
                beacon_results.get("candidates", []),
                _http_tuples,
                threat_intel["ja3_flags"],
            )
        except Exception:
            pass

    results = {
        "meta":      meta_results,
        "hosts":     hosts_results,
        "dns":       dns_results,
        "http":      http_results,
        "beaconing": beacon_results,
        "smb":       smb_results,
        "discovery": disc_results,
        "iocs":         ioc_results,
        "threat_intel": threat_intel,
        "timeline":  _build_timeline({
            "meta": meta_results, "http": http_results,
            "dns":  dns_results,  "beaconing": beacon_results,
            "smb":  smb_results,  "discovery": disc_results,
        }),
    }

    jobs[job_id]["status_label"] = "Enriching…"
    try:
        _enrich(results, data_folder, jobs, job_id)
    except Exception:
        pass

    try:
        results["narrative"] = _build_narrative(results)
    except Exception:
        results["narrative"] = {
            "infected_hosts": [], "attack_type": "unknown",
            "attack_type_label": "Analysis incomplete",
            "overall_severity": "INFO", "confidence": "LOW",
            "sentences": ["The narrative summary could not be generated."],
            "key_facts": [],
        }

    results["ai_narrative"] = None
    if _DEEP_OK:
        _anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")
        if _anthropic_key:
            try:
                jobs[job_id]["status_label"] = "Generating AI narrative…"
                _ai_data = {
                    "capture_info": {
                        "duration_minutes": meta_results.get("duration_s", 0) / 60,
                        "total_packets":    meta_results.get("total_packets", 0),
                        "start_time":       meta_results.get("start_time", ""),
                    },
                    "internal_hosts": [
                        h["ip"] for h in hosts_results.get("hosts", [])
                        if h.get("type") == "internal"
                    ],
                    "external_hosts": [
                        h["ip"] for h in hosts_results.get("hosts", [])
                        if h.get("type") == "external"
                    ],
                    "beacons":         beacon_results.get("candidates", [])[:5],
                    "post_requests":   [r for r in http_results.get("requests", [])
                                        if r.get("method") == "POST"][:5],
                    "suspicious_urls": [],
                    "suspicious_domains": [
                        {"domain": f["domain"],
                         "reason": ", ".join(f.get("flags", []))}
                        for f in dns_results.get("flagged", [])[:5]
                    ],
                    "smb_pairs":       smb_results.get("pairs", [])[:3],
                    "malware_matches": threat_intel.get("malware_families", [])[:3],
                    "ja3_flags":       threat_intel.get("ja3_flags", [])[:3],
                    "cert_flags":      threat_intel.get("cert_flags", [])[:3],
                    "extracted_files": threat_intel.get("extracted_files", [])[:3],
                }
                results["ai_narrative"] = generate_narrative(_ai_data, _anthropic_key)
            except Exception:
                pass

    try:
        geo: dict[str, int] = {}
        for h in results["hosts"]["hosts"]:
            if h.get("type") == "external":
                cc = h.get("country", "")
                if cc and len(cc) == 2 and cc.isalpha():
                    geo[cc.upper()] = geo.get(cc.upper(), 0) + 1
        results["geo_summary"] = geo
    except Exception:
        results["geo_summary"] = {}

    jobs[job_id]["progress"] = 99

    out_path = os.path.join(data_folder, f"{job_id}.json")
    with open(out_path, "w") as fout:
        json.dump(results, fout, default=str)

    jobs[job_id]["status"]   = "complete"
    jobs[job_id]["progress"] = 100


# ── Single-threaded path (PCAPNG or files < 50 MB) ────────────────
def _analyze_single(pcap_path: str, job_id: str, jobs: dict, data_folder: str) -> None:
    jobs[job_id]["status"]   = "running"
    jobs[job_id]["progress"] = 5

    file_size = max(os.path.getsize(pcap_path), 1)

    meta_an   = MetaAnalyzer()
    hosts_an  = HostsAnalyzer()
    dns_an    = DnsAnalyzer()
    http_an   = HttpAnalyzer()
    beacon_an = BeaconingAnalyzer()
    smb_an    = SmbAnalyzer()
    disc_an   = DiscoveryAnalyzer()

    tls_payloads: list = []
    http_streams: dict = collections.defaultdict(bytearray)

    with open(pcap_path, "rb") as _fh:
        with mmap.mmap(_fh.fileno(), 0, access=mmap.ACCESS_READ) as f:
            try:
                if is_pcapng(pcap_path):
                    pcap = dpkt.pcapng.Reader(f)
                else:
                    pcap = dpkt.pcap.Reader(f)
            except Exception as exc:
                raise ValueError(f"Failed to open capture file: {exc}") from exc

            packet_count  = 0
            last_reported = 5

            for ts, buf in pcap:
                packet_count += 1
                _eth = None

                # ── Raw-bytes fast-path routing ───────────────────────
                # Determine packet type from raw bytes before any dpkt object
                # creation, then dispatch only to the analysers that can use it.
                if len(buf) >= 14:
                    ethertype = (buf[12] << 8) | buf[13]

                    if ethertype == 0x0800 and len(buf) >= 24:  # IPv4
                        ip_ihl   = (buf[14] & 0x0f) * 4
                        ip_proto = buf[23]
                        try:
                            _eth = dpkt.ethernet.Ethernet(buf)
                        except Exception:
                            _eth = None

                        toff = 14 + ip_ihl   # transport header offset

                        if ip_proto == 6 and len(buf) >= toff + 4:   # TCP
                            src_port = (buf[toff]     << 8) | buf[toff + 1]
                            dst_port = (buf[toff + 2] << 8) | buf[toff + 3]
                            meta_an.feed(ts, buf, _eth)
                            hosts_an.feed(ts, buf, _eth)
                            beacon_an.feed(ts, buf, _eth)
                            if dst_port in (139, 445) or src_port in (139, 445):
                                smb_an.feed(ts, buf, _eth)
                            elif dst_port in (80, 8080) or src_port in (80, 8080):
                                http_an.feed(ts, buf, _eth)

                        elif ip_proto == 17 and len(buf) >= toff + 4:  # UDP
                            src_port = (buf[toff]     << 8) | buf[toff + 1]
                            dst_port = (buf[toff + 2] << 8) | buf[toff + 3]
                            meta_an.feed(ts, buf, _eth)
                            hosts_an.feed(ts, buf, _eth)
                            beacon_an.feed(ts, buf, _eth)
                            if dst_port == 53 or src_port == 53:
                                dns_an.feed(ts, buf, _eth)
                                if src_port == 53:
                                    disc_an.feed(ts, buf, _eth)
                            elif src_port in (5355, 5353, 137) or dst_port in (5355, 5353, 137):
                                disc_an.feed(ts, buf, _eth)
                            elif src_port == 1900 or dst_port == 1900:  # SSDP/UPnP
                                disc_an.feed(ts, buf, _eth)
                            elif src_port == 67 or dst_port == 67:  # DHCP
                                disc_an.feed(ts, buf, _eth)

                        elif ip_proto == 1:  # ICMP
                            meta_an.feed(ts, buf, _eth)
                            hosts_an.feed(ts, buf, _eth)
                        else:
                            meta_an.feed(ts, buf, _eth)
                            hosts_an.feed(ts, buf, _eth)
                    else:
                        # Non-IPv4 (ARP, IPv6, LLDP, etc.)
                        if ethertype == 0x0806:  # ARP
                            if _eth is None:
                                try:
                                    _eth = dpkt.ethernet.Ethernet(buf)
                                except Exception:
                                    pass
                            if _eth is not None:
                                disc_an.feed(ts, buf, _eth)
                        elif ethertype == 0x88CC:  # LLDP
                            if _eth is None:
                                try:
                                    _eth = dpkt.ethernet.Ethernet(buf)
                                except Exception:
                                    pass
                            if _eth is not None:
                                disc_an.feed(ts, buf, _eth)
                        meta_an.feed(ts, buf, None)
                else:
                    meta_an.feed(ts, buf, None)

                # Deep analysis TLS / HTTP stream collection — reuse _eth
                if _DEEP_OK and _eth is not None:
                    try:
                        ip = _eth.data
                        if isinstance(ip, dpkt.ip.IP):
                            tcp = ip.data
                            if isinstance(tcp, dpkt.tcp.TCP):
                                payload = bytes(tcp.data)
                                if payload:
                                    src_ip = socket.inet_ntoa(ip.src)
                                    dst_ip = socket.inet_ntoa(ip.dst)
                                    sport, dport = tcp.sport, tcp.dport
                                    if (len(payload) > 9
                                            and payload[0] == 0x16
                                            and payload[1] == 0x03):
                                        tls_payloads.append((src_ip, dst_ip, payload))
                                    if dport in (80, 8080, 8000) or sport in (80, 8080, 8000):
                                        key = (src_ip, dst_ip, sport, dport)
                                        if len(http_streams[key]) < 4 * 1024 * 1024:
                                            http_streams[key].extend(payload)
                    except Exception:
                        pass

                if packet_count % 500 == 0:
                    raw_progress = int(f.tell() / file_size * 85)
                    new_progress = max(5, min(85, raw_progress))
                    if new_progress != last_reported:
                        jobs[job_id]["progress"]     = new_progress
                        jobs[job_id]["status_label"] = f"Parsing packets… ({packet_count:,} processed)"
                        last_reported = new_progress

    _finish_analysis(
        pcap_path, job_id, jobs, data_folder,
        meta_an, hosts_an, dns_an, http_an, beacon_an, smb_an, disc_an,
        tls_payloads, http_streams,
    )


# ── Multi-process path (regular PCAP ≥ 50 MB) ────────────────────
def _analyze_multi(pcap_path: str, job_id: str, jobs: dict, data_folder: str) -> None:
    jobs[job_id]["status"]       = "running"
    jobs[job_id]["progress"]     = 2
    jobs[job_id]["status_label"] = "Scanning packet offsets…"

    endian, ts_div, offsets = _scan_pcap_offsets(pcap_path)
    if not offsets:
        raise ValueError("No packets found in capture file")

    jobs[job_id]["progress"] = 5

    n_workers  = min(multiprocessing.cpu_count() or 1, 4)
    chunk_size = (len(offsets) + n_workers - 1) // n_workers
    chunks     = [offsets[i * chunk_size:(i + 1) * chunk_size] for i in range(n_workers)]
    chunks     = [c for c in chunks if c]
    n_actual   = len(chunks)

    jobs[job_id]["status_label"] = f"Parsing with {n_actual} core{'s' if n_actual != 1 else ''}…"

    ctx      = multiprocessing.get_context("spawn")
    result_q = ctx.Queue()

    processes = []
    for chunk in chunks:
        p = ctx.Process(
            target=_worker_process,
            args=(pcap_path, endian, ts_div, chunk, result_q),
            daemon=True,
        )
        p.start()
        processes.append(p)

    worker_states: list[dict] = []
    for _ in processes:
        try:
            state = result_q.get(timeout=3600)
            worker_states.append(state)
        except Exception:
            pass

    for p in processes:
        p.join(timeout=10)

    jobs[job_id]["progress"]     = 15
    jobs[job_id]["status_label"] = "Merging worker results…"

    meta_an   = MetaAnalyzer()
    hosts_an  = HostsAnalyzer()
    dns_an    = DnsAnalyzer()
    http_an   = HttpAnalyzer()
    beacon_an = BeaconingAnalyzer()
    smb_an    = SmbAnalyzer()
    disc_an   = DiscoveryAnalyzer()

    tls_payloads, http_streams = _merge_states(
        meta_an, hosts_an, dns_an, http_an, beacon_an, smb_an, disc_an,
        worker_states,
    )

    _finish_analysis(
        pcap_path, job_id, jobs, data_folder,
        meta_an, hosts_an, dns_an, http_an, beacon_an, smb_an, disc_an,
        tls_payloads, http_streams,
    )


# ── Main entry point ──────────────────────────────────────────────
def analyze(pcap_path: str, job_id: str, jobs: dict, data_folder: str) -> None:
    try:
        file_size = os.path.getsize(pcap_path)
        if is_pcapng(pcap_path) or file_size < 50 * 1024 * 1024:
            _analyze_single(pcap_path, job_id, jobs, data_folder)
        else:
            _analyze_multi(pcap_path, job_id, jobs, data_folder)
    except Exception as exc:
        jobs[job_id]["status"] = "error"
        jobs[job_id]["error"]  = str(exc)
        err_path = os.path.join(data_folder, f"{job_id}.error")
        try:
            with open(err_path, "w") as f:
                f.write(str(exc))
        except OSError:
            pass
