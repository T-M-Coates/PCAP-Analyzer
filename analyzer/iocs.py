from __future__ import annotations

_SUSP_TLDS = {'.ga', '.cf', '.ml', '.tk', '.pw', '.top', '.xyz', '.su'}
_EXE_EXTS = {'.exe', '.zip', '.dll', '.ps1', '.bat'}
_SYSINFO_KEYWORDS = [
    'windows', 'kaspersky', 'norton', 'mcafee', 'avast', 'eset',
    'defender', 'malwarebytes', 'computername', 'username', 'hostname',
]


def _tld(domain: str) -> str:
    parts = domain.rsplit('.', 1)
    return '.' + parts[-1] if len(parts) > 1 else ''


def _make_ioc(type_: str, value: str, severity: str, description: str, source: str) -> dict:
    return {
        "type": type_,
        "value": value,
        "severity": severity,
        "description": description,
        "source_module": source,
    }


def aggregate(dns_results: dict, http_results: dict, beaconing_results: dict, smb_results: dict, discovery_results: dict | None = None) -> dict:
    iocs: list[dict] = []
    seen: set[tuple] = set()

    def add(ioc: dict) -> None:
        key = (ioc["type"], ioc["value"])
        if key not in seen:
            seen.add(key)
            iocs.append(ioc)

    flagged_dns_domains = {f["domain"] for f in dns_results.get("flagged", []) if "PTR" not in f.get("flags", [])}
    dc = smb_results.get("dc_candidate")

    # --- DNS flags ---
    for entry in dns_results.get("flagged", []):
        domain = entry["domain"]
        flags = entry.get("flags", [])

        if "PTR" in flags:
            ip = domain.replace("PTR:", "")
            add(_make_ioc("ip", ip, "INFO", "Reverse DNS (PTR) lookup observed", "dns"))
            continue

        if "SUSP_TLD" in flags:
            add(_make_ioc("domain", domain, "MEDIUM", f"Contact with suspicious TLD domain: {domain}", "dns"))

        if "HEX32" in flags:
            add(_make_ioc("domain", domain, "HIGH",
                          f"Subdomain matches 32-char hex pattern (possible DGA or DNS C2): {domain}", "dns"))

        if "HIGH_FREQ" in flags and "SUSP_TLD" not in flags and "HEX32" not in flags:
            add(_make_ioc("domain", domain, "INFO",
                          f"Unusually high DNS query frequency: {entry['query_count']} queries", "dns"))

    # --- HTTP flags ---
    for req in http_results.get("flagged_requests", []):
        url = req.get("url", "")
        host = req.get("host", "")
        flags = req.get("flags", [])
        method = req.get("method", "")
        tld = _tld(host)

        # CRITICAL: executable/zip download from suspicious TLD
        if any(f.startswith("SUSP_PATH:") for f in flags) and tld in _SUSP_TLDS:
            path_flags = [f.replace("SUSP_PATH:", "") for f in flags if f.startswith("SUSP_PATH:")]
            for ext in path_flags:
                if any(ext.endswith(e) for e in _EXE_EXTS):
                    add(_make_ioc("url", url, "CRITICAL",
                                  f"Executable download ({ext}) from suspicious TLD domain {host}", "http"))
                    break

        # CRITICAL: POST to unknown domain with base64 body indicators
        if method.upper() == 'POST' and "POST_WITH_BODY" in flags and "B64_PARAM" in flags:
            add(_make_ioc("url", url, "CRITICAL",
                          f"POST request with encoded parameters to {host}", "http"))

        # HIGH: system info exfiltration in decoded URL params
        if "SYSINFO_EXFIL" in flags:
            add(_make_ioc("url", url, "HIGH",
                          f"Decoded URL parameter contains system/AV information at {host}", "http"))

        # MEDIUM: contact with flagged DNS domain
        if "FLAGGED_DOMAIN" in flags and not any(
            s in ["SYSINFO_EXFIL", "B64_PARAM"] for s in flags
        ):
            add(_make_ioc("domain", host, "MEDIUM", f"HTTP request to previously flagged domain {host}", "http"))

        # MEDIUM: suspicious path patterns (not already CRITICAL)
        for f in flags:
            if f.startswith("SUSP_PATH:") and tld not in _SUSP_TLDS:
                pat = f.replace("SUSP_PATH:", "")
                add(_make_ioc("url", url, "MEDIUM", f"Request to suspicious path pattern '{pat}'", "http"))

        # INFO: unusual User-Agent
        for f in flags:
            if f.startswith("SUSP_UA:"):
                ua_sub = f.replace("SUSP_UA:", "")
                add(_make_ioc("user_agent", req.get("user_agent", ua_sub), "INFO",
                              f"Non-browser User-Agent string contains '{ua_sub}'", "http"))

    # --- Beaconing flags ---
    for cand in beaconing_results.get("candidates", []):
        cv = cand["cv"]
        value = f"{cand['src']} -> {cand['dst']}:{cand['port']}"
        interval = cand["interval_s"]
        if cv < 0.05:
            add(_make_ioc("flow", value, "HIGH",
                          f"Machine-perfect beaconing: interval {interval}s, CV={cv:.4f}, {cand['packet_count']} packets",
                          "beaconing"))
        else:
            add(_make_ioc("flow", value, "MEDIUM",
                          f"Regular beaconing pattern: interval {interval}s, CV={cv:.4f}, {cand['packet_count']} packets",
                          "beaconing"))

    # --- SMB flags ---
    if smb_results.get("external_smb_sources"):
        for ext_ip in smb_results["external_smb_sources"]:
            add(_make_ioc("ip", ext_ip, "CRITICAL",
                          f"External IP {ext_ip} initiating SMB connection (possible ransomware / brute force)", "smb"))

    if dc:
        for pair in smb_results.get("pairs", []):
            if pair["dst"] == dc:
                src = pair["src"]
                add(_make_ioc("ip", src, "HIGH",
                              f"Host {src} sending SMB traffic to DC candidate {dc} ({pair['packet_count']} packets)",
                              "smb"))

    # --- MITM / Discovery flags ---
    if discovery_results:
        for flip in discovery_results.get("mac_flips", []):
            add(_make_ioc("mitm", flip["ip"], "CRITICAL",
                          flip.get("description", f"ARP spoofing: IP {flip['ip']} changed MAC"),
                          "discovery"))
        for entry in discovery_results.get("mac_multiip", []):
            add(_make_ioc("mitm", entry["mac"], "HIGH",
                          entry.get("description", f"MAC {entry['mac']} claimed multiple IPs"),
                          "discovery"))
        for race in discovery_results.get("dns_races", []):
            add(_make_ioc("mitm", race["domain"], "HIGH",
                          race.get("description", f"DNS conflict for {race['domain']}"),
                          "discovery"))
        for spoofer in discovery_results.get("name_spoofers", []):
            add(_make_ioc("mitm", spoofer["ip"], "HIGH",
                          spoofer.get("description", f"Name-service spoofing from {spoofer['ip']}"),
                          "discovery"))
        if discovery_results.get("grat_arps"):
            n = len(discovery_results["grat_arps"])
            first = discovery_results["grat_arps"][0]
            add(_make_ioc("mitm", first["ip"], "MEDIUM",
                          f"{n} gratuitous ARP repl{'ies' if n != 1 else 'y'} detected (possible cache poisoning attempt)",
                          "discovery"))

    # Sort by severity
    _order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
    iocs.sort(key=lambda x: _order.get(x["severity"], 99))

    return {
        "iocs": iocs,
        "critical_count": sum(1 for i in iocs if i["severity"] == "CRITICAL"),
        "high_count":     sum(1 for i in iocs if i["severity"] == "HIGH"),
        "medium_count":   sum(1 for i in iocs if i["severity"] == "MEDIUM"),
        "info_count":     sum(1 for i in iocs if i["severity"] == "INFO"),
    }
