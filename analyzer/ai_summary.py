"""
AI-assisted incident narrative generation using the Claude API.

Accepts a structured dict of PCAP analysis results and returns a 2-3 paragraph
plain-English incident summary suitable for a SOC report or analyst briefing.
"""
import os

try:
    import anthropic
    _ANTHROPIC_OK = True
except ImportError:
    _ANTHROPIC_OK = False

_MODEL = "claude-opus-4-8"
_SYSTEM = (
    "You are a senior cybersecurity analyst writing incident reports. "
    "Be concise, accurate, and professional. Use threat analysis terminology "
    "(C2, beacon, lateral movement, exfiltration, etc.). "
    "Base your analysis strictly on the evidence provided — do not speculate "
    "beyond what the data supports. "
    "Format your response as 2-3 plain paragraphs with no headers or bullet points."
)


def _build_prompt(data: dict) -> str:
    """Render structured analysis data as a concise evidence block for the model."""
    lines = [
        "Analyse the following network capture evidence and write a professional "
        "incident summary.\n\n--- EVIDENCE ---\n"
    ]

    if data.get('capture_info'):
        ci = data['capture_info']
        lines.append(
            f"Capture: {ci.get('duration_minutes', 0):.1f} min, "
            f"{ci.get('total_packets', 0):,} flow-packets, "
            f"start {ci.get('start_time', 'unknown')} UTC\n"
        )

    if data.get('internal_hosts'):
        hosts = sorted(data['internal_hosts'])[:10]
        lines.append(f"Internal hosts: {', '.join(hosts)}\n")

    if data.get('external_hosts'):
        lines.append(f"Unique external IPs contacted: {len(data['external_hosts'])}\n")

    if data.get('beacons'):
        lines.append("\nBeaconing detected:\n")
        for b in data['beacons'][:4]:
            lines.append(
                f"  {b['src']} → {b['dst']}:{b['port']}  "
                f"every ~{b['interval_s']:.0f}s  "
                f"CV={b['cv']:.2f}  {b['packet_count']} pkts\n"
            )

    if data.get('post_requests'):
        lines.append(f"\nPOST requests (potential C2 check-in / exfil): "
                     f"{len(data['post_requests'])}\n")
        for p in data['post_requests'][:3]:
            lines.append(f"  {p['src']} → {p['host']} | {p.get('path','')[:80]}\n")

    if data.get('suspicious_urls'):
        lines.append(f"\nSuspicious URL patterns: {len(data['suspicious_urls'])}\n")
        for u in data['suspicious_urls'][:3]:
            lines.append(f"  [{u['keyword']}] {u['host']} | {u['request'][:80]}\n")

    if data.get('suspicious_domains'):
        lines.append(f"\nSuspicious domains ({len(data['suspicious_domains'])}):\n")
        seen: set[str] = set()
        for d in data['suspicious_domains']:
            if d['domain'] not in seen:
                seen.add(d['domain'])
                lines.append(f"  {d['domain']} ({d['reason']})\n")
                if len(seen) >= 5:
                    break

    if data.get('smb_pairs'):
        lines.append("\nSMB / lateral movement:\n")
        for s in data['smb_pairs'][:3]:
            lines.append(
                f"  {s['src']} → {s['dst']}:{s['port']}  {s['count']} pkts\n"
            )

    if data.get('malware_matches'):
        lines.append("\nMalware family indicators:\n")
        for m in data['malware_matches'][:3]:
            inds = '; '.join(m['indicators'][:3])
            lines.append(f"  {m['family']} ({m['confidence']}): {inds}\n")

    if data.get('ja3_flags'):
        lines.append("\nKnown-malicious JA3 fingerprints:\n")
        for j in data['ja3_flags'][:3]:
            lines.append(
                f"  {j['hash'][:16]}… → {j['label']}  ({j['src']} → {j['dst']})\n"
            )

    if data.get('cert_flags'):
        lines.append("\nSuspicious TLS certificates:\n")
        for c in data['cert_flags'][:3]:
            lines.append(
                f"  CN={c.get('cn', 'unknown')}  [{', '.join(c['flags'])}]  "
                f"({c.get('src', '?')} → {c.get('dst', '?')})\n"
            )

    if data.get('extracted_files'):
        lines.append(f"\nFiles extracted from traffic ({len(data['extracted_files'])}):\n")
        for fi in data['extracted_files'][:3]:
            lines.append(
                f"  {fi['filename']}  {fi['content_type']}  "
                f"{fi['size']:,} B  SHA256:{fi['sha256'][:16]}…\n"
            )

    if data.get('imap_connections', 0):
        lines.append(
            f"\nIMAP/IMAPS connections: {data['imap_connections']} "
            "(potential email exfiltration)\n"
        )

    no_iocs = not any(data.get(k) for k in (
        'beacons', 'post_requests', 'suspicious_urls', 'suspicious_domains',
        'smb_pairs', 'malware_matches', 'ja3_flags', 'cert_flags', 'extracted_files',
    ))
    if no_iocs:
        lines.append("\nNo significant malware indicators detected in this capture.\n")

    return ''.join(lines)


def generate_narrative(analysis_data: dict, api_key: str = '') -> str:
    """
    Generate a plain-English incident narrative using claude-opus-4-8.

    Args:
        analysis_data: structured dict from the PCAP analysis pipeline
        api_key:        Anthropic API key; falls back to ANTHROPIC_API_KEY env var

    Returns:
        Narrative string, or an explanatory error message if unavailable.
    """
    if not _ANTHROPIC_OK:
        return "[AI summary unavailable: 'anthropic' library not installed]"

    key = api_key or os.getenv('ANTHROPIC_API_KEY', '')
    if not key:
        return "[AI summary unavailable: ANTHROPIC_API_KEY not set]"

    prompt = _build_prompt(analysis_data)

    try:
        client = anthropic.Anthropic(api_key=key)

        with client.messages.stream(
            model=_MODEL,
            max_tokens=1024,
            thinking={"type": "adaptive"},
            system=_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        ) as stream:
            final = stream.get_final_message()
            # Return the first text block (thinking blocks are skipped)
            return next(
                (b.text for b in final.content if b.type == "text"),
                "[No text response received]",
            )

    except anthropic.AuthenticationError:
        return "[AI summary failed: invalid API key — check ANTHROPIC_API_KEY]"
    except anthropic.RateLimitError:
        return "[AI summary failed: Anthropic API rate limit exceeded]"
    except anthropic.APIConnectionError:
        return "[AI summary failed: could not reach Anthropic API]"
    except Exception as e:
        return f"[AI summary failed: {e}]"
