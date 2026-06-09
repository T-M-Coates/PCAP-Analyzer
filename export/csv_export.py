"""
CSV export for the IOC list.

Columns: severity, type, value, description, vt_malicious, country, asn, is_known_c2

Usage:
    from export.csv_export import iocs_to_csv
    csv_str = iocs_to_csv(results)
"""
from __future__ import annotations
import csv
import io


def iocs_to_csv(results: dict) -> str:
    """
    Convert the IOC section of a results dict to a CSV string.
    Handles missing enrichment data gracefully.
    """
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow([
        "severity", "type", "value", "description",
        "source_module", "vt_malicious", "vt_total",
        "country", "asn", "is_known_c2",
    ])

    for ioc in results.get("iocs", {}).get("iocs", []):
        enr = ioc.get("enrichment") or {}
        writer.writerow([
            ioc.get("severity", ""),
            ioc.get("type", ""),
            ioc.get("value", ""),
            ioc.get("description", ""),
            ioc.get("source_module", ""),
            enr.get("vt_malicious", ""),
            enr.get("vt_total", ""),
            enr.get("country", ""),
            enr.get("asn_description", "") or enr.get("asn", ""),
            enr.get("is_known_c2", ""),
        ])

    return output.getvalue()
