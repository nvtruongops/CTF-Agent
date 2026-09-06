#!/usr/bin/env python3
"""
CVE & Threat Intelligence Lookup Utility (v2.0)
Authoritative vulnerability intelligence pipeline for CTF Agents & Security Researchers:
- CVE List V5 / CVE Services API (cveawg.mitre.org)
- FIRST EPSS API (api.first.org)
- CISA KEV (Known Exploited Vulnerabilities) catalog check
"""

import sys
import json
import urllib.request
import urllib.error
from typing import Optional, Dict, Any, List

USER_AGENT = "CTF-Agent-ThreatIntel/2.0"
TIMEOUT = 10


def fetch_json(url: str) -> Optional[Dict[str, Any]]:
    """Fetch JSON payload from a remote endpoint with custom headers."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def get_cve_details(cve_id: str) -> Optional[Dict[str, Any]]:
    """Query official CVE Services API (CVE List V5 format)."""
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    return fetch_json(url)


def get_epss_score(cve_id: str) -> Optional[Dict[str, Any]]:
    """Query FIRST EPSS API for exploitation probability and percentile."""
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    data = fetch_json(url)
    if data and "data" in data and len(data["data"]) > 0:
        return data["data"][0]
    return None


def check_cisa_kev(cve_id: str) -> Dict[str, Any]:
    """Check if CVE is listed in CISA Known Exploited Vulnerabilities catalog."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    data = fetch_json(url)
    if not data:
        return {"listed": False, "error": "Unable to reach CISA KEV feed"}

    vulns = data.get("vulnerabilities", [])
    for v in vulns:
        if v.get("cveID", "").upper() == cve_id:
            return {
                "listed": True,
                "vendorProject": v.get("vendorProject", "Unknown"),
                "product": v.get("product", "Unknown"),
                "vulnerabilityName": v.get("vulnerabilityName", "N/A"),
                "dateAdded": v.get("dateAdded", "N/A"),
                "requiredAction": v.get("requiredAction", "N/A"),
                "knownRansomwareCampaignUse": v.get("knownRansomwareCampaignUse", "Unknown"),
            }
    return {"listed": False}


def parse_and_display(cve_id: str) -> None:
    """Execute end-to-end vulnerability intelligence lookup and render summary."""
    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        cve_id = "CVE-" + cve_id

    print("\n" + "=" * 70)
    print(f"[*] VULNERABILITY THREAT INTELLIGENCE: {cve_id}")
    print("=" * 70)

    # 1. Fetch CVE Services Record (CVE List V5)
    cve_data = get_cve_details(cve_id)
    if not cve_data:
        print(f"[-] Error: Record for {cve_id} not found in CVE List V5 repository.")
        return

    cve_metadata = cve_data.get("cveMetadata", {})
    state = cve_metadata.get("state", "UNKNOWN")
    cna_container = cve_data.get("containers", {}).get("cna", {})

    title = cna_container.get("title", "No title provided by CNA")
    descriptions = cna_container.get("descriptions", [])
    desc_text = "No description available."
    for d in descriptions:
        if d.get("lang") in ("en", "en-US", None):
            desc_text = d.get("value", desc_text)
            break

    print(f"\n[+] STATUS: {state} | CNA: {cve_metadata.get('assignerShortName', 'Unknown')}")
    print(f"[+] TITLE : {title}\n")
    print(f"[+] DESCRIPTION:\n    {desc_text.strip()}\n")

    # 2. Affected Components (CNA Scope)
    affected = cna_container.get("affected", [])
    if affected:
        print("[+] AFFECTED PRODUCTS & VERSIONS:")
        for aff in affected[:5]:
            vendor = aff.get("vendor", "Unknown")
            product = aff.get("product", "Unknown")
            versions = aff.get("versions", [])
            v_list = []
            for v in versions[:4]:
                ver = v.get("version", "")
                status = v.get("status", "")
                v_list.append(f"{ver} ({status})")
            ver_str = ", ".join(v_list) if v_list else "Unspecified"
            print(f"    - {vendor} / {product} -> {ver_str}")
        print()

    # 3. Metrics (CVSS)
    metrics = cna_container.get("metrics", [])
    if metrics:
        print("[+] METRICS & BASE SCORES:")
        for m in metrics:
            for cvss_key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                if cvss_key in m:
                    cvss = m[cvss_key]
                    score = cvss.get("baseScore", "N/A")
                    severity = cvss.get("baseSeverity", "N/A")
                    vector = cvss.get("vectorString", "N/A")
                    print(f"    - {cvss_key}: {score} ({severity}) | Vector: {vector}")
        print()

    # 4. FIRST EPSS (Exploit Prediction Scoring System)
    epss_info = get_epss_score(cve_id)
    print("[+] EPSS PROBABILITY (FIRST.org):")
    if epss_info:
        epss_prob = float(epss_info.get("epss", 0.0))
        epss_pct = float(epss_info.get("percentile", 0.0)) * 100.0
        print(f"    - Exploitation Probability (30-day): {epss_prob:.4f} ({epss_prob * 100:.2f}%)")
        print(f"    - EPSS Percentile: {epss_pct:.2f}% (Higher than {epss_pct:.2f}% of all CVEs)")
        print("    - Note: High EPSS indicates active wild targeting; low EPSS does not imply unexploitable in CTF.")
    else:
        print("    - No EPSS data available.")
    print()

    # 5. CISA KEV Catalog Check
    kev_info = check_cisa_kev(cve_id)
    print("[+] CISA KEV (KNOWN EXPLOITED VULNERABILITIES):")
    if kev_info.get("listed"):
        print(f"    - [CRITICAL] In CISA KEV Catalog: YES (Active in-the-wild exploitation confirmed)")
        print(f"    - Vulnerability Name: {kev_info.get('vulnerabilityName')}")
        print(f"    - Added to KEV: {kev_info.get('dateAdded')}")
        print(f"    - Known Ransomware Campaign Use: {kev_info.get('knownRansomwareCampaignUse')}")
    elif "error" in kev_info:
        print(f"    - Status: {kev_info.get('error')}")
    else:
        print("    - Listed in CISA KEV: NO (No federal mandate / confirmed broad in-the-wild exploitation yet)")
    print()

    # 6. Authoritative References
    references = cna_container.get("references", [])
    if references:
        print(f"[+] AUTHORITATIVE REFERENCES ({len(references)} total):")
        for ref in references[:8]:
            ref_url = ref.get("url", "")
            tags = ref.get("tags", [])
            tag_str = f" [{', '.join(tags)}]" if tags else ""
            print(f"    - {ref_url}{tag_str}")
        print()
    print("=" * 70 + "\n")


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/cve_lookup.py <CVE-YYYY-NNNN>")
        print("Example: python3 scripts/cve_lookup.py CVE-2023-44487")
        sys.exit(1)

    cve_arg = sys.argv[1]
    parse_and_display(cve_arg)


if __name__ == "__main__":
    main()
