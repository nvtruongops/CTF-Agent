#!/usr/bin/env python3
"""
CVE & Threat Intelligence Lookup Utility (v2.1)
Authoritative vulnerability intelligence pipeline for CTF Agents & Security Researchers:
- CVE List V5 / CVE Services API (cveawg.mitre.org)
- FIRST EPSS API (api.first.org)
- CISA KEV (Known Exploited Vulnerabilities) catalog with in-memory caching
- Exploit reference categorization (PoC, Exploit-DB, GitHub, Packet Storm)
- Decoupled CTF Challenge Relevance Layer
- Structured JSON output mode (--json)
"""

import sys
import os
import re
import time
import json
import urllib.request
import urllib.error
from functools import lru_cache
from typing import Optional, Dict, Any, List, Tuple

# Safe UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

USER_AGENT = "CTF-Agent-ThreatIntel/2.1"
TIMEOUT = 10
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")

EXPLOIT_URL_PATTERNS = [
    re.compile(r"exploit-db\.com", re.I),
    re.compile(r"packetstormsecurity\.com", re.I),
    re.compile(r"github\.com/[^/]+/(?:poc|exploit|cve-)", re.I),
    re.compile(r"0day\.today", re.I),
    re.compile(r"seclists\.org/fulldisclosure", re.I),
    re.compile(r"rapid7\.com/db", re.I),
    re.compile(r"sploitus\.com", re.I),
    re.compile(r"project-zero", re.I),
]
EXPLOIT_TAGS = {"exploit", "technical-description", "third-party-advisory"}


def normalize_cve_id(cve_id: str) -> str:
    """Validates and normalizes CVE identifier format (CVE-YYYY-NNNN)."""
    if not cve_id or not isinstance(cve_id, str) or not cve_id.strip():
        raise ValueError(f"Invalid CVE identifier: '{cve_id}'. Expected format: CVE-YYYY-NNNN")

    cleaned = cve_id.strip().upper()
    if not cleaned.startswith("CVE-"):
        cleaned = "CVE-" + cleaned

    if not CVE_PATTERN.fullmatch(cleaned):
        raise ValueError(f"Invalid CVE identifier: '{cve_id}'. Expected format: CVE-YYYY-NNNN")

    return cleaned


def fetch_json(url: str, retries: int = 2, backoff: float = 0.5) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Fetch JSON payload from a remote endpoint with retry logic and error classification.
    Returns (data_dict, error_message).
    """
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})

    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                content = resp.read().decode("utf-8")
                return json.loads(content), None
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None, f"HTTP 404: Resource not found at {url}"
            if exc.code == 429 and attempt < retries:
                time.sleep(backoff * (2 ** attempt))
                continue
            if exc.code in (500, 502, 503, 504) and attempt < retries:
                time.sleep(backoff * (2 ** attempt))
                continue
            return None, f"HTTP error {exc.code} while fetching {url}: {exc.reason}"
        except urllib.error.URLError as exc:
            if attempt < retries:
                time.sleep(backoff * (2 ** attempt))
                continue
            return None, f"Network error connecting to {url}: {exc.reason}"
        except json.JSONDecodeError as exc:
            return None, f"Malformed JSON response from {url}: {exc}"
        except Exception as exc:
            return None, f"Unexpected error fetching {url}: {exc}"

    return None, f"Failed to fetch {url} after {retries + 1} attempts"


def get_cve_details(cve_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Query official CVE Services API (CVE List V5 format)."""
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    return fetch_json(url)


def get_epss_score(cve_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Query FIRST EPSS API for exploitation probability and percentile."""
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    data, err = fetch_json(url)
    if data and "data" in data and len(data["data"]) > 0:
        return data["data"][0], None
    return None, err or "No EPSS record returned"


@lru_cache(maxsize=1)
def get_cisa_kev_catalog() -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Downloads and caches the official CISA KEV catalog in memory.
    Cached across lookups to avoid downloading multi-megabyte feeds repeatedly.
    """
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    return fetch_json(url)


def check_cisa_kev(cve_id: str) -> Dict[str, Any]:
    """Check if CVE is listed in CISA Known Exploited Vulnerabilities catalog."""
    data, err = get_cisa_kev_catalog()
    if not data:
        return {"listed": False, "error": err or "Unable to reach CISA KEV feed"}

    vulns = data.get("vulnerabilities", [])
    target_id = cve_id.upper()
    for v in vulns:
        if v.get("cveID", "").upper() == target_id:
            return {
                "listed": True,
                "vendorProject": v.get("vendorProject", "Unknown"),
                "product": v.get("product", "Unknown"),
                "vulnerabilityName": v.get("vulnerabilityName", "N/A"),
                "dateAdded": v.get("dateAdded", "N/A"),
                "requiredAction": v.get("requiredAction", "N/A"),
                "knownRansomwareCampaignUse": v.get("knownRansomwareCampaignUse", "Unknown"),
                "note": "Exploitation has been confirmed historically in the wild",
            }
    return {
        "listed": False,
        "note": "No federal mandate / confirmed broad in-the-wild exploitation recorded in KEV catalog",
    }


def classify_references(references: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Classifies external references into general advisories vs public exploit PoCs."""
    exploit_urls: List[str] = []
    other_urls: List[str] = []

    for ref in references:
        url = ref.get("url", "")
        tags = set(ref.get("tags", []))
        is_exploit = bool(tags & EXPLOIT_TAGS) or any(pat.search(url) for pat in EXPLOIT_URL_PATTERNS)

        if is_exploit:
            exploit_urls.append(url)
        else:
            other_urls.append(url)

    return {
        "total": len(references),
        "exploit_related": len(exploit_urls),
        "exploit_urls": exploit_urls,
        "general_urls": other_urls[:5],
    }


def assess_ctf_relevance(
    cve_data: Optional[Dict[str, Any]],
    epss_info: Optional[Dict[str, Any]],
    kev_info: Dict[str, Any],
    ref_info: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Computes educational CTF challenge relevance heuristic score and signals.
    Note: Decoupled strictly from EPSS (real-world probability) and CVSS (severity).
    """
    score = 0.0
    signals: List[str] = []

    # 1. Public PoC / Exploit availability (strongest CTF indicator)
    if ref_info.get("exploit_related", 0) > 0:
        score += 0.35
        signals.append(f"public_exploit_poc_available ({ref_info['exploit_related']} references)")

    # 2. Historical confirmed exploitation (CISA KEV)
    if kev_info.get("listed"):
        score += 0.25
        signals.append("cisa_kev_listed")

    # 3. CVSS metrics extraction
    cvss_score = 0.0
    cvss_vector = ""
    if cve_data:
        cna = cve_data.get("containers", {}).get("cna", {})
        metrics = cna.get("metrics", [])
        for m in metrics:
            for cvss_key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                if cvss_key in m:
                    cvss = m[cvss_key]
                    try:
                        cvss_score = max(cvss_score, float(cvss.get("baseScore", 0.0)))
                    except (ValueError, TypeError):
                        pass
                    cvss_vector = cvss.get("vectorString", cvss_vector)

    if cvss_score >= 7.0:
        score += 0.20
        signals.append(f"high_severity_cvss ({cvss_score})")

    if "AV:N" in cvss_vector:
        score += 0.15
        signals.append("network_attack_vector (AV:N)")

    if "PR:N" in cvss_vector or "PR:L" in cvss_vector:
        score += 0.10
        signals.append("low_or_none_privileges_required")

    if "UI:N" in cvss_vector:
        score += 0.10
        signals.append("no_user_interaction_required")

    # 4. Web / RCE / Memory corruption keywords
    text_content = ""
    if cve_data:
        cna = cve_data.get("containers", {}).get("cna", {})
        title = cna.get("title", "")
        desc = " ".join(d.get("value", "") for d in cna.get("descriptions", []))
        text_content = f"{title} {desc}".lower()

    web_keywords = ["remote code execution", "rce", "sql injection", "command injection", "buffer overflow", "deserialization", "authentication bypass", "memory corruption"]
    matched_kws = [kw for kw in web_keywords if kw in text_content]
    if matched_kws:
        score += 0.15
        signals.append(f"challenge_vulnerability_pattern ({', '.join(matched_kws[:3])})")

    normalized_score = min(1.0, round(score, 2))
    return {
        "score": normalized_score,
        "signals": signals,
        "note": "CTF relevance is an educational challenge heuristic based on public exploit availability and network reachability; it is strictly distinct from EPSS and CVSS.",
    }


def lookup_cve_threat_intel(cve_id: str) -> Dict[str, Any]:
    """End-to-end vulnerability threat intelligence pipeline returning structured data."""
    norm_cve = normalize_cve_id(cve_id)
    errors: List[str] = []

    # 1. Fetch MITRE CVE V5 Record
    cve_data, cve_err = get_cve_details(norm_cve)
    if cve_err:
        errors.append(cve_err)

    if not cve_data:
        return {
            "status": "error",
            "cve": norm_cve,
            "error": cve_err or f"Record for {norm_cve} not found in CVE List V5 repository.",
        }

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

    # 2. Extract CVSS
    cvss_info: Dict[str, Any] = {}
    metrics = cna_container.get("metrics", [])
    for m in metrics:
        for cvss_key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            if cvss_key in m:
                c = m[cvss_key]
                cvss_info = {
                    "version": cvss_key.replace("cvssV", "").replace("_", "."),
                    "score": c.get("baseScore", "N/A"),
                    "severity": c.get("baseSeverity", "N/A"),
                    "vector": c.get("vectorString", "N/A"),
                }
                break
        if cvss_info:
            break

    # 3. Affected Products
    affected_list = []
    for aff in cna_container.get("affected", [])[:5]:
        v_list = [f"{v.get('version', '')} ({v.get('status', '')})" for v in aff.get("versions", [])[:3]]
        affected_list.append({
            "vendor": aff.get("vendor", "Unknown"),
            "product": aff.get("product", "Unknown"),
            "versions": v_list,
        })

    # 4. FIRST EPSS
    epss_raw, epss_err = get_epss_score(norm_cve)
    if epss_err:
        errors.append(epss_err)

    epss_info: Dict[str, Any] = {}
    if epss_raw:
        epss_prob = float(epss_raw.get("epss", 0.0))
        epss_pct = float(epss_raw.get("percentile", 0.0))
        epss_info = {
            "score": epss_prob,
            "percentile": epss_pct,
            "note": "EPSS estimates the probability of exploitation in the wild; it is not proof of active exploitation and should not be treated as a CTF exploitability score.",
        }

    # 5. CISA KEV
    kev_info = check_cisa_kev(norm_cve)

    # 6. References Classification
    raw_refs = cna_container.get("references", [])
    ref_info = classify_references(raw_refs)

    # 7. CTF Relevance Assessment
    relevance = assess_ctf_relevance(cve_data, epss_raw, kev_info, ref_info)

    return {
        "status": "success",
        "cve": norm_cve,
        "state": state,
        "cna": cve_metadata.get("assignerShortName", "Unknown"),
        "title": title,
        "description": desc_text.strip(),
        "affected": affected_list,
        "cvss": cvss_info,
        "epss": epss_info,
        "kev": kev_info,
        "references": ref_info,
        "ctf_relevance": relevance,
        "errors": errors,
    }


def display_human_summary(intel: Dict[str, Any]) -> None:
    """Renders formatted console output from structured threat intelligence data."""
    cve_id = intel["cve"]
    print("\n" + "=" * 70)
    print(f"[*] VULNERABILITY THREAT INTELLIGENCE: {cve_id}")
    print("=" * 70)

    print(f"\n[+] STATUS: {intel.get('state')} | CNA: {intel.get('cna')}")
    print(f"[+] TITLE : {intel.get('title')}\n")
    print(f"[+] DESCRIPTION:\n    {intel.get('description')}\n")

    # Affected products
    affected = intel.get("affected", [])
    if affected:
        print("[+] AFFECTED PRODUCTS & VERSIONS:")
        for aff in affected:
            ver_str = ", ".join(aff["versions"]) if aff["versions"] else "Unspecified"
            print(f"    - {aff['vendor']} / {aff['product']} -> {ver_str}")
        print()

    # Metrics
    cvss = intel.get("cvss", {})
    if cvss:
        print(f"[+] CVSS BASE METRICS (v{cvss.get('version', '3.x')}):")
        print(f"    - Score: {cvss.get('score')} ({cvss.get('severity')}) | Vector: {cvss.get('vector')}\n")

    # EPSS
    epss = intel.get("epss", {})
    print("[+] EPSS PROBABILITY (FIRST.org):")
    if epss and "score" in epss:
        score = epss["score"]
        pct = epss["percentile"] * 100.0
        print(f"    - Exploitation Probability (30-day): {score:.4f} ({score * 100:.2f}%)")
        print(f"    - Percentile: {pct:.2f}%")
        print(f"    - Note: {epss.get('note')}")
    else:
        print("    - No EPSS data available.")
    print()

    # CISA KEV
    kev = intel.get("kev", {})
    print("[+] CISA KEV (KNOWN EXPLOITED VULNERABILITIES):")
    if kev.get("listed"):
        print(f"    - [HIGH] Listed in CISA KEV: YES (exploitation has been confirmed)")
        print(f"    - Vulnerability Name: {kev.get('vulnerabilityName')}")
        print(f"    - Date Added: {kev.get('dateAdded')}")
        print(f"    - Known Ransomware Campaign Use: {kev.get('knownRansomwareCampaignUse')}")
    elif "error" in kev:
        print(f"    - Status: {kev.get('error')}")
    else:
        print(f"    - Listed in CISA KEV: NO ({kev.get('note')})")
    print()

    # Exploit References
    refs = intel.get("references", {})
    print(f"[+] REFERENCES ({refs.get('total', 0)} total, {refs.get('exploit_related', 0)} exploit-related):")
    if refs.get("exploit_urls"):
        print("    [!] Public PoC / Exploit References:")
        for e_url in refs["exploit_urls"][:6]:
            print(f"        * {e_url}")
    for g_url in refs.get("general_urls", [])[:3]:
        print(f"    - {g_url}")
    print()

    # CTF Relevance
    ctf_rel = intel.get("ctf_relevance", {})
    print(f"[+] CTF CHALLENGE RELEVANCE (Heuristic Score: {ctf_rel.get('score', 0.0):.2f}/1.0):")
    for sig in ctf_rel.get("signals", []):
        print(f"    - [Signal] {sig}")
    print(f"    - Note: {ctf_rel.get('note')}")
    print("=" * 70 + "\n")


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="CTF-Agent Vulnerability Threat Intelligence Utility v2.1")
    parser.add_argument("cve", help="CVE identifier (e.g. CVE-2023-44487 or 2023-44487)")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON structure")

    args = parser.parse_args()

    try:
        norm_cve = normalize_cve_id(args.cve)
    except ValueError as exc:
        if args.json:
            print(json.dumps({"status": "error", "error": str(exc)}, indent=2))
        else:
            print(f"[-] Input Error: {exc}", file=sys.stderr)
        sys.exit(1)

    intel = lookup_cve_threat_intel(norm_cve)

    if intel.get("status") == "error":
        if args.json:
            print(json.dumps(intel, indent=2))
        else:
            print(f"[-] Error: {intel.get('error')}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(intel, indent=2))
    else:
        display_human_summary(intel)


if __name__ == "__main__":
    main()
