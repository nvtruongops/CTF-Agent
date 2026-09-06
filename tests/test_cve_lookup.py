#!/usr/bin/env python3
"""
Unit and Integration Tests for CVE Threat Intelligence Pipeline (v2.1)
Validates CVE identifier normalization, CISA KEV catalog caching, exploit classification,
CTF relevance heuristics, EPSS/KEV semantics, and JSON output formatting.
"""

import sys
import json
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from cve_lookup import (
    normalize_cve_id,
    classify_references,
    assess_ctf_relevance,
    check_cisa_kev,
    get_cisa_kev_catalog,
    lookup_cve_threat_intel,
)


def test_normalize_cve_id_valid_formats():
    """Verifies that valid CVE identifiers are correctly normalized to standard uppercase format."""
    valid_cases = [
        ("CVE-2023-44487", "CVE-2023-44487"),
        ("cve-2023-44487", "CVE-2023-44487"),
        ("2023-44487", "CVE-2023-44487"),
        ("  CVE-2021-34527  ", "CVE-2021-34527"),
        ("CVE-2024-1234567", "CVE-2024-1234567"),
    ]
    for raw, expected in valid_cases:
        assert normalize_cve_id(raw) == expected


def test_normalize_cve_id_invalid_formats():
    """Verifies that malformed or malicious inputs raise ValueError with clear guidance."""
    invalid_cases = [
        "",
        "   ",
        "CVE",
        "CVE-2023",
        "CVE-ABCD-1234",
        "CVE-2023-abc",
        "2023-abc",
        "../../etc/passwd",
        "CVE-23-1234",
    ]
    for bad in invalid_cases:
        with pytest.raises(ValueError, match="Invalid CVE identifier"):
            normalize_cve_id(bad)


def test_classify_references_identifies_exploit_pocs():
    """Verifies classification of external references into general advisories vs public exploit PoCs."""
    sample_refs = [
        {"url": "https://www.exploit-db.com/exploits/51234", "tags": ["exploit"]},
        {"url": "https://github.com/rapid7/metasploit-framework", "tags": []},
        {"url": "https://github.com/attacker/cve-2023-44487-poc", "tags": ["third-party-advisory"]},
        {"url": "https://packetstormsecurity.com/files/175000/poc.txt", "tags": []},
        {"url": "https://nvd.nist.gov/vuln/detail/CVE-2023-44487", "tags": ["technical-description"]},
        {"url": "https://vendor.com/security-bulletin/2023", "tags": ["patch"]},
    ]

    res = classify_references(sample_refs)
    assert res["total"] == 6
    assert res["exploit_related"] >= 4
    assert any("exploit-db.com" in u for u in res["exploit_urls"])
    assert any("packetstormsecurity.com" in u for u in res["exploit_urls"])
    assert any("cve-2023-44487-poc" in u for u in res["exploit_urls"])


def test_assess_ctf_relevance_heuristic_scoring():
    """Verifies CTF challenge relevance score computation and decoupled educational notes."""
    mock_cve_data = {
        "containers": {
            "cna": {
                "title": "HTTP/2 Rapid Reset Remote Code Execution Denial of Service",
                "descriptions": [{"value": "Allows remote attackers to trigger RCE and bypass memory protections via HTTP/2."}],
                "metrics": [
                    {
                        "cvssV3_1": {
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        }
                    }
                ],
            }
        }
    }
    mock_epss = {"epss": "0.95", "percentile": "0.99"}
    mock_kev = {"listed": True}
    mock_refs = {
        "total": 5,
        "exploit_related": 2,
        "exploit_urls": ["https://www.exploit-db.com/exploits/123"],
    }

    relevance = assess_ctf_relevance(mock_cve_data, mock_epss, mock_kev, mock_refs)
    assert relevance["score"] >= 0.8
    assert "public_exploit_poc_available (2 references)" in relevance["signals"]
    assert "cisa_kev_listed" in relevance["signals"]
    assert "network_attack_vector (AV:N)" in relevance["signals"]
    assert "strictly distinct from EPSS and CVSS" in relevance["note"]


def test_cisa_kev_catalog_caching():
    """Verifies that get_cisa_kev_catalog uses LRU caching and does not redownload on repeat calls."""
    mock_catalog = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2023-44487",
                "vendorProject": "Multiple Vendors",
                "product": "HTTP/2 Protocol",
                "vulnerabilityName": "HTTP/2 Rapid Reset",
                "dateAdded": "2023-10-10",
                "requiredAction": "Apply mitigations",
                "knownRansomwareCampaignUse": "Known",
            }
        ]
    }

    get_cisa_kev_catalog.cache_clear()
    with patch("cve_lookup.fetch_json", return_value=(mock_catalog, None)) as mock_fetch:
        res1 = check_cisa_kev("CVE-2023-44487")
        assert res1["listed"] is True
        assert res1["vendorProject"] == "Multiple Vendors"
        assert "confirmed historically" in res1["note"]

        # Second lookup should hit cache
        res2 = check_cisa_kev("CVE-2023-44487")
        assert res2["listed"] is True

        # Third lookup for unlisted CVE
        res3 = check_cisa_kev("CVE-1999-9999")
        assert res3["listed"] is False
        assert "No federal mandate" in res3["note"]

        # Only one HTTP fetch should have occurred
        assert mock_fetch.call_count == 1


def test_epss_and_kev_semantics():
    """Verifies that EPSS and KEV textual notes adhere to strict statistical and threat definitions."""
    with patch("cve_lookup.get_cve_details") as mock_cve, \
         patch("cve_lookup.get_epss_score") as mock_epss, \
         patch("cve_lookup.get_cisa_kev_catalog") as mock_kev:

        mock_cve.return_value = (
            {
                "cveMetadata": {"state": "PUBLISHED", "assignerShortName": "google"},
                "containers": {
                    "cna": {
                        "title": "Sample CVE",
                        "descriptions": [{"value": "Test description"}],
                        "metrics": [],
                        "references": [],
                    }
                },
            },
            None,
        )
        mock_epss.return_value = ({"epss": "0.45", "percentile": "0.75"}, None)
        mock_kev.return_value = ({"vulnerabilities": []}, None)

        intel = lookup_cve_threat_intel("CVE-2023-12345")
        assert intel["status"] == "success"

        # Check EPSS semantics
        epss_note = intel["epss"]["note"]
        assert "EPSS estimates the probability of exploitation in the wild" in epss_note
        assert "not proof of active exploitation" in epss_note
        assert "should not be treated as a CTF exploitability score" in epss_note

        # Check KEV semantics
        kev_note = intel["kev"]["note"]
        assert "No federal mandate" in kev_note


def test_cli_json_mode_error_handling():
    """Verifies that invalid CVE arguments via CLI output structured error JSON with exit code 1."""
    cmd = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "cve_lookup.py"),
        "invalid_cve_name",
        "--json",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert res.returncode == 1
    data = json.loads(res.stdout)
    assert data["status"] == "error"
    assert "Invalid CVE identifier" in data["error"]
