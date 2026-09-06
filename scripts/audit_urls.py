#!/usr/bin/env python3
"""
CTF-Agent URL & File Link Audit Utility
Audits all internal relative file links and external HTTP/HTTPS URLs across the repository.
"""

import os
import re
import sys
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, unquote

import requests

REPO_ROOT = Path(__file__).resolve().parent.parent

# Regex patterns
MD_LINK_RE = re.compile(r'\[([^\]]*)\]\(([^)]+)\)')
RAW_URL_RE = re.compile(r'https?://[^\s<>\"\'`()\[\]{}|\\^]+')

# Known XML namespaces or schema identifiers that are not meant to be visited via HTTP
SCHEMA_NAMESPACES = [
    "schemas.microsoft.com", "schemas.openxmlformats.org", "w3.org", "xmlsoap.org"
]

# Patterns indicating CTF challenge targets, payloads, cloud SSRF targets, or template placeholders
CTF_PLACEHOLDER_DOMAINS = [
    "localhost", "127.0.0.1", "0.0.0.0", "target", "chall", "victim", "attacker",
    "example.com", "example.org", "test.com", "mysite.com", "target.com",
    "challenge.ctf", "vuln.com", "company.com", "internal.lan", "local",
    "169.254.169.254", "metadata.google.internal", "kubernetes.default.svc",
    "api.prod", "trusted.com", "exfil.com", "evil.com", "target.tld", "attacker.tld",
    "rbndr.us", "x.x.x.x", "host", "backend", "example.invalid"
]

CTF_PLACEHOLDER_PATTERNS = [
    "$", "{", "}", "<", ">", "%", "*", "...", "http://target", "http://chall",
    "webhook.site/id", "webhook.site/your_id", "webhook.site/token",
    ".run.app", ".cloudfunctions.net", "username.tumblr.com", "guild_id", "12345"
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

def strip_markdown_code(text: str) -> str:
    """Strip fenced code blocks and inline code spans to avoid false-positive link parsing."""
    # Strip fenced code blocks ```...```
    text = re.sub(r'```[\s\S]*?```', '', text)
    # Strip inline code spans `...`
    text = re.sub(r'`[^`\n]+`', '', text)
    return text

def is_placeholder_url(url: str) -> bool:
    """Check if a URL is a CTF lab placeholder, local service, cloud SSRF target, or template string."""
    url_lower = url.lower()
    for ch in CTF_PLACEHOLDER_PATTERNS:
        if ch in url_lower:
            return True
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        host_lower = host.lower()
        if not host:
            return True
        for s in SCHEMA_NAMESPACES:
            if host_lower == s or host_lower.endswith("." + s):
                return True
        for d in CTF_PLACEHOLDER_DOMAINS:
            if host_lower == d or host_lower.endswith("." + d) or d in host_lower:
                return True
        # IP ranges like 10.x.x.x, 192.168.x.x, 172.x.x.x
        if host_lower.startswith("10.") or host_lower.startswith("192.168.") or host_lower.startswith("172."):
            return True
    except Exception:
        return True
    return False

def clean_url(raw_url: str) -> str:
    """Clean trailing punctuation from raw regex match."""
    url = raw_url.strip()
    while url and url[-1] in ".,;:!?":
        url = url[:-1]
    return url

def audit_file_links():
    """Audit all internal Markdown relative file links."""
    internal_links = []
    broken_internal = []
    file_uri_links = []

    for p in REPO_ROOT.rglob("*.md"):
        if any(part in p.parts for part in [".git", "__pycache__", ".pytest_cache", "venv", "brain"]):
            continue
        try:
            content = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        rel_source = p.relative_to(REPO_ROOT)
        cleaned_content = strip_markdown_code(content)

        for m in MD_LINK_RE.finditer(cleaned_content):
            link_text = m.group(1)
            target = m.group(2).strip()

            # Check for illegal hardcoded file:/// scheme
            if target.startswith("file:///"):
                file_uri_links.append((str(rel_source), link_text, target))
                continue

            # Skip external web URLs, anchors on same page, or mailto
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue

            # Parse path and fragment
            target_path_str = target.split("#")[0]
            if not target_path_str:
                continue

            # Resolve target path relative to current file's directory
            decoded_path = unquote(target_path_str)
            resolved_path = (p.parent / decoded_path).resolve()

            internal_links.append((str(rel_source), target, str(resolved_path)))
            if not resolved_path.exists():
                broken_internal.append((str(rel_source), target, str(resolved_path)))

    return internal_links, broken_internal, file_uri_links

def check_external_url(url: str, timeout: int = 10) -> dict:
    """Check availability of an external HTTP/HTTPS URL."""
    try:
        # Send GET request with realistic headers
        res = requests.get(url, headers=HEADERS, timeout=timeout, stream=True, allow_redirects=True)
        # Status < 400 = OK. Status 401/403/429 = bot challenged or authentication required (endpoint alive).
        is_ok = (res.status_code < 400) or (res.status_code in (401, 403, 429))
        return {
            "url": url,
            "status_code": res.status_code,
            "ok": is_ok,
            "error": None
        }
    except requests.exceptions.SSLError as e:
        try:
            res = requests.get(url, headers=HEADERS, timeout=timeout, stream=True, verify=False, allow_redirects=True)
            return {
                "url": url,
                "status_code": res.status_code,
                "ok": True,
                "error": "SSL_UNVERIFIED"
            }
        except Exception:
            return {"url": url, "status_code": 0, "ok": False, "error": f"SSL_ERROR: {str(e)[:60]}"}
    except requests.exceptions.Timeout:
        return {"url": url, "status_code": 0, "ok": False, "error": "TIMEOUT"}
    except requests.exceptions.ConnectionError as e:
        return {"url": url, "status_code": 0, "ok": False, "error": f"CONNECTION_ERROR: {str(e)[:60]}"}
    except Exception as e:
        return {"url": url, "status_code": 0, "ok": False, "error": str(e)[:60]}

def audit_external_urls(max_workers: int = 15):
    """Audit all external HTTP/HTTPS URLs across the repository."""
    raw_urls_map = {}  # url -> list of files

    for p in REPO_ROOT.rglob("*"):
        if any(part in p.parts for part in [".git", "__pycache__", ".pytest_cache", "venv", "brain"]):
            continue
        if not p.is_file() or p.suffix not in (".md", ".py", ".sh", ".json", ".yml", ".yaml", "Dockerfile"):
            continue
        try:
            content = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        rel_source = str(p.relative_to(REPO_ROOT))
        for m in RAW_URL_RE.finditer(content):
            u = clean_url(m.group(0))
            if u not in raw_urls_map:
                raw_urls_map[u] = []
            raw_urls_map[u].append(rel_source)

    placeholders = []
    real_urls = []

    for u, files in raw_urls_map.items():
        if is_placeholder_url(u):
            placeholders.append((u, files))
        else:
            real_urls.append((u, files))

    print(f"[*] Found {len(raw_urls_map)} total unique URLs:")
    print(f"    - CTF Target / Schema / Placeholder URLs: {len(placeholders)}")
    print(f"    - Real External Reference URLs to probe : {len(real_urls)}")
    print(f"[*] Probing {len(real_urls)} external URLs with {max_workers} threads...")

    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(check_external_url, u): (u, files) for u, files in real_urls}
        for future in as_completed(future_to_url):
            res = future.result()
            u, files = future_to_url[future]
            res["files"] = files
            results.append(res)

    return placeholders, results

def main():
    print("============================================================")
    print("[*] CTF-Agent Comprehensive Link & URL Audit Suite")
    print("============================================================")

    # 1. Audit Internal Markdown Links
    print("\n--- 1. AUDITING INTERNAL RELATIVE FILE LINKS ---")
    internal_links, broken_internal, file_uri_links = audit_file_links()
    print(f"Total internal relative links checked : {len(internal_links)}")
    print(f"Broken internal links found           : {len(broken_internal)}")
    print(f"Illegal hardcoded file:/// links found: {len(file_uri_links)}")

    if file_uri_links:
        print("\n[!] DETECTED ILLEGAL file:/// LINKS:")
        for src, txt, target in file_uri_links:
            print(f"  In {src}: [{txt}]({target})")

    if broken_internal:
        print("\n[!] DETECTED BROKEN INTERNAL RELATIVE LINKS:")
        for src, target, resolved in broken_internal:
            print(f"  In {src} -> '{target}' (resolved: {resolved})")

    # 2. Audit External URLs
    print("\n--- 2. AUDITING EXTERNAL HTTP/HTTPS URLS ---")
    placeholders, ext_results = audit_external_urls()

    live_urls = [r for r in ext_results if r["ok"]]
    failed_urls = [r for r in ext_results if not r["ok"]]

    print(f"\nExternal URLs verified live (2xx/3xx/auth/bot-gate) : {len(live_urls)}")
    print(f"External URLs unreachable or 404                   : {len(failed_urls)}")

    if failed_urls:
        print("\n[!] POTENTIALLY BROKEN / UNREACHABLE EXTERNAL URLS:")
        for r in failed_urls:
            print(f"  Status: {r['status_code']} | Error: {r['error']}")
            print(f"  URL   : {r['url']}")
            print(f"  Files : {', '.join(r['files'][:3])}")
            print()

    print("\n============================================================")
    print("AUDIT SUMMARY:")
    print(f"  Internal Links  : {len(internal_links)} checked, {len(broken_internal)} broken")
    print(f"  file:/// Links  : {len(file_uri_links)} found")
    print(f"  CTF Placeholders: {len(placeholders)} classified")
    print(f"  External Live   : {len(live_urls)}/{len(ext_results)} accessible ({len(live_urls)/max(1, len(ext_results))*100:.1f}%)")
    print("============================================================")

    if broken_internal or file_uri_links:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
