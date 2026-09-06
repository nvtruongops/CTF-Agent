#!/usr/bin/env python3
"""
Flag Candidate Extraction Engine (v2.1)
Extracts, normalizes, deduplicates, and scores flag candidates from raw text, command output, or files.
Supports high-visibility terminal banners for Blitz mode and JSON output for CTFd automation.
"""

import sys
import os
import re
import json
import argparse
from dataclasses import dataclass, asdict
from typing import List, Optional

# Ensure safe UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

@dataclass
class FlagCandidate:
    value: str
    source: str
    location: Optional[str]
    confidence: float

# Common competition flag patterns with baseline confidence
DEFAULT_FLAG_PATTERNS = [
    (r'(?<![a-zA-Z0-9_])picoCTF\{[^\}]+\}', 0.95),
    (r'(?<![a-zA-Z0-9_])Dice\{[^\}]+\}', 0.95),
    (r'(?<![a-zA-Z0-9_])SEKAI\{[^\}]+\}', 0.95),
    (r'(?<![a-zA-Z0-9_])HTB\{[^\}]+\}', 0.95),
    (r'(?<![a-zA-Z0-9_])flagyard\{[^\}]+\}', 0.95),
    (r'(?<![a-zA-Z0-9_])FlagY\{[^\}]+\}', 0.95),
    (r'(?<![a-zA-Z0-9_])flag\{[a-zA-Z0-9_\-\.\!\?@#\$%\^&\*\+=\s]+\}', 0.95),
    (r'(?<![a-zA-Z0-9_])FLAG\{[a-zA-Z0-9_\-\.\!\?@#\$%\^&\*\+=\s]+\}', 0.95),
    (r'(?<![a-zA-Z0-9_])CTF\{[a-zA-Z0-9_\-\.\!\?@#\$%\^&\*\+=\s]+\}', 0.95),
    (r'(?<![a-zA-Z0-9_])FLAG-[A-Za-z0-9]{16,64}', 0.85),
    (r'(?<![a-zA-Z0-9_])[0-9a-fA-F]{32}(?![a-zA-Z0-9_])', 0.30),  # Raw MD5-like candidate (weak)
]

def extract_flag_candidates(
    raw_text: str,
    source: str = "terminal",
    location: Optional[str] = None,
    custom_prefix: Optional[str] = None
) -> List[FlagCandidate]:
    candidates = []
    seen = set()

    patterns = list(DEFAULT_FLAG_PATTERNS)
    if custom_prefix:
        custom_regex = rf'{re.escape(custom_prefix)}\{{[^\}}]+\}}'
        patterns.insert(0, (custom_regex, 1.0))

    for pattern, base_conf in patterns:
        matches = re.findall(pattern, raw_text)
        for m in matches:
            cleaned = m.strip()
            if cleaned not in seen:
                seen.add(cleaned)
                conf = base_conf
                if location and any(k in location for k in ("flag.txt", "/flag", "environ", "response")):
                    conf = min(1.0, conf + 0.05)
                candidates.append(FlagCandidate(value=cleaned, source=source, location=location, confidence=conf))

    return sorted(candidates, key=lambda c: c.confidence, reverse=True)

def print_banner(flag: str, confidence: float, source: str):
    """Print high-visibility terminal banner for Blitz mode."""
    width = max(60, len(flag) + 24)
    border = "=" * width
    print(f"\n{border}")
    print(f"[+] FLAG ACQUIRED: {flag}")
    print(f"Confidence: {confidence * 100:.0f}% | Source: {source}")
    print(f"{border}\n")

def main():
    parser = argparse.ArgumentParser(description="CTF Flag Extraction & Banner Generator")
    parser.add_argument("text", nargs="*", help="Raw text string to scan for flags")
    parser.add_argument("-f", "--file", help="Read input from a file instead of stdin/args")
    parser.add_argument("--prefix", help="Custom flag prefix (e.g., TETCTF, DEFCON)")
    parser.add_argument("--banner", action="store_true", help="Print high-visibility Blitz flag banner on discovery")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--exit-code", action="store_true", help="Return exit code 0 if flag found, 1 if not")
    parser.add_argument("--submit", type=int, metavar="CHALL_ID", help="Auto-submit top flag to CTFd challenge ID if CTF_URL and CTF_TOKEN exist")

    args = parser.parse_args()

    raw_text = ""
    source_name = "cli"

    if args.file:
        try:
            with open(args.file, "r", errors="ignore") as f:
                raw_text = f.read()
            source_name = f"file:{args.file}"
        except Exception as e:
            print(f"[-] Error reading file {args.file}: {e}", file=sys.stderr)
            sys.exit(1)
    elif args.text:
        raw_text = " ".join(args.text)
        source_name = "cli_args"
    elif not sys.stdin.isatty():
        raw_text = sys.stdin.read()
        source_name = "stdin"

    results = extract_flag_candidates(raw_text, source=source_name, custom_prefix=args.prefix)

    if not results:
        if args.json:
            print(json.dumps({"success": False, "candidates": []}))
        else:
            print("[-] No flag candidates identified.")
        sys.exit(1 if args.exit_code else 0)

    top_candidate = results[0]

    if args.banner:
        print_banner(top_candidate.value, top_candidate.confidence, top_candidate.source)

    if args.json:
        output_data = {
            "success": True,
            "top_flag": top_candidate.value,
            "candidates": [asdict(c) for c in results]
        }
        print(json.dumps(output_data, indent=2))
    elif not args.banner:
        print(f"[+] Identified {len(results)} flag candidate(s):")
        for idx, c in enumerate(results, 1):
            print(f"  {idx}. [{c.confidence:.2f}] {c.value} (Source: {c.source})")

    # Optional automated CTFd submission
    if args.submit:
        ctf_url = os.environ.get("CTF_URL")
        ctf_token = os.environ.get("CTF_TOKEN")
        if ctf_url and ctf_token:
            try:
                from ctfd_client import CTFdClient
                client = CTFdClient(ctf_url, ctf_token)
                sub_res = client.submit_flag(args.submit, top_candidate.value)
                print(f"[*] CTFd Submission Result: {sub_res.get('status', 'unknown').upper()} - {sub_res.get('message', '')}")
            except Exception as e:
                print(f"[!] CTFd submission failed: {e}", file=sys.stderr)

    if args.exit_code:
        sys.exit(0)

if __name__ == "__main__":
    main()
