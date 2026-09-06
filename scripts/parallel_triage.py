#!/usr/bin/env python3
"""
CTF-Agent High-Speed Parallel Triage Scheduler
Dispatches concurrent Tier 1 & Tier 2 diagnostics to minimize Time-to-Flag (First Blood).
Executes parallel security probes for ELF binaries, source trees, and web targets.
"""

import os
import sys
import re
import json
import shutil
import argparse
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional

# Safe UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


class PurePythonElfTriage:
    """Fallback ELF parser providing checksec-equivalent mitigations using pure Python."""

    @staticmethod
    def parse_elf(file_path: Path) -> Dict[str, Any]:
        result = {
            "is_elf": False,
            "arch": "unknown",
            "bitness": 0,
            "endian": "little",
            "pie": "unknown",
            "nx": "unknown",
            "canary": "unknown",
            "relro": "unknown",
            "stripped": True,
        }

        if not file_path.is_file():
            return result

        data = file_path.read_bytes()
        if len(data) < 64 or not data.startswith(b"\x7fELF"):
            return result

        result["is_elf"] = True
        ei_class = data[4]
        result["bitness"] = 64 if ei_class == 2 else 32
        result["endian"] = "little" if data[5] == 1 else "big"

        # e_type at offset 16 (2 bytes, little endian)
        e_type = int.from_bytes(data[16:18], "little" if result["endian"] == "little" else "big")
        if e_type == 2:  # ET_EXEC
            result["pie"] = "No PIE (ET_EXEC)"
        elif e_type == 3:  # ET_DYN
            result["pie"] = "PIE enabled (ET_DYN)"

        # Check for symbols: __stack_chk_fail -> Canary
        if b"__stack_chk_fail" in data:
            result["canary"] = "Canary found (__stack_chk_fail)"
        else:
            result["canary"] = "No canary found"

        # Check for stripped
        if b".symtab" in data:
            result["stripped"] = False
        else:
            result["stripped"] = True

        # GNU_STACK program header for NX
        # Quick heuristic in raw bytes
        if b"GNU_STACK" in data:
            result["nx"] = "NX enabled (GNU_STACK present)"
        else:
            result["nx"] = "NX unknown/disabled"

        return result


class ParallelTriageScheduler:
    """High-concurrency scheduler running multi-threaded security diagnostics."""

    @staticmethod
    def triage_binary(target_path: Path) -> Dict[str, Any]:
        """Runs parallel binary diagnostics: file classification, checksec, strings, symbols."""
        results: Dict[str, Any] = {
            "target": str(target_path.resolve()),
            "type": "binary",
            "diagnostics": {},
            "recommendations": [],
        }

        if not target_path.exists():
            results["error"] = f"Target path {target_path} does not exist"
            return results

        def run_file():
            file_bin = shutil.which("file")
            if file_bin:
                try:
                    res = subprocess.run([file_bin, "-b", str(target_path)], capture_output=True, text=True, timeout=4)
                    return ("file", res.stdout.strip())
                except Exception:
                    pass
            # Fallback Python detection
            raw = target_path.read_bytes()[:16]
            if raw.startswith(b"\x7fELF"):
                return ("file", f"ELF binary (Bitness: {64 if raw[4] == 2 else 32}-bit)")
            elif raw.startswith(b"MZ"):
                return ("file", "Windows PE executable")
            elif raw.startswith(b"%PDF"):
                return ("file", "PDF document")
            return ("file", "Generic binary/data file")

        def run_checksec():
            checksec_bin = shutil.which("checksec")
            if checksec_bin:
                try:
                    res = subprocess.run([checksec_bin, f"--file={target_path}"], capture_output=True, text=True, timeout=5)
                    return ("checksec", res.stdout.strip())
                except Exception:
                    pass
            # Fallback pure python ELF parser
            elf_info = PurePythonElfTriage.parse_elf(target_path)
            return ("checksec", elf_info)

        def run_strings():
            strings_bin = shutil.which("strings")
            interesting_patterns = [
                r"flag\{[^}]+\}",
                r"picoCTF\{[^}]+\}",
                r"HTB\{[^}]+\}",
                r"/bin/sh",
                r"system",
                r"execve",
                r"/dev/urandom",
                r"password",
                r"admin",
            ]
            matches: List[str] = []
            if strings_bin:
                try:
                    res = subprocess.run([strings_bin, "-n", "5", str(target_path)], capture_output=True, text=True, timeout=5)
                    text = res.stdout
                    for pat in interesting_patterns:
                        found = re.findall(pat, text, re.IGNORECASE)
                        if found:
                            matches.extend(found[:3])
                    return ("strings", list(set(matches)))
                except Exception:
                    pass

            # Python fallback strings
            content = target_path.read_bytes()
            extracted = re.findall(b"[ -~]{5,}", content)
            text = "\n".join(e.decode("latin1") for e in extracted)
            for pat in interesting_patterns:
                found = re.findall(pat, text, re.IGNORECASE)
                if found:
                    matches.extend(found[:3])
            return ("strings", list(set(matches)))

        def run_symbols():
            readelf_bin = shutil.which("readelf")
            symbols_found = []
            if readelf_bin:
                try:
                    res = subprocess.run([readelf_bin, "-s", str(target_path)], capture_output=True, text=True, timeout=5)
                    for line in res.stdout.splitlines():
                        for sym in ["win", "flag", "backdoor", "vuln", "target", "secret"]:
                            if sym in line.lower():
                                symbols_found.append(line.strip())
                    return ("symbols", symbols_found[:5])
                except Exception:
                    pass
            # Python fallback search for function symbols
            raw = target_path.read_bytes()
            for sym in [b"win", b"flag", b"backdoor", b"vuln", b"secret"]:
                if sym in raw:
                    symbols_found.append(f"Contains substring: '{sym.decode('latin1')}'")
            return ("symbols", symbols_found)

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(run_file),
                executor.submit(run_checksec),
                executor.submit(run_strings),
                executor.submit(run_symbols),
            ]
            for f in as_completed(futures):
                try:
                    key, val = f.result()
                    results["diagnostics"][key] = val
                except Exception as e:
                    pass

        # Synthesize recommendations
        chk = results["diagnostics"].get("checksec", {})
        if isinstance(chk, dict):
            if "No canary found" in chk.get("canary", ""):
                results["recommendations"].append("Tier 2 PWN: Stack buffer overflow feasible (No canary detected).")
            if "No PIE" in chk.get("pie", ""):
                results["recommendations"].append("Tier 2 PWN: Fixed code addresses available (PIE disabled; ret2win/ROP).")
        symbols = results["diagnostics"].get("symbols", [])
        if any("win" in s.lower() for s in symbols):
            results["recommendations"].append("High-Priority Target: 'win' function detected -> Check ret2win / call target.")

        strings = results["diagnostics"].get("strings", [])
        if any("flag" in s.lower() for s in strings):
            results["recommendations"].append("Tier 1 Plaintext: Possible plaintext flag detected in binary strings.")

        return results

    @staticmethod
    def triage_web(target_url: str, timeout: float = 4.0) -> Dict[str, Any]:
        """Runs parallel web diagnostics: HTTP headers, robots.txt, sitemap, tech stack, and leak probes."""
        if not target_url.startswith(("http://", "https://")):
            target_url = "http://" + target_url

        base_url = target_url.rstrip("/")
        results: Dict[str, Any] = {
            "target": target_url,
            "type": "web",
            "diagnostics": {},
            "recommendations": [],
        }

        headers_agent = {"User-Agent": "CTF-Agent-Triage/1.3 (Security Lab Educational Scanner)"}

        def probe_head():
            req = urllib.request.Request(base_url, headers=headers_agent)
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    resp_headers = {k.lower(): v for k, v in resp.info().items()}
                    return ("headers", {
                        "status": resp.status,
                        "server": resp_headers.get("server", "hidden"),
                        "powered_by": resp_headers.get("x-powered-by", "none"),
                        "content_type": resp_headers.get("content-type", ""),
                    })
            except urllib.error.HTTPError as e:
                return ("headers", {"status": e.code, "server": str(e.headers.get("server", ""))})
            except Exception as e:
                return ("headers", {"error": str(e)})

        def probe_robots():
            url = f"{base_url}/robots.txt"
            req = urllib.request.Request(url, headers=headers_agent)
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    if resp.status == 200:
                        content = resp.read().decode("utf-8", errors="replace")
                        disallows = [line.strip() for line in content.splitlines() if line.lower().startswith("disallow:")]
                        return ("robots_txt", {"present": True, "disallows": disallows[:10]})
            except Exception:
                pass
            return ("robots_txt", {"present": False})

        def probe_sitemap():
            url = f"{base_url}/sitemap.xml"
            req = urllib.request.Request(url, headers=headers_agent)
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    if resp.status == 200:
                        return ("sitemap_xml", {"present": True, "size": len(resp.read())})
            except Exception:
                pass
            return ("sitemap_xml", {"present": False})

        def probe_leaks():
            endpoints = ["/.git/HEAD", "/.env", "/config.json", "/api", "/actuator/health"]
            found_leaks = []
            for ep in endpoints:
                url = f"{base_url}{ep}"
                req = urllib.request.Request(url, headers=headers_agent)
                try:
                    with urllib.request.urlopen(req, timeout=1.5) as resp:
                        if resp.status == 200:
                            body = resp.read(64)
                            if ep == "/.git/HEAD" and b"ref:" in body:
                                found_leaks.append(ep)
                            elif ep == "/.env" and b"=" in body:
                                found_leaks.append(ep)
                            elif ep not in ("/.git/HEAD", "/.env"):
                                found_leaks.append(ep)
                except Exception:
                    pass
            return ("leaks", found_leaks)

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(probe_head),
                executor.submit(probe_robots),
                executor.submit(probe_sitemap),
                executor.submit(probe_leaks),
            ]
            for f in as_completed(futures):
                try:
                    key, val = f.result()
                    results["diagnostics"][key] = val
                except Exception:
                    pass

        # Synthesize recommendations
        robots = results["diagnostics"].get("robots_txt", {})
        if robots.get("present"):
            disallows = robots.get("disallows", [])
            results["recommendations"].append(f"Tier 1 Web: robots.txt detected with {len(disallows)} entries. Check hidden paths.")

        leaks = results["diagnostics"].get("leaks", [])
        if leaks:
            results["recommendations"].append(f"Tier 1 Critical Leak: Sensitive endpoints accessible: {', '.join(leaks)}.")

        headers = results["diagnostics"].get("headers", {})
        srv = str(headers.get("server", "")).lower()
        powered = str(headers.get("powered_by", "")).lower()
        combined = f"{srv} {powered}"
        if "flask" in combined or "werkzeug" in combined:
            results["recommendations"].append("Tier 3 Web: Flask/Werkzeug detected -> Test Jinja2 SSTI & pin console.")
        elif "express" in combined or "node" in combined:
            results["recommendations"].append("Tier 3 Web: Node.js/Express detected -> Test Prototype Pollution & vm/eval RCE.")
        elif "php" in combined:
            results["recommendations"].append("Tier 2 Web: PHP environment detected -> Check version matrix for loose equality / LFI.")

        return results

    @classmethod
    def triage(cls, target: str, target_type: str = "auto") -> Dict[str, Any]:
        """Auto-detects target nature and delegates to binary or web parallel triage."""
        if target_type == "web" or target.startswith(("http://", "https://")) or ":" in target and not Path(target).exists():
            return cls.triage_web(target)
        else:
            path = Path(target)
            return cls.triage_binary(path)


def print_triage_banner(results: Dict[str, Any]):
    """Formats parallel triage results for maximum speedrun readability."""
    print("\n=================================================================")
    print("CTF-AGENT HIGH-SPEED PARALLEL TRIAGE REPORT")
    print("=================================================================")
    print(f"Target   : {results.get('target')}")
    print(f"Category : {results.get('type', 'unknown').upper()}")
    print("-----------------------------------------------------------------")
    print("Diagnostic Vectors (Concurrently Dispatched):")

    diag = results.get("diagnostics", {})
    for k, v in diag.items():
        if isinstance(v, dict):
            print(f"  [+] {k.upper()}:")
            for sub_k, sub_v in v.items():
                print(f"      - {sub_k:15}: {sub_v}")
        elif isinstance(v, list):
            print(f"  [+] {k.upper()}: {', '.join(v) if v else 'None'}")
        else:
            print(f"  [+] {k.upper():12}: {v}")

    print("-----------------------------------------------------------------")
    recs = results.get("recommendations", [])
    if recs:
        print("Triage Hypotheses & Actionable Vectors:")
        for r in recs:
            print(f"  [*] {r}")
    else:
        print("Triage Hypotheses: Standard triage progression recommended (Tier 1 -> Tier 2).")
    print("=================================================================\n")


def main():
    parser = argparse.ArgumentParser(description="CTF-Agent High-Speed Parallel Triage Scheduler")
    parser.add_argument("target", help="Challenge target (binary path, local file, or web URL)")
    parser.add_argument("--type", choices=["auto", "binary", "pwn", "web"], default="auto", help="Target type (default: auto)")
    parser.add_argument("--json", action="store_true", help="Output triage report as JSON")

    args = parser.parse_args()

    t_type = "binary" if args.type == "pwn" else args.type
    results = ParallelTriageScheduler.triage(args.target, target_type=t_type)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_triage_banner(results)


if __name__ == "__main__":
    main()
