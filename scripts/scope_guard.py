#!/usr/bin/env python3
"""
CTF-Agent Machine-Enforced Scope Guard
Enforces runtime boundary compliance for Security Context Objects (SCO) and Task Envelopes (TE).
Validates targets against authorized educational sandboxes and blocks prohibited actions.
Includes strict anti-SSRF, IP obfuscation detection, and target category classification.
"""

import os
import sys
import re
import ipaddress
import urllib.parse
import argparse
import json
from enum import Enum
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

# Safe UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

REPO_ROOT = Path(__file__).resolve().parent.parent


class TargetCategory(str, Enum):
    LOCAL_FILE = "local_file"
    PRIVATE_LAB = "private_lab"
    CHALLENGE_INSTANCE = "challenge_instance"
    PLATFORM_PORTAL = "platform_portal"
    CUSTOM_AUTHORIZED = "custom_authorized"


# Allowed protocols for CTF target interactions
PERMITTED_SCHEMES = {"http", "https", "tcp", "nc", "ssl", "ws", "wss", "ssh"}

# Strictly prohibited URL schemes (SSRF / LFI / local code execution risks)
DANGEROUS_SCHEMES = {"javascript", "file", "data", "gopher", "dict", "ldap", "vbscript"}

# Authorized Challenge Infrastructure (ephemeral instancers, challenge subdomains)
CHALLENGE_DOMAIN_PATTERNS = [
    r"^(?:[a-zA-Z0-9-]+\.)*chal{1,2}s?\.io$",
    r"^(?:[a-zA-Z0-9-]+\.)*chal\.pw$",
    r"^(?:[a-zA-Z0-9-]+\.)*picoctf\.net$",
    r"^(?:[a-zA-Z0-9-]+\.)*flagyard\.com$",
    r"^(?:[a-zA-Z0-9-]+\.)*playat\.flagyard\.com$",
    r"^(?:[a-zA-Z0-9-]+\.)*lab\.hackthebox\.com$",
    r"^lab\.hackthebox\.com$",
    r"^app\.hackthebox\.com$",
    r"^(?:[a-zA-Z0-9-]+\.)*web-security-academy\.net$",
    r"^(?:[a-zA-Z0-9-]+\.)*root-me\.org$",
    r"^(?:[a-zA-Z0-9-]+\.)*cyberdefenders\.org$",
    r"^(?:[a-zA-Z0-9-]+\.)*pwni\.ng$",
    r"^(?:[a-zA-Z0-9-]+\.)*ctf\.su$",
    r"^(?:[a-zA-Z0-9-]+\.)*seccon\.games$",
    r"^(?:[a-zA-Z0-9-]+\.)*kctf\.dev$",
    r"^(?:[a-zA-Z0-9-]+\.)*instancer\.[a-zA-Z0-9-.]+$",
]

# Authorized Platform Portals (scoreboards / account portals)
PLATFORM_PORTAL_PATTERNS = [
    r"^(?:www\.)?picoctf\.org$",
    r"^play\.picoctf\.org$",
    r"^(?:[a-zA-Z0-9-]+\.)*ctfd\.io$",
    r"^ctfd\.io$",
    r"^(?:www\.)?hackthebox\.(?:com|eu)$",
    r"^(?:www\.)?tryhackme\.com$",
    r"^(?:www\.)?flagyard\.com$",
    r"^(?:www\.)?overthewire\.org$",
]

# Authorized Private / Lab TLDs and names
PRIVATE_LAB_DOMAIN_PATTERNS = [
    r"^localhost$",
    r"^(?:[a-zA-Z0-9-]+\.)*local$",
    r"^(?:[a-zA-Z0-9-]+\.)*internal$",
    r"^(?:[a-zA-Z0-9-]+\.)*lan$",
    r"^(?:[a-zA-Z0-9-]+\.)*test$",
    r"^(?:[a-zA-Z0-9-]+\.)*lab$",
    r"^(?:[a-zA-Z0-9-]+\.)*ctf$",
    r"^(?:[a-zA-Z0-9-]+\.)*htb$",
    r"^(?:[a-zA-Z0-9-]+\.)*thm$",
]

# Known SSRF / DNS wildcard evasion domains to block
DNS_REBINDING_DOMAINS = [
    r"^(?:[a-zA-Z0-9-]+\.)*nip\.io$",
    r"^(?:[a-zA-Z0-9-]+\.)*sslip\.io$",
    r"^(?:[a-zA-Z0-9-]+\.)*xip\.io$",
]

# Strictly prohibited command signatures
PROHIBITED_COMMAND_PATTERNS = [
    (r"\brm\s+-[rR]f\s+/(?:\s|$|\*)", "Destructive command: Root filesystem deletion"),
    (r"\bformat\s+[cC]:", "Destructive command: Drive format"),
    (r"\bdel\s+/[fF]\s+/[sS]\s+/[qQ]\s+[cC]:\\Windows", "Destructive command: Windows system deletion"),
    (r"\bmasscan\s+(?:0\.0\.0\.0/0|(?:\d{1,3}\.){3}\d{1,3}/(?:[0-7]|1[0-5]))", "Prohibited: Wide-area indiscriminate network scanning"),
    (r"\bnmap\s+(?:-[^\s]+\s+)*(?:0\.0\.0\.0/0|(?:\d{1,3}\.){3}\d{1,3}/[1-9]\b)", "Prohibited: Wide-area indiscriminate network scanning"),
    (r"\b(?:echo|cat)\s+.*>>\s+/(?:etc/cron|etc/init\.d)", "Prohibited: System-level persistence establishment"),
    (r"\bReg(?:\.exe)?\s+ADD\s+HK(?:LM|CU)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Prohibited: Windows autorun persistence"),
]


class ScopeViolationError(Exception):
    """Raised when an operation, target, or command violates educational sandbox scope."""
    pass


class ScopeGuard:
    """Enforces target isolation, private network boundaries, anti-SSRF rules, and action restrictions."""

    @staticmethod
    def load_env_whitelist(workspace_path: Optional[Path] = None) -> List[str]:
        """Loads allowed hosts and URLs from .env or .env.example if present."""
        allowed: List[str] = []
        candidates = []
        if workspace_path:
            candidates.extend([workspace_path / ".env", workspace_path / ".env.example"])
        candidates.extend([REPO_ROOT / ".env", REPO_ROOT / ".env.example"])

        for env_file in candidates:
            if env_file.is_file():
                try:
                    for line in env_file.read_text(encoding="utf-8").splitlines():
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            k = k.strip().upper()
                            v = v.strip()
                            if k in ("TARGET_HOST", "TARGET_URL", "CTFD_URL") and v:
                                allowed.append(v)
                except Exception:
                    pass
        return allowed

    @classmethod
    def check_ip_obfuscation(cls, host: str) -> Tuple[bool, Optional[str]]:
        """
        Detects alternate IP representations (integer, hex, octal, dword) used to bypass scope/SSRF checks.
        Returns (is_obfuscated, reason).
        """
        raw = host.strip()

        # 1. Decimal integer representation (e.g. 2130706433)
        if raw.isdigit() and len(raw) > 3:
            try:
                num = int(raw)
                if 0 <= num <= 4294967295:
                    return True, f"Obfuscated integer IP representation rejected: {raw}"
            except ValueError:
                pass

        # 2. Hexadecimal representation (e.g. 0x7f000001 or dotted 0x7f.0.0.1)
        if raw.lower().startswith("0x") or re.search(r"\b0x[0-9a-fA-F]+\b", raw):
            return True, f"Obfuscated hexadecimal IP representation rejected: {raw}"

        # 3. Octal representation (e.g. 017700000001 or dotted octal 0177.0.0.1)
        if re.match(r"^0[0-7]+$", raw) and len(raw) > 3:
            return True, f"Obfuscated octal IP representation rejected: {raw}"

        # 4. Dotted representation with octal octets (e.g. 0177.0.0.1, 127.000.000.001)
        if "." in raw:
            parts = raw.split(".")
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                for p in parts:
                    if len(p) > 1 and p.startswith("0"):
                        return True, f"Obfuscated octal-formatted dotted IP rejected: {raw}"

        return False, None

    @classmethod
    def validate_target(
        cls,
        target: str,
        workspace_path: Optional[Path] = None,
    ) -> Tuple[bool, str]:
        """
        Validates whether a target is inside an authorized CTF educational sandbox.
        Backwards-compatible tuple (is_authorized, reason_string).
        """
        is_auth, reason, _ = cls.validate_target_with_category(target, workspace_path=workspace_path)
        return is_auth, reason

    @classmethod
    def validate_target_with_category(
        cls,
        target: str,
        workspace_path: Optional[Path] = None,
    ) -> Tuple[bool, str, TargetCategory]:
        """
        Validates whether a target is inside an authorized CTF educational sandbox.
        Returns:
            (is_authorized, reason_string, target_category)
        """
        if not target or not target.strip():
            return False, "Target is empty", TargetCategory.PRIVATE_LAB

        raw_target = target.strip()

        # Check for dangerous schemes upfront
        lower_target = raw_target.lower()
        for d_scheme in DANGEROUS_SCHEMES:
            if lower_target.startswith(f"{d_scheme}:"):
                return False, f"Scope Violation: Dangerous scheme '{d_scheme}:' is strictly prohibited.", TargetCategory.PRIVATE_LAB

        # Check for protocol-relative URLs without scheme (//example.com)
        if raw_target.startswith("//"):
            return False, "Scope Violation: Protocol-relative URLs ('//') are not permitted.", TargetCategory.PRIVATE_LAB

        # 1. Local filesystem path check (only when no protocol scheme is specified)
        if "://" not in raw_target:
            local_p = Path(raw_target)
            # Must look like a real path or existing file
            if (
                local_p.exists()
                or (local_p.is_absolute() and ("/" in raw_target or "\\" in raw_target))
                or raw_target.startswith(("./", ".\\", "../", "..\\"))
                or raw_target.endswith((".bin", ".elf", ".py", ".pcap", ".pcapng", ".exe", ".so", ".apk", ".zip", ".tar", ".gz"))
            ):
                return True, f"Authorized local filesystem target: {local_p}", TargetCategory.LOCAL_FILE

        # 2. URL parsing & scheme extraction
        scheme = None
        host = raw_target
        port = None

        if "://" in raw_target:
            parsed = urllib.parse.urlsplit(raw_target)
            scheme = parsed.scheme.lower()
            if scheme not in PERMITTED_SCHEMES:
                return False, f"Scope Violation: Prohibited or unsupported scheme '{scheme}'. Allowed: {', '.join(sorted(PERMITTED_SCHEMES))}", TargetCategory.PRIVATE_LAB

            if not parsed.netloc and not parsed.hostname:
                return False, f"Scope Violation: Malformed URL '{raw_target}' missing host.", TargetCategory.PRIVATE_LAB

            host = parsed.hostname or ""
            if not host and parsed.netloc:
                # Handle host with port or bracketed IPv6
                host = parsed.netloc.split("@")[-1]  # Strip any userinfo
                if ":" in host and not host.startswith("["):
                    host = host.split(":")[0]

            try:
                port = parsed.port
            except ValueError:
                return False, f"Scope Violation: Invalid port specification in '{raw_target}'.", TargetCategory.PRIVATE_LAB

        else:
            # Format: host:port or ip:port or pure host
            if ":" in raw_target and not raw_target.startswith("["):
                parts = raw_target.split(":")
                if len(parts) == 2 and parts[1].split("/")[0].isdigit():
                    host = parts[0]
                    port_str = parts[1].split("/")[0]
                    try:
                        port = int(port_str)
                    except ValueError:
                        return False, f"Scope Violation: Invalid port '{port_str}'.", TargetCategory.PRIVATE_LAB

        if not host:
            return False, "Unable to extract valid host from target", TargetCategory.PRIVATE_LAB

        # Strip brackets from IPv6 host
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]

        # 3. Port range verification (if specified)
        if port is not None:
            if not (1 <= port <= 65535):
                return False, f"Scope Violation: Port {port} outside valid range (1-65535).", TargetCategory.PRIVATE_LAB

        # 4. Anti-SSRF: Obfuscated IP check
        is_obf, obf_reason = cls.check_ip_obfuscation(host)
        if is_obf:
            return False, f"Scope Violation: {obf_reason}", TargetCategory.PRIVATE_LAB

        # 5. Anti-SSRF: DNS rebinding wildcard domains check (e.g. nip.io, sslip.io)
        for rebind_pat in DNS_REBINDING_DOMAINS:
            if re.match(rebind_pat, host, re.IGNORECASE):
                return False, f"Scope Violation: Wildcard DNS rebinding domain '{host}' is prohibited.", TargetCategory.PRIVATE_LAB

        # 6. Check Loopback hostnames
        if host.lower() in ("localhost", "0.0.0.0"):
            return True, f"Authorized loopback target: {host}", TargetCategory.PRIVATE_LAB

        # 7. Check IP addresses (IPv4 & IPv6)
        try:
            ip_obj = ipaddress.ip_address(host)

            if ip_obj.is_loopback:
                return True, f"Authorized loopback IP: {ip_obj}", TargetCategory.PRIVATE_LAB

            if ip_obj.is_private:
                return True, f"Authorized private lab/container IP (RFC1918): {ip_obj}", TargetCategory.PRIVATE_LAB

            # Check if public IP is explicitly whitelisted in .env
            env_allowed = cls.load_env_whitelist(workspace_path)
            if any(host == item or host in item for item in env_allowed):
                return True, f"Authorized competition IP from .env whitelist: {host}", TargetCategory.CUSTOM_AUTHORIZED

            return False, f"Scope Violation: Public IP {host} is outside authorized private sandbox.", TargetCategory.PRIVATE_LAB

        except ValueError:
            # Target is a domain name
            pass

        # 8. Check Challenge Infrastructure Patterns (highest priority for CTF instances)
        for pat in CHALLENGE_DOMAIN_PATTERNS:
            if re.match(pat, host, re.IGNORECASE):
                return True, f"Authorized CTF challenge instance: {host}", TargetCategory.CHALLENGE_INSTANCE

        # 9. Check Platform Portal Patterns
        for pat in PLATFORM_PORTAL_PATTERNS:
            if re.match(pat, host, re.IGNORECASE):
                return True, f"Authorized CTF platform portal: {host}", TargetCategory.PLATFORM_PORTAL

        # 10. Check Private / Lab Domain Patterns
        for pat in PRIVATE_LAB_DOMAIN_PATTERNS:
            if re.match(pat, host, re.IGNORECASE):
                return True, f"Authorized private lab domain: {host}", TargetCategory.PRIVATE_LAB

        # 11. Check .env whitelist for custom domains
        env_allowed = cls.load_env_whitelist(workspace_path)
        for item in env_allowed:
            if host == item or item.endswith(f"://{host}") or f"://{host}:" in item:
                return True, f"Authorized domain from .env configuration: {host}", TargetCategory.CUSTOM_AUTHORIZED

        return False, (
            f"Scope Violation: Domain '{host}' is not an authorized CTF challenge instance, platform, or private lab. "
            f"Add to .env (TARGET_HOST/TARGET_URL) to authorize."
        ), TargetCategory.PRIVATE_LAB

    @classmethod
    def validate_command(cls, command: str) -> Tuple[bool, str]:
        """
        Validates command string against prohibited destructive, wide-scan, or persistence patterns.
        """
        if not command or not command.strip():
            return True, "Empty command"

        cmd = command.strip()
        for pattern, reason in PROHIBITED_COMMAND_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE):
                return False, f"Prohibited Action Blocked: {reason} (matched rule: {pattern})"

        return True, "Command passed scope guard validation"

    @classmethod
    def create_security_context_object(
        cls,
        target: str,
        category: str = "general",
        mode: str = "speedrun",
        workspace_path: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """
        Creates a formally validated Security Context Object (SCO) for agent orchestration.
        Raises ScopeViolationError if the target fails scope verification.
        """
        is_valid, reason, target_cat = cls.validate_target_with_category(target, workspace_path=workspace_path)
        if not is_valid:
            raise ScopeViolationError(reason)

        return {
            "version": "1.3",
            "type": "educational_ctf_challenge",
            "scope": {
                "target": target,
                "category": category,
                "target_type": target_cat.value,
                "mode": mode,
                "authorization_status": "authorized_sandbox",
                "validation_reason": reason,
            },
            "environment": {
                "isolated": True,
                "sandbox_guarantee": True,
                "production_targets": False,
            },
            "constraints": {
                "max_subagent_depth": 1,
                "persistence_allowed": False,
                "destructive_actions_allowed": False,
                "timeout_seconds": 60,
            },
        }


def main():
    parser = argparse.ArgumentParser(description="CTF-Agent Machine-Enforced Scope Guard v1.3")
    parser.add_argument("--validate-target", help="Check if target is inside authorized educational sandbox")
    parser.add_argument("--validate-cmd", help="Check if command contains prohibited or destructive actions")
    parser.add_argument("--create-sco", help="Generate a verified Security Context Object for target")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()

    results: Dict[str, Any] = {}

    if args.validate_target:
        valid, reason, cat = ScopeGuard.validate_target_with_category(args.validate_target)
        results = {
            "target": args.validate_target,
            "authorized": valid,
            "category": cat.value,
            "reason": reason,
        }

    elif args.validate_cmd:
        valid, reason = ScopeGuard.validate_command(args.validate_cmd)
        results = {
            "command": args.validate_cmd,
            "authorized": valid,
            "reason": reason,
        }

    elif args.create_sco:
        try:
            sco = ScopeGuard.create_security_context_object(args.create_sco)
            results = {"status": "success", "sco": sco}
        except ScopeViolationError as e:
            results = {"status": "error", "error": str(e)}

    else:
        parser.print_help()
        sys.exit(1)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        if results.get("authorized") or results.get("status") == "success":
            print(f"[OK] Scope Guard: {results.get('reason', 'Security Context Created')}")
        else:
            print(f"[!] Scope Guard Refusal: {results.get('reason', results.get('error'))}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
