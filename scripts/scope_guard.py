#!/usr/bin/env python3
"""
CTF-Agent Machine-Enforced Scope Guard
Enforces runtime boundary compliance for Security Context Objects (SCO) and Task Envelopes (TE).
Validates targets against authorized educational sandboxes and blocks prohibited actions.
"""

import os
import sys
import re
import ipaddress
import urllib.parse
import argparse
import json
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

# Allowed CTF and educational domain patterns
ALLOWED_DOMAIN_PATTERNS = [
    r"^localhost$",
    r"^(?:.*\.)?local$",
    r"^(?:.*\.)?internal$",
    r"^(?:.*\.)?test$",
    r"^(?:.*\.)?ctf$",
    r"^(?:.*\.)?chal{1,2}s?\.io$",
    r"^(?:.*\.)?picoctf\.net$",
    r"^(?:.*\.)?hackthebox\.(?:com|eu)$",
    r"^(?:.*\.)?tryhackme\.com$",
    r"^(?:.*\.)?flagyard\.com$",
    r"^(?:.*\.)?ctfd\.io$",
    r"^(?:.*\.)?ctf\.site$",
    r"^(?:.*\.)?sandia\.gov$",
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
    """Enforces target isolation, private network boundaries, and action restrictions."""

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
    def validate_target(cls, target: str, workspace_path: Optional[Path] = None) -> Tuple[bool, str]:
        """
        Validates whether a target is inside an authorized CTF educational sandbox.
        Allows:
          - Local file paths (binaries, PCAPs, source trees)
          - Localhost & Loopback (127.0.0.1, ::1)
          - RFC1918 Private IPv4 subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
          - Verified CTF competition domains & .env configured targets
        Rejects:
          - Unauthorized public IPv4/IPv6 addresses
          - Out-of-scope non-CTF internet domains
        """
        if not target or not target.strip():
            return False, "Target is empty"

        target = target.strip()

        # 1. Local path check
        local_p = Path(target)
        if "://" not in target and (
            local_p.exists()
            or local_p.is_absolute()
            or "/" in target
            or "\\" in target
            or target.startswith(".")
            or target.endswith((".bin", ".elf", ".py", ".pcap", ".pcapng", ".exe", ".so", ".apk", ".zip", ".tar", ".gz"))
        ):
            return True, f"Authorized local filesystem target: {local_p}"

        # 2. Extract host from URL if formatted as URL
        host = target
        if "://" in target:
            parsed = urllib.parse.urlparse(target)
            host = parsed.hostname or parsed.netloc

        if not host:
            return False, "Unable to extract host from target"

        # Remove port if present
        if ":" in host and not host.startswith("["):
            host = host.split(":")[0]

        # 3. Check loopback
        if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return True, f"Authorized loopback target: {host}"

        # 4. Check IP addresses (RFC1918 private subnets)
        try:
            ip_obj = ipaddress.ip_address(host)
            if ip_obj.is_loopback:
                return True, f"Authorized loopback IP: {ip_obj}"
            if ip_obj.is_private:
                return True, f"Authorized private lab/container IP (RFC1918): {ip_obj}"
            # Check if public IP is whitelisted in .env
            env_allowed = cls.load_env_whitelist(workspace_path)
            if any(host in item for item in env_allowed):
                return True, f"Authorized competition IP from .env whitelist: {host}"

            return False, f"Scope Violation: Public IP {host} is outside authorized private sandbox."
        except ValueError:
            # Target is a domain name
            pass

        # 5. Check domain whitelist against authorized CTF patterns
        for pat in ALLOWED_DOMAIN_PATTERNS:
            if re.match(pat, host, re.IGNORECASE):
                return True, f"Authorized CTF platform domain: {host} (matched {pat})"

        # 6. Check .env whitelist
        env_allowed = cls.load_env_whitelist(workspace_path)
        for item in env_allowed:
            if host in item or item in host:
                return True, f"Authorized domain from .env configuration: {host}"

        return False, (
            f"Scope Violation: Domain '{host}' is not a recognized CTF platform or private sandbox. "
            f"Add to .env (TARGET_HOST/TARGET_URL) to authorize."
        )

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
        is_valid, reason = cls.validate_target(target, workspace_path=workspace_path)
        if not is_valid:
            raise ScopeViolationError(reason)

        return {
            "version": "1.1",
            "type": "educational_ctf_challenge",
            "scope": {
                "target": target,
                "category": category,
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
    parser = argparse.ArgumentParser(description="CTF-Agent Machine-Enforced Scope Guard")
    parser.add_argument("--validate-target", help="Check if target is inside authorized educational sandbox")
    parser.add_argument("--validate-cmd", help="Check if command contains prohibited or destructive actions")
    parser.add_argument("--create-sco", help="Generate a verified Security Context Object for target")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()

    results: Dict[str, Any] = {}

    if args.validate_target:
        valid, reason = ScopeGuard.validate_target(args.validate_target)
        results = {
            "target": args.validate_target,
            "authorized": valid,
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
