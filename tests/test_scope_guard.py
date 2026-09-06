#!/usr/bin/env python3
"""
Unit and Integration Tests for Machine-Enforced Scope Guard
Validates target sandbox containment, private subnet routing, destructive action blocking, and SCO generation.
"""

import sys
import json
import subprocess
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from scope_guard import ScopeGuard, ScopeViolationError


def test_target_allows_localhost_and_private_subnets():
    """Verifies that localhost and RFC1918 subnets (Docker, VPN, local labs) are authorized."""
    valid_targets = [
        "127.0.0.1",
        "localhost",
        "http://localhost:8000",
        "http://127.0.0.1:1337/challenge",
        "10.0.2.15",
        "172.17.0.2",
        "192.168.1.100",
        "./vulnerable_binary",
        "resources/chall.bin",
    ]

    for target in valid_targets:
        is_valid, reason = ScopeGuard.validate_target(target)
        assert is_valid is True, f"Target '{target}' should be authorized: {reason}"


def test_target_allows_ctf_domains():
    """Verifies that official CTF platforms and lab domains are authorized."""
    ctf_targets = [
        "https://challenge.picoctf.net:1234",
        "http://web.chals.io:8080",
        "https://web.challs.io:443",
        "http://lab.hackthebox.com",
        "https://hackthebox.com",
        "http://challenge.flagyard.com",
        "https://flagyard.com",
        "https://tryhackme.com",
        "http://lab.local",
    ]

    for target in ctf_targets:
        is_valid, reason = ScopeGuard.validate_target(target)
        assert is_valid is True, f"CTF target '{target}' should be authorized: {reason}"


def test_target_blocks_unauthorized_public_ips_and_domains():
    """Verifies that out-of-scope public IPs and generic production websites are strictly blocked."""
    invalid_targets = [
        "8.8.8.8",
        "1.1.1.1",
        "https://google.com",
        "https://paypal.com",
        "http://production-bank.com",
    ]

    for target in invalid_targets:
        is_valid, reason = ScopeGuard.validate_target(target)
        assert is_valid is False, f"Target '{target}' should be blocked by Scope Guard"
        assert "Scope Violation" in reason


def test_command_validation_blocks_destructive_and_persistence_actions():
    """Verifies that destructive host system calls, wide-area scans, and persistence backdoors are blocked."""
    prohibited_cmds = [
        "rm -rf /",
        "rm -rf /*",
        "format C:",
        "del /f /s /q C:\\Windows",
        "masscan 0.0.0.0/0 -p80",
        "nmap 0.0.0.0/0",
        "echo 'payload' >> /etc/cron.d/backdoor",
        "reg.exe ADD HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v bad",
    ]

    for cmd in prohibited_cmds:
        is_valid, reason = ScopeGuard.validate_command(cmd)
        assert is_valid is False, f"Command '{cmd}' should be blocked: {reason}"
        assert "Prohibited Action Blocked" in reason


def test_command_validation_allows_standard_ctf_tools():
    """Verifies that normal diagnostic tools and CTF solvers are permitted."""
    allowed_cmds = [
        "checksec --file=./pwn_chall",
        "gdb -q ./vuln",
        "ROPgadget --binary ./pwn --ropchain",
        "python3 solve.py",
        "curl -I http://127.0.0.1:8000",
        "ffuf -u http://127.0.0.1:8000/FUZZ -w wordlist.txt",
    ]

    for cmd in allowed_cmds:
        is_valid, reason = ScopeGuard.validate_command(cmd)
        assert is_valid is True, f"Command '{cmd}' should be permitted: {reason}"


def test_create_security_context_object_flow():
    """Verifies that SCO creation validates targets and sets appropriate sandbox constraints."""
    # Valid target
    sco = ScopeGuard.create_security_context_object("http://127.0.0.1:8080", category="web", mode="blitz")
    assert sco["type"] == "educational_ctf_challenge"
    assert sco["environment"]["isolated"] is True
    assert sco["constraints"]["max_subagent_depth"] == 1

    # Unauthorized target must raise ScopeViolationError
    with pytest.raises(ScopeViolationError):
        ScopeGuard.create_security_context_object("8.8.8.8", category="pwn")


def test_cli_scope_guard_json():
    """Verifies that 'python scripts/scope_guard.py --validate-target 127.0.0.1 --json' outputs valid JSON."""
    cmd = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "scope_guard.py"),
        "--validate-target",
        "127.0.0.1",
        "--json",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert data["authorized"] is True
    assert "target" in data
