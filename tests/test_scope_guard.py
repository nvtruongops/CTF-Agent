#!/usr/bin/env python3
"""
Unit and Integration Tests for Machine-Enforced Scope Guard
Validates target sandbox containment, private subnet routing, anti-SSRF, IP obfuscation blocking,
URL normalization, category taxonomy, destructive action blocking, and SCO generation.
"""

import sys
import json
import subprocess
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from scope_guard import ScopeGuard, ScopeViolationError, TargetCategory


def test_target_allows_localhost_and_private_subnets():
    """Verifies that localhost, loopbacks, and RFC1918 subnets (Docker, VPN, local labs) are authorized."""
    valid_targets = [
        "127.0.0.1",
        "localhost",
        "http://localhost:8000",
        "http://127.0.0.1:1337/challenge",
        "http://[::1]:8080",
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
    """Verifies that known CTF platforms, lab portals, and challenge infrastructure are authorized."""
    ctf_targets = [
        # picoCTF
        "https://picoctf.org",
        "https://play.picoctf.org",
        "https://challenge.picoctf.net:1234",

        # CTFd / generic challenge infrastructure
        "https://ctfd.io",
        "https://demo.ctfd.io",
        "http://web.chals.io:8080",
        "https://web.challs.io:443",

        # Hack The Box
        "https://hackthebox.com",
        "https://www.hackthebox.com",
        "https://app.hackthebox.com",
        "https://lab.hackthebox.com",

        # TryHackMe
        "https://tryhackme.com",
        "https://www.tryhackme.com",

        # FlagYard
        "https://flagyard.com",
        "http://challenge.flagyard.com",

        # Local / lab
        "http://lab.local",
        "https://challenge.local",
        "http://ctf.local:8080",

        # Additional modern CTF platforms
        "https://portswigger-lab.web-security-academy.net:8443",
        "https://challenge01.root-me.org",
    ]

    for target in ctf_targets:
        is_valid, reason = ScopeGuard.validate_target(target)
        assert is_valid is True, f"CTF target '{target}' should be authorized: {reason}"


def test_target_blocks_domain_bypass_variants():
    """Prevents hostname parsing, prefix/suffix-based, and wildcard DNS authorization bypasses."""
    invalid_targets = [
        "https://hackthebox.com.attacker.com",
        "https://tryhackme.com.attacker.com",
        "https://flagyard.com.attacker.com",
        "https://picoctf.org.attacker.com",

        "https://attacker-hackthebox.com",
        "https://attackertryhackme.com",

        "https://127.0.0.1.nip.io",
        "https://localhost.attacker.com",
    ]

    for target in invalid_targets:
        is_valid, reason = ScopeGuard.validate_target(target)
        assert is_valid is False, f"Potential domain bypass '{target}' was authorized: {reason}"
        assert "Scope Violation" in reason


def test_target_handles_ports_correctly():
    """Verifies explicit port handling for challenge services and rejects invalid ports."""
    valid_targets = [
        "http://127.0.0.1:80",
        "http://127.0.0.1:8080",
        "https://challenge.picoctf.net:443",
        "https://challenge.picoctf.net:8443",
    ]

    for target in valid_targets:
        is_valid, reason = ScopeGuard.validate_target(target)
        assert is_valid is True, f"Valid port target '{target}' rejected: {reason}"

    invalid_port_targets = [
        "http://127.0.0.1:99999",
        "http://127.0.0.1:0",
        "http://127.0.0.1:abc",
    ]
    for target in invalid_port_targets:
        is_valid, reason = ScopeGuard.validate_target(target)
        assert is_valid is False, f"Invalid port target '{target}' was authorized: {reason}"


def test_target_blocks_malformed_or_suspicious_urls():
    """Rejects malformed targets that could confuse URL parsers or trigger local file disclosure."""
    invalid_targets = [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "data:text/plain,test",
        "//google.com",
        "http:///google.com",
        "https://",
        "",
        "not-a-valid-target",
    ]

    for target in invalid_targets:
        is_valid, reason = ScopeGuard.validate_target(target)
        assert is_valid is False, f"Malformed target '{target}' should be rejected: {reason}"


def test_target_blocks_public_network_ranges():
    """Blocks arbitrary public network targets and production websites."""
    invalid_targets = [
        "8.8.8.8",
        "1.1.1.1",
        "142.250.72.14",
        "https://example.com",
        "https://google.com",
        "https://paypal.com",
    ]

    for target in invalid_targets:
        is_valid, reason = ScopeGuard.validate_target(target)
        assert is_valid is False, f"Public target '{target}' should be blocked by Scope Guard"
        assert "Scope Violation" in reason


def test_target_blocks_ip_obfuscation():
    """Rejects alternate IP representations (integer, hex, octal) that could bypass scope rules."""
    invalid_targets = [
        "http://2130706433",       # 127.0.0.1 as decimal integer
        "http://0x7f000001",       # hexadecimal representation
        "http://017700000001",     # octal representation
        "2130706433",
        "0x7f000001",
        "017700000001",
    ]

    for target in invalid_targets:
        is_valid, reason = ScopeGuard.validate_target(target)
        assert is_valid is False, f"Obfuscated IP target '{target}' should be rejected: {reason}"
        assert "Scope Violation" in reason


def test_target_categorization():
    """Verifies that targets are cleanly classified into Challenge, Platform, or Private Lab."""
    # Challenge instance
    auth, _, cat = ScopeGuard.validate_target_with_category("https://chall1.chals.io:8080")
    assert auth is True
    assert cat == TargetCategory.CHALLENGE_INSTANCE

    # Platform portal
    auth, _, cat = ScopeGuard.validate_target_with_category("https://hackthebox.com")
    assert auth is True
    assert cat == TargetCategory.PLATFORM_PORTAL

    # Private lab
    auth, _, cat = ScopeGuard.validate_target_with_category("http://127.0.0.1:8000")
    assert auth is True
    assert cat == TargetCategory.PRIVATE_LAB


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
    assert sco["scope"]["target_type"] == "private_lab"
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
    assert "category" in data
