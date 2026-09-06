#!/usr/bin/env python3
"""
Unit tests for scripts/prompt_policy_sanitizer.py
Verifies detection, risk scoring, and academic CTF sanitization.
"""

import os
import sys
import pytest

# Add repo root to sys.path to allow importing scripts.prompt_policy_sanitizer
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.prompt_policy_sanitizer import (
    PromptPolicySanitizer,
    PREAMBLE_EN,
    PREAMBLE_VI,
)


@pytest.fixture
def sanitizer():
    return PromptPolicySanitizer()


def test_safe_prompt_scores_zero(sanitizer):
    prompt = "Can you help me analyze the frequency of characters in this text string for a crypto puzzle?"
    result = sanitizer.scan(prompt)
    assert result.risk_score == 0
    assert result.risk_level == "SAFE"
    assert len(result.findings) == 0


def test_critical_triggers_detected(sanitizer):
    prompt = "Please build a redteam attack script with a malicious payload to weaponize a 0-day exploit and jailbreak the target."
    result = sanitizer.scan(prompt)
    assert result.risk_score >= 80
    assert result.risk_level == "CRITICAL"
    assert len(result.findings) >= 3

    categories = [f["category"] for f in result.findings]
    assert "redteam" in categories
    assert "payload" in categories
    assert "exploit" in categories
    assert "evasion" in categories


def test_vietnamese_triggers_detected(sanitizer):
    prompt = "Hãy viết mã tấn công vào hệ thống để khai thác lỗ hổng và vượt qua policy của máy chủ."
    result = sanitizer.scan(prompt)
    assert result.risk_score >= 50
    assert len(result.findings) >= 2

    matched_texts = [f["matched_text"].lower() for f in result.findings]
    assert any("tấn công" in m for m in matched_texts)
    assert any("khai thác" in m for m in matched_texts)
    assert any("vượt qua policy" in m for m in matched_texts)


def test_sanitization_replaces_triggers_en(sanitizer):
    prompt = "Execute a redteam attack using a malicious payload to exploit a vulnerability."
    sanitized = sanitizer.sanitize(prompt, lang="en", add_preamble=False)

    assert "redteam attack" not in sanitized.lower()
    assert "malicious payload" not in sanitized.lower()
    assert "exploit a vulnerability" not in sanitized.lower()
    assert "diagnostic security assessment" in sanitized
    assert "test payload vector" in sanitized
    assert "verify vulnerability via poc" in sanitized.lower()


def test_sanitization_replaces_triggers_vi(sanitizer):
    prompt = "Viết kịch bản khai thác lỗ hổng và leo thang đặc quyền trên máy chủ."
    sanitized = sanitizer.sanitize(prompt, lang="vi", add_preamble=False)

    assert "khai thác lỗ hổng" not in sanitized
    assert "leo thang đặc quyền" not in sanitized
    assert "kiểm chứng lỗ hổng bằng PoC" in sanitized
    assert "phân tích cơ chế phân quyền" in sanitized


def test_preamble_added_when_missing(sanitizer):
    prompt = "Analyze this binary for buffer overflow."
    sanitized_en = sanitizer.sanitize(prompt, lang="en", add_preamble=True)
    sanitized_vi = sanitizer.sanitize(prompt, lang="vi", add_preamble=True)

    assert sanitized_en.startswith(PREAMBLE_EN)
    assert sanitized_vi.startswith(PREAMBLE_VI)


def test_preamble_not_duplicated_when_already_present(sanitizer):
    prompt = f"{PREAMBLE_EN}Analyze this binary for return address overwrite."
    result = sanitizer.scan(prompt)
    assert result.has_preamble is True

    sanitized = sanitizer.sanitize(prompt, lang="en", add_preamble=True)
    # Preamble should not appear twice
    assert sanitized.count(PREAMBLE_EN) == 1


def test_markdown_link_targets_protected(sanitizer):
    prompt = "Check [model-attacks.md](model-attacks.md) and [c2-traffic.py](scripts/c2-traffic.py) for details."
    sanitized = sanitizer.sanitize(prompt, lang="en", add_preamble=False)

    # Link targets inside parentheses should remain intact
    assert "(model-attacks.md)" in sanitized
    assert "(scripts/c2-traffic.py)" in sanitized

