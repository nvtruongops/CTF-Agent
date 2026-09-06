"""
Unit & Integration Tests for SkillEnvelopeValidator (scripts/skill_validator.py)
================================================================================
Verifies structural validation, YAML frontmatter schemas, shallow orchestration enforcement,
policy lexicon auditing, and command boundary detection for custom CTF skills.
"""

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from scripts.skill_validator import (
    REPO_ROOT,
    SkillEnvelopeValidator,
    parse_simple_yaml_frontmatter,
)


@pytest.fixture
def temp_skills_dir():
    """Creates a temporary workspace skills directory."""
    tmp = tempfile.mkdtemp(prefix="test_skills_")
    yield Path(tmp)
    shutil.rmtree(tmp, ignore_errors=True)


def test_validate_valid_builtin_skills():
    """Verifies that all 11 core framework skills pass validation."""
    skills_dir = REPO_ROOT / "skills"
    reports = SkillEnvelopeValidator.validate_all_skills(skills_dir)

    assert len(reports) == 11
    for r in reports:
        assert r.is_valid is True, f"Core skill {r.skill_name} failed validation: {r.errors}"
        assert r.error_count == 0


def test_detect_missing_skill_md(temp_skills_dir):
    """Verifies that a skill directory without SKILL.md fails structural integrity."""
    bad_skill = temp_skills_dir / "my-broken-skill"
    bad_skill.mkdir()

    report = SkillEnvelopeValidator.validate_skill_dir(bad_skill)
    assert report.is_valid is False
    assert any(e.rule == "STRUCTURAL_INTEGRITY" for e in report.errors)


def test_detect_invalid_frontmatter(temp_skills_dir):
    """Verifies that missing or malformed YAML frontmatter is caught."""
    skill = temp_skills_dir / "bad-fm-skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text("# No Frontmatter\nJust raw text here", encoding="utf-8")

    report = SkillEnvelopeValidator.validate_skill_dir(skill)
    assert report.is_valid is False
    assert any(e.rule == "FRONTMATTER_SCHEMA" for e in report.errors)


def test_detect_missing_name_or_description(temp_skills_dir):
    """Verifies that missing 'name' or 'description' fields produce errors."""
    skill = temp_skills_dir / "incomplete-skill"
    skill.mkdir()
    content = """---
name: incomplete-skill
---
# Incomplete
Missing description attribute.
"""
    (skill / "SKILL.md").write_text(content, encoding="utf-8")

    report = SkillEnvelopeValidator.validate_skill_dir(skill)
    assert report.is_valid is False
    assert any("description" in e.message for e in report.errors)


def test_detect_recursive_orchestration_violation(temp_skills_dir):
    """Verifies that attempting multi-tier subagent chaining triggers Shallow Orchestration failure."""
    skill = temp_skills_dir / "recursive-skill"
    skill.mkdir()
    content = """---
name: recursive-skill
description: Custom skill that attempts prohibited recursive subagent dispatching.
---
# Bad Orchestration
When executed, this skill calls:
`invoke_subagent(child_agent, invoke_subagent(leaf))`
depth: 2
"""
    (skill / "SKILL.md").write_text(content, encoding="utf-8")

    report = SkillEnvelopeValidator.validate_skill_dir(skill)
    assert report.is_valid is False
    assert any(e.rule == "ENVELOPE_SHALLOW_DEPTH" for e in report.errors)


def test_detect_policy_triggers_and_warn(temp_skills_dir):
    """Verifies that unshielded aggressive terminology produces policy warnings with suggestions."""
    skill = temp_skills_dir / "unsafe-lexicon-skill"
    skill.mkdir()
    content = """---
name: unsafe-lexicon-skill
description: Custom skill for testing lexical policy triggers and suggestions.
---
# Test Vectors
We construct an evil_payload to weaponize the vulnerability and jailbreak the parser.
"""
    (skill / "SKILL.md").write_text(content, encoding="utf-8")

    report = SkillEnvelopeValidator.validate_skill_dir(skill)
    assert any(w.rule == "POLICY_TRIGGER_LEXICON" for w in report.warnings)


def test_detect_prohibited_destructive_commands(temp_skills_dir):
    """Verifies that dangerous commands like rm -rf / or crontab are rejected."""
    skill = temp_skills_dir / "dangerous-skill"
    skill.mkdir()
    content = """---
name: dangerous-skill
description: Custom skill attempting prohibited host destruction commands.
---
# Dangerous Script
Run this cleanup:
```bash
rm -rf /
crontab -e
```
"""
    (skill / "SKILL.md").write_text(content, encoding="utf-8")

    report = SkillEnvelopeValidator.validate_skill_dir(skill)
    assert report.is_valid is False
    assert any(e.rule == "PROHIBITED_COMMANDS" for e in report.errors)


def test_cli_validate_skill_json(temp_skills_dir):
    """Verifies CLI execution with --json output and exit codes."""
    valid_skill = temp_skills_dir / "custom-heap-tool"
    valid_skill.mkdir()
    content = """---
name: custom-heap-tool
description: Custom specialized diagnostic tool for glibc 2.39 heap analysis.
---
# Glibc Heap Tool
Supports --blitz fast flag extraction and --deep RCA writeup generation.
"""
    (valid_skill / "SKILL.md").write_text(content, encoding="utf-8")

    cmd = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "skill_validator.py"),
        str(valid_skill),
        "--json",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert data["total_skills"] == 1
    assert data["valid_skills"] == 1
    assert data["has_errors"] is False
