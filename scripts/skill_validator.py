#!/usr/bin/env python3
"""
CTF-Agent Custom Skill & Prompt Envelope Compatibility Validator
=================================================================
Validates external custom skills added to `.agents/skills/` or `skills/`
to prevent prompt envelope conflicts, recursive orchestration rejections,
and LLM backend safety policy violations.

Zero Host Dependencies: Pure Python Standard Library.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent

# Reserved built-in skills defined by CTF-Agent framework
RESERVED_CORE_SKILLS: Set[str] = {
    "solve-challenge",
    "ctf-web",
    "ctf-pwn",
    "ctf-crypto",
    "ctf-reverse",
    "ctf-forensics",
    "ctf-ai-ml",
    "ctf-osint",
    "ctf-misc",
    "ctf-malware",
    "ctf-writeup",
}

# High-risk lexical triggers that trigger upstream LLM safety policy refusals
POLICY_TRIGGER_DICTIONARY: Dict[str, str] = {
    "evil_payload": "test_payload / proof-of-concept input",
    "malicious_payload": "diagnostic test vector",
    "weaponize": "reproduce vulnerability / construct PoC",
    "jailbreak": "evaluate prompt robustness",
    "steal credentials": "retrieve challenge token",
    "exfiltrate": "retrieve / verify challenge flag",
    "c2 beacon": "simulated command channel",
    "redteam attack": "diagnostic security assessment",
    "bypass safety": "evaluate boundary controls",
    "bypass policy": "test mitigation boundaries",
}

# Dangerous / destructive command patterns
DESTRUCTIVE_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"\brm\s+-[a-zA-Z]*rf?\s+/(?:\s|$|\*)", re.I), "Root filesystem deletion (rm -rf /)"),
    (re.compile(r"\bmkfs(?:\.[a-z0-9]+)?\s+", re.I), "Filesystem format (mkfs)"),
    (re.compile(r"\bdd\s+if=/dev/(?:zero|urandom)\s+of=/dev/[a-z0-9]+", re.I), "Raw block device wipe (dd)"),
    (re.compile(r"\bcrontab\s+-[eir]", re.I), "Persistent crontab installation"),
    (re.compile(r"\.ssh/authorized_keys", re.I), "SSH key injection persistence"),
]

# Recursive multi-agent chaining indicators
RECURSIVE_CHAIN_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"invoke_subagent\s*\([^)]*invoke_subagent", re.I), "Recursive subagent dispatch within subagent"),
    (re.compile(r"\bdepth\s*:\s*[2-9]\b", re.I), "Orchestration depth > 1 requested"),
    (re.compile(r"(?:chain|delegate)\s+to\s+(?:another|nested|child)\s+subagent", re.I), "Multi-tier nested subagent delegation"),
]


class ValidationLevel(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


@dataclass
class ValidationIssue:
    rule: str
    level: ValidationLevel
    message: str
    line_number: Optional[int] = None
    suggestion: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule,
            "level": self.level.value,
            "message": self.message,
            "line_number": self.line_number,
            "suggestion": self.suggestion,
        }


@dataclass
class SkillValidationReport:
    skill_name: str
    skill_path: str
    is_valid: bool
    errors: List[ValidationIssue] = field(default_factory=list)
    warnings: List[ValidationIssue] = field(default_factory=list)
    info: List[ValidationIssue] = field(default_factory=list)

    @property
    def error_count(self) -> int:
        return len(self.errors)

    @property
    def warning_count(self) -> int:
        return len(self.warnings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "skill_name": self.skill_name,
            "skill_path": self.skill_path,
            "is_valid": self.is_valid,
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
            "info_count": len(self.info),
            "errors": [e.to_dict() for e in self.errors],
            "warnings": [w.to_dict() for w in self.warnings],
            "info": [i.to_dict() for i in self.info],
        }


def parse_simple_yaml_frontmatter(content: str) -> Tuple[Optional[Dict[str, Any]], Optional[str], Optional[int]]:
    """
    Parses YAML frontmatter between opening and closing '---' markers without external libraries.
    Returns: (parsed_dict, error_message, closing_line_number)
    """
    lines = content.splitlines()
    if not lines or lines[0].strip() != "---":
        return None, "File does not begin with frontmatter marker '---'", None

    closing_idx = -1
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            closing_idx = i
            break

    if closing_idx == -1:
        return None, "Unterminated frontmatter (missing closing '---')", None

    yaml_lines = lines[1:closing_idx]
    data: Dict[str, Any] = {}
    current_key: Optional[str] = None

    for line_no, raw_line in enumerate(yaml_lines, start=2):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if ":" in line:
            key, val = line.split(":", 1)
            key = key.strip()
            val = val.strip()

            # Handle quotes
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                val = val[1:-1]

            data[key] = val
            current_key = key
        elif current_key and line.startswith("- "):
            # Simple list item
            item = line[2:].strip()
            if not isinstance(data[current_key], list):
                data[current_key] = []
            data[current_key].append(item)

    return data, None, closing_idx + 1


class SkillEnvelopeValidator:
    """Validates custom CTF skills against architecture, security envelope, and policy rules."""

    @classmethod
    def validate_skill_dir(cls, skill_dir: Path, is_core: bool = False) -> SkillValidationReport:
        skill_path_str = str(skill_dir.resolve())
        skill_name = skill_dir.name

        errors: List[ValidationIssue] = []
        warnings: List[ValidationIssue] = []
        info: List[ValidationIssue] = []

        # 1. Structural Integrity Check
        if not skill_dir.exists() or not skill_dir.is_dir():
            errors.append(
                ValidationIssue(
                    rule="STRUCTURAL_INTEGRITY",
                    level=ValidationLevel.ERROR,
                    message=f"Skill path is not an existing directory: {skill_dir}",
                )
            )
            return SkillValidationReport(
                skill_name=skill_name,
                skill_path=skill_path_str,
                is_valid=False,
                errors=errors,
            )

        skill_md = skill_dir / "SKILL.md"
        if not skill_md.is_file():
            errors.append(
                ValidationIssue(
                    rule="STRUCTURAL_INTEGRITY",
                    level=ValidationLevel.ERROR,
                    message="Missing mandatory 'SKILL.md' entrypoint file in skill directory.",
                    suggestion="Create a 'SKILL.md' file with valid YAML frontmatter and operational instructions.",
                )
            )
            return SkillValidationReport(
                skill_name=skill_name,
                skill_path=skill_path_str,
                is_valid=False,
                errors=errors,
            )

        try:
            content = skill_md.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            errors.append(
                ValidationIssue(
                    rule="STRUCTURAL_INTEGRITY",
                    level=ValidationLevel.ERROR,
                    message="SKILL.md is not valid UTF-8 encoded text.",
                    suggestion="Convert SKILL.md to standard UTF-8 encoding.",
                )
            )
            return SkillValidationReport(
                skill_name=skill_name,
                skill_path=skill_path_str,
                is_valid=False,
                errors=errors,
            )

        # 2. YAML Frontmatter Schema
        fm_data, fm_err, end_line = parse_simple_yaml_frontmatter(content)
        if fm_err:
            errors.append(
                ValidationIssue(
                    rule="FRONTMATTER_SCHEMA",
                    level=ValidationLevel.ERROR,
                    message=f"Invalid frontmatter syntax: {fm_err}",
                    suggestion="Ensure SKILL.md starts with '---', contains key-value pairs, and closes with '---'.",
                )
            )
        else:
            assert fm_data is not None
            # Check name field
            declared_name = fm_data.get("name")
            if not declared_name:
                errors.append(
                    ValidationIssue(
                        rule="FRONTMATTER_SCHEMA",
                        level=ValidationLevel.ERROR,
                        message="Frontmatter is missing required 'name' attribute.",
                        suggestion=f"Add 'name: {skill_name}' inside frontmatter.",
                    )
                )
            else:
                declared_name_str = str(declared_name).strip()
                if not re.match(r"^[a-z0-9-_]+$", declared_name_str):
                    errors.append(
                        ValidationIssue(
                            rule="FRONTMATTER_SCHEMA",
                            level=ValidationLevel.ERROR,
                            message=f"Declared name '{declared_name_str}' contains invalid characters.",
                            suggestion="Use lowercase alphanumeric characters, dashes, and underscores only.",
                        )
                    )
                elif declared_name_str != skill_name:
                    warnings.append(
                        ValidationIssue(
                            rule="FRONTMATTER_SCHEMA",
                            level=ValidationLevel.WARNING,
                            message=f"Declared name '{declared_name_str}' does not match directory name '{skill_name}'.",
                            suggestion=f"Rename directory to '{declared_name_str}' or update frontmatter name.",
                        )
                    )

            # Check description field
            description = fm_data.get("description")
            if not description or len(str(description).strip()) < 20:
                errors.append(
                    ValidationIssue(
                        rule="FRONTMATTER_SCHEMA",
                        level=ValidationLevel.ERROR,
                        message="Frontmatter 'description' is missing or too short (< 20 characters).",
                        suggestion="Provide a clear, detailed description explaining when and how agents should invoke this skill.",
                    )
                )

            # 3. Collision / Namespace Guard
            if not is_core and declared_name in RESERVED_CORE_SKILLS:
                warnings.append(
                    ValidationIssue(
                        rule="NAME_COLLISION",
                        level=ValidationLevel.WARNING,
                        message=f"Skill name '{declared_name}' collides with built-in framework skill.",
                        suggestion="If this is a custom tool, rename to a unique identifier (e.g. 'custom-pwn-heap') to avoid overriding core functionality.",
                    )
                )

        # 4. Prompt Envelope & Shallow Orchestration Checks
        body_content = content[content.find("---", 3) + 3 :] if "---" in content[3:] else content

        for pat, desc in RECURSIVE_CHAIN_PATTERNS:
            match = pat.search(body_content)
            if match:
                errors.append(
                    ValidationIssue(
                        rule="ENVELOPE_SHALLOW_DEPTH",
                        level=ValidationLevel.ERROR,
                        message=f"Violation of Shallow Orchestration Mandate (Depth <= 1): {desc}.",
                        suggestion="CTF-Agent enforces Depth=1 execution. Custom skills must operate as direct specialist workers or leaf tools without recursive agent spawning.",
                    )
                )

        # Mode Awareness & Stop Conditions
        has_blitz = bool(re.search(r"\b(?:--blitz|--fast|blitz mode|stop-on-flag)\b", body_content, re.I))
        has_deep = bool(re.search(r"\b(?:--deep|--lab|deep analysis|rca|writeup)\b", body_content, re.I))

        if not (has_blitz or has_deep):
            warnings.append(
                ValidationIssue(
                    rule="MODE_AWARENESS",
                    level=ValidationLevel.WARNING,
                    message="Skill does not document operational mode handling (--blitz or --deep).",
                    suggestion="Add instructions specifying fast flag retrieval for Blitz mode and deep RCA/writeup for Lab mode.",
                )
            )
        else:
            info.append(
                ValidationIssue(
                    rule="MODE_AWARENESS",
                    level=ValidationLevel.INFO,
                    message=f"Operational mode awareness verified (Blitz: {has_blitz}, Deep: {has_deep}).",
                )
            )

        # 5. LLM Safety & Policy Lexicon Audit
        for trigger, replacement in POLICY_TRIGGER_DICTIONARY.items():
            pattern = re.compile(rf"\b{re.escape(trigger)}\b", re.I)
            matches = list(pattern.finditer(body_content))
            if matches:
                # Find line number of first match
                first_match = matches[0]
                line_no = body_content[: first_match.start()].count("\n") + (end_line or 1)
                warnings.append(
                    ValidationIssue(
                        rule="POLICY_TRIGGER_LEXICON",
                        level=ValidationLevel.WARNING,
                        line_number=line_no,
                        message=f"Detected high-risk policy trigger jargon: '{trigger}'.",
                        suggestion=f"Replace '{trigger}' with policy-safe academic equivalent: '{replacement}'.",
                    )
                )

        # 6. Prohibited Destructive Command Inspection
        for pat, desc in DESTRUCTIVE_PATTERNS:
            match = pat.search(body_content)
            if match:
                line_no = body_content[: match.start()].count("\n") + (end_line or 1)
                errors.append(
                    ValidationIssue(
                        rule="PROHIBITED_COMMANDS",
                        level=ValidationLevel.ERROR,
                        line_number=line_no,
                        message=f"Detected prohibited dangerous command pattern: {desc}.",
                        suggestion="Remove dangerous host destruction or backdoor persistence commands from skill instructions.",
                    )
                )

        is_valid = len(errors) == 0
        return SkillValidationReport(
            skill_name=skill_name,
            skill_path=skill_path_str,
            is_valid=is_valid,
            errors=errors,
            warnings=warnings,
            info=info,
        )

    @classmethod
    def validate_all_skills(cls, parent_dir: Path) -> List[SkillValidationReport]:
        """Scans and validates all skills within a directory."""
        reports: List[SkillValidationReport] = []
        if not parent_dir.exists() or not parent_dir.is_dir():
            return reports

        for item in sorted(parent_dir.iterdir()):
            if item.is_dir() and (item / "SKILL.md").exists():
                is_core = (parent_dir.resolve() == (REPO_ROOT / "skills").resolve())
                report = cls.validate_skill_dir(item, is_core=is_core)
                reports.append(report)

        return reports


def print_validation_report(reports: List[SkillValidationReport]) -> int:
    """Prints user-friendly terminal report. Returns 0 if all valid, 1 otherwise."""
    print("\n=================================================================")
    print("CTF-AGENT SKILL & PROMPT ENVELOPE COMPATIBILITY AUDIT")
    print("=================================================================")

    total = len(reports)
    passed = sum(1 for r in reports if r.is_valid)
    failed = total - passed
    total_warnings = sum(len(r.warnings) for r in reports)

    for r in reports:
        status_tag = "[PASS]" if r.is_valid else "[FAIL]"
        print(f"\n{status_tag} Skill: {r.skill_name}")
        print(f"       Path : {r.skill_path}")

        if r.errors:
            print("       Errors:")
            for err in r.errors:
                loc = f" (line {err.line_number})" if err.line_number else ""
                print(f"         - [{err.rule}]{loc}: {err.message}")
                if err.suggestion:
                    print(f"           Tip: {err.suggestion}")

        if r.warnings:
            print("       Warnings:")
            for warn in r.warnings:
                loc = f" (line {warn.line_number})" if warn.line_number else ""
                print(f"         - [{warn.rule}]{loc}: {warn.message}")
                if warn.suggestion:
                    print(f"           Tip: {warn.suggestion}")

    print("\n-----------------------------------------------------------------")
    print(f"Summary: {passed}/{total} skills valid | {failed} errors | {total_warnings} warnings")
    print("=================================================================\n")

    return 0 if failed == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="CTF-Agent Custom Skill & Prompt Envelope Compatibility Validator"
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Path to specific skill directory or parent directory containing skills.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Validate all skills found in target directory (or current workspace .agents/skills).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON format.",
    )

    args = parser.parse_args()

    # Determine target path
    if args.target:
        target_path = Path(args.target).resolve()
    else:
        # Default to local workspace .agents/skills or repo skills/
        dot_skills = Path.cwd() / ".agents" / "skills"
        if dot_skills.exists():
            target_path = dot_skills
            args.all = True
        else:
            target_path = REPO_ROOT / "skills"
            args.all = True

    reports: List[SkillValidationReport] = []

    if args.all or (target_path.is_dir() and not (target_path / "SKILL.md").exists()):
        reports = SkillEnvelopeValidator.validate_all_skills(target_path)
        if not reports:
            print(f"No valid skill directories containing 'SKILL.md' found in {target_path}", file=sys.stderr)
            return 1
    else:
        # Single skill directory
        is_core = (target_path.parent.resolve() == (REPO_ROOT / "skills").resolve())
        report = SkillEnvelopeValidator.validate_skill_dir(target_path, is_core=is_core)
        reports = [report]

    if args.json:
        payload = {
            "total_skills": len(reports),
            "valid_skills": sum(1 for r in reports if r.is_valid),
            "has_errors": any(not r.is_valid for r in reports),
            "reports": [r.to_dict() for r in reports],
        }
        print(json.dumps(payload, indent=2))
        return 0 if payload["valid_skills"] == payload["total_skills"] else 1

    return print_validation_report(reports)


if __name__ == "__main__":
    sys.exit(main())
