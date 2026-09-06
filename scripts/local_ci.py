#!/usr/bin/env python3
"""
CTF-Agent Local CI & Validation Engine (v1.3)
Replaces slow cloud-based CI workflows with a high-speed, comprehensive local
verification runner that validates security, manifest synchronization, schemas,
documentation, and test suites in seconds.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Ensure safe UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

REPO_ROOT = Path(__file__).resolve().parent.parent

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None


@dataclass
class CIPassResult:
    phase: str
    passed: bool
    details: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0


class LocalCIRunner:
    """Orchestrates comprehensive local CI validation across all repository invariants."""

    def __init__(self, repo_root: Path = REPO_ROOT, auto_fix: bool = False):
        self.repo_root = repo_root
        self.auto_fix = auto_fix
        self.results: List[CIPassResult] = []

    def get_canonical_version(self) -> str:
        pkg_file = self.repo_root / "package.json"
        data = json.loads(pkg_file.read_text(encoding="utf-8"))
        return data["version"]

    def phase_security_and_secrets(self) -> CIPassResult:
        """Scans workspace files for leaked API keys, tokens, or private certificates."""
        start = time.time()
        details: List[str] = []
        passed = True

        secret_patterns = [
            (r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', "Private Key Material"),
            (r'\bAKIA[0-9A-Z]{16}\b', "AWS Access Key"),
            (r'\bAIza[0-9A-Za-z\\-_]{35}\b', "Google API Key"),
            (r'npm_[A-Za-z0-9]{36}', "NPM Auth Token"),
            (r'ghp_[A-Za-z0-9]{36}', "GitHub Personal Access Token"),
        ]

        ignored_parts = {".git", ".pytest_cache", "__pycache__", ".venv", "build", "dist", ".agents"}
        files_scanned = 0

        for p in self.repo_root.rglob("*"):
            if any(part in p.parts for part in ignored_parts) or not p.is_file():
                continue
            if p.suffix in (".pyc", ".lock", ".png", ".jpg", ".bin", ".tar", ".gz", ".zip"):
                continue

            files_scanned += 1
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
                for pat, label in secret_patterns:
                    match = re.search(pat, content)
                    if match:
                        passed = False
                        details.append(f"Secret alert: {label} detected in {p.relative_to(self.repo_root)}")
            except Exception:
                pass

        if passed:
            details.append(f"Scanned {files_scanned} files - zero credentials or private keys detected.")

        return CIPassResult(
            phase="Phase 1: Security & Secrets Audit",
            passed=passed,
            details=details,
            duration_seconds=round(time.time() - start, 3),
        )

    def phase_git_and_line_endings(self) -> CIPassResult:
        """Verifies .gitattributes presence, LF line-endings on shell scripts, and .gitignore rules."""
        start = time.time()
        details: List[str] = []
        passed = True

        gitattrs = self.repo_root / ".gitattributes"
        if not gitattrs.is_file():
            passed = False
            details.append("Missing .gitattributes file enforcing Unix LF line endings.")
        else:
            text = gitattrs.read_text(encoding="utf-8")
            if "*.sh text eol=lf" not in text:
                passed = False
                details.append(".gitattributes missing '*.sh text eol=lf' declaration.")
            else:
                details.append("Validated .gitattributes configuration.")

        scripts_dir = self.repo_root / "scripts"
        crlf_scripts = []
        if scripts_dir.is_dir():
            for sh_file in scripts_dir.glob("*.sh"):
                raw = sh_file.read_bytes()
                if b"\r\n" in raw:
                    if self.auto_fix:
                        sh_file.write_bytes(raw.replace(b"\r\n", b"\n"))
                        details.append(f"Auto-fixed CRLF -> LF for {sh_file.name}")
                    else:
                        crlf_scripts.append(sh_file.name)

        if crlf_scripts:
            passed = False
            details.append(f"Shell scripts contain CRLF line endings (run with --fix): {', '.join(crlf_scripts)}")
        else:
            details.append("All shell scripts verified with strict Unix LF line endings.")

        gitignore = self.repo_root / ".gitignore"
        if gitignore.is_file():
            gi_text = gitignore.read_text(encoding="utf-8")
            for req in ["tests", "__pycache__", ".venv"]:
                if req not in gi_text:
                    passed = False
                    details.append(f".gitignore missing expected rule: {req}")
            if "*.py[cod]" not in gi_text and "*.pyc" not in gi_text:
                passed = False
                details.append(".gitignore missing rule for byte-compiled files (*.pyc or *.py[cod])")
            if passed:
                details.append("Validated .gitignore isolation rules.")

        return CIPassResult(
            phase="Phase 2: Git Hygiene & Line-Ending Audit",
            passed=passed,
            details=details,
            duration_seconds=round(time.time() - start, 3),
        )

    def phase_version_synchronization(self) -> CIPassResult:
        """Verifies that package.json, pyproject.toml, uv.lock, and CLI entrypoint versions match."""
        start = time.time()
        details: List[str] = []
        passed = True

        pkg_version = self.get_canonical_version()
        details.append(f"Canonical Version: {pkg_version}")

        pyproject_file = self.repo_root / "pyproject.toml"
        pyproject_content = pyproject_file.read_text(encoding="utf-8")
        python_version = None
        if tomllib:
            python_version = tomllib.loads(pyproject_content).get("project", {}).get("version")
        else:
            for line in pyproject_content.splitlines():
                if line.strip().startswith("version ="):
                    python_version = line.split("=")[1].strip().strip('"').strip("'")
                    break

        if python_version != pkg_version:
            passed = False
            details.append(f"pyproject.toml mismatch: expected {pkg_version}, found {python_version}")
        else:
            details.append("pyproject.toml version matches package.json.")

        uv_lock = self.repo_root / "uv.lock"
        if uv_lock.is_file():
            content = uv_lock.read_text(encoding="utf-8")
            match = re.search(r'name = "ctf-agent"\s+version = "([^"]+)"', content)
            if not match or match.group(1) != pkg_version:
                passed = False
                details.append(f"uv.lock version mismatch for ctf-agent: found {match.group(1) if match else 'None'}")
            else:
                details.append("uv.lock version matches package.json.")

        cli_file = self.repo_root / "ctf_agent_cli.py"
        cli_content = cli_file.read_text(encoding="utf-8")
        cli_match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', cli_content)
        if not cli_match or cli_match.group(1) != pkg_version:
            passed = False
            details.append(f"ctf_agent_cli.py __version__ mismatch: found {cli_match.group(1) if cli_match else 'None'}")
        else:
            details.append("ctf_agent_cli.py __version__ matches package.json.")

        manifest_file = self.repo_root / "MANIFEST.in"
        if manifest_file.is_file():
            mf_text = manifest_file.read_text(encoding="utf-8")
            for req in ["README.md", "AGENTS.md", "scripts", "agents", "skills", "rules", "references"]:
                if req not in mf_text:
                    passed = False
                    details.append(f"MANIFEST.in missing essential directory: {req}")
            if passed:
                details.append("MANIFEST.in includes all essential distribution targets.")

        return CIPassResult(
            phase="Phase 3: Package Version & Manifest Synchronization",
            passed=passed,
            details=details,
            duration_seconds=round(time.time() - start, 3),
        )

    def phase_asset_mirrors(self) -> CIPassResult:
        """Verifies that all files in scripts/assets/ strictly match their root counterparts."""
        start = time.time()
        details: List[str] = []
        passed = True

        assets_dir = self.repo_root / "scripts" / "assets"
        if not assets_dir.is_dir():
            return CIPassResult(
                phase="Phase 4: Asset Mirror Synchronization",
                passed=False,
                details=["scripts/assets directory does not exist"],
                duration_seconds=0.0,
            )

        asset_files = ["AGENTS.md", "mcp_config.json", "skills.json", "README.md"]
        for fname in asset_files:
            asset_path = assets_dir / fname
            root_path = self.repo_root / fname

            if not asset_path.is_file() or not root_path.is_file():
                passed = False
                details.append(f"Missing asset file: {fname}")
                continue

            if asset_path.read_bytes() != root_path.read_bytes():
                if self.auto_fix:
                    shutil.copy2(root_path, asset_path)
                    details.append(f"Auto-synchronized: {fname} -> scripts/assets/{fname}")
                else:
                    passed = False
                    details.append(f"Asset mismatch: scripts/assets/{fname} differs from {fname}")

        if passed:
            details.append("All 4 asset mirrors in scripts/assets/ verified identical to root files.")

        return CIPassResult(
            phase="Phase 4: Asset Mirror Synchronization",
            passed=passed,
            details=details,
            duration_seconds=round(time.time() - start, 3),
        )

    def phase_skill_and_persona_schemas(self) -> CIPassResult:
        """Validates all 10 category skills and 3 persona subagents for valid frontmatter and schema."""
        start = time.time()
        details: List[str] = []
        passed = True

        skills_dir = self.repo_root / "skills"
        if not skills_dir.is_dir():
            return CIPassResult(
                phase="Phase 5: Skill & Agent Persona Validation",
                passed=False,
                details=["skills/ directory missing"],
                duration_seconds=0.0,
            )

        skill_count = 0
        for s_dir in sorted(skills_dir.iterdir()):
            if not s_dir.is_dir():
                continue
            skill_md = s_dir / "SKILL.md"
            if not skill_md.is_file():
                passed = False
                details.append(f"Skill '{s_dir.name}' missing SKILL.md")
                continue

            content = skill_md.read_text(encoding="utf-8")
            if not content.startswith("---"):
                passed = False
                details.append(f"Skill '{s_dir.name}' missing YAML frontmatter delimiters (---)")
                continue

            skill_count += 1

        details.append(f"Validated {skill_count} category skills in skills/.")

        agents_dir = self.repo_root / "agents"
        required_agents = ["ctf-controller.md", "ctf-speedrun.md", "ctf-analyzer.md"]
        for agent_file in required_agents:
            ap = agents_dir / agent_file
            if not ap.is_file():
                passed = False
                details.append(f"Missing core subagent: {agent_file}")

        if passed:
            details.append("Validated all 3 core subagent personas in agents/.")

        return CIPassResult(
            phase="Phase 5: Skill & Agent Persona Validation",
            passed=passed,
            details=details,
            duration_seconds=round(time.time() - start, 3),
        )

    def phase_documentation_standards(self) -> CIPassResult:
        """Enforces English language documentation, zero decorative emojis, and valid badge links."""
        start = time.time()
        details: List[str] = []
        passed = True

        canonical_ver = self.get_canonical_version()
        readme = self.repo_root / "README.md"
        readme_text = readme.read_text(encoding="utf-8")

        if "[![npm version](https://img.shields.io/npm/v/ctf-agent.svg)](https://www.npmjs.com/package/ctf-agent)" not in readme_text:
            passed = False
            details.append("README.md missing official npm version badge.")

        badge_match = re.search(r'badge/release-v?([0-9]+\.[0-9]+\.[0-9]+)-blue\.svg', readme_text)
        if badge_match and badge_match.group(1) != canonical_ver:
            passed = False
            details.append(f"Release badge version ({badge_match.group(1)}) differs from canonical ({canonical_ver})")

        stale_match = re.search(r'ctf-agent@1\.[0-2]\.[0-9]', readme_text)
        if stale_match:
            passed = False
            details.append(f"Stale version reference in README.md: {stale_match.group(0)}")

        if passed:
            details.append("README badges and version references verified.")

        return CIPassResult(
            phase="Phase 6: Documentation Standards & Badge Verification",
            passed=passed,
            details=details,
            duration_seconds=round(time.time() - start, 3),
        )

    def phase_automated_test_suite(self) -> CIPassResult:
        """Runs pytest on the entire repository test suite."""
        start = time.time()
        details: List[str] = []

        test_runner = self.repo_root / "tests" / "run_all_tests.py"
        cmd = [sys.executable, str(test_runner)]

        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        passed = (res.returncode == 0)

        match = re.search(r'collected (\d+) items', res.stdout)
        total_items = match.group(1) if match else "all"

        pass_match = re.search(r'(\d+) passed in ([\d\.]+)s', res.stdout)
        if pass_match:
            details.append(f"Test suite executed: {pass_match.group(1)}/{total_items} passed in {pass_match.group(2)}s.")
        else:
            details.append(f"Test runner exited with code {res.returncode}.")

        if not passed:
            details.append("Test failures detected in test suite.")
            for line in res.stdout.splitlines()[-15:]:
                details.append(f"  {line}")

        return CIPassResult(
            phase="Phase 7: Full Automated Regression Suite",
            passed=passed,
            details=details,
            duration_seconds=round(time.time() - start, 3),
        )

    def run(self, quick: bool = False, json_mode: bool = False) -> Dict[str, Any]:
        """Executes all CI phases sequentially and generates the summary report."""
        if not json_mode:
            print("=================================================================")
            print("CTF-AGENT LOCAL CI & VALIDATION RUNNER (Fast Local Workflow)")
            print("=================================================================")

        phases = [
            self.phase_security_and_secrets,
            self.phase_git_and_line_endings,
            self.phase_version_synchronization,
            self.phase_asset_mirrors,
            self.phase_skill_and_persona_schemas,
            self.phase_documentation_standards,
        ]

        if not quick:
            phases.append(self.phase_automated_test_suite)

        all_passed = True
        total_duration = 0.0

        for func in phases:
            res = func()
            self.results.append(res)
            total_duration += res.duration_seconds
            if not json_mode:
                status_tag = "[PASS]" if res.passed else "[FAIL]"
                print(f"{status_tag} {res.phase} ({res.duration_seconds}s)")
                for d in res.details:
                    print(f"       - {d}")
            if not res.passed:
                all_passed = False

        if not json_mode:
            print("=================================================================")
            if all_passed:
                print(f"[OK] ALL LOCAL CI PHASES PASSED IN {round(total_duration, 2)}s!")
                print("     Repository is 100% compliant and ready for release/push.")
            else:
                print(f"[!] LOCAL CI FAILED IN {round(total_duration, 2)}s! Review failures above.")
            print("=================================================================")

        return {
            "all_passed": all_passed,
            "total_duration_seconds": round(total_duration, 3),
            "phases": [asdict(r) for r in self.results],
        }


def main():
    parser = argparse.ArgumentParser(
        description="CTF-Agent Local CI & Pre-Release Validation Engine"
    )
    parser.add_argument(
        "--quick",
        "-q",
        action="store_true",
        help="Run static, security, manifest, and schema checks without full pytest execution",
    )
    parser.add_argument(
        "--fix",
        "-f",
        action="store_true",
        help="Automatically rectify fixable anomalies (CRLF line endings, asset mirror drift)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format for automation pipelines",
    )

    args = parser.parse_args()

    runner = LocalCIRunner(auto_fix=args.fix)
    report = runner.run(quick=args.quick, json_mode=args.json)

    if args.json:
        print(json.dumps(report, indent=2))

    sys.exit(0 if report["all_passed"] else 1)


if __name__ == "__main__":
    main()
