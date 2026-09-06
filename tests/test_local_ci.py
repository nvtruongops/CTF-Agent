#!/usr/bin/env python3
"""
CI Validation: Local CI Runner Integration Tests
Verifies that LocalCIRunner, Python CLI dispatcher, and Node launcher
correctly execute local validation phases and produce compliant reports.
"""

import sys
import json
import shutil
import subprocess
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

try:
    from local_ci import LocalCIRunner
except ImportError:
    LocalCIRunner = None


def test_local_ci_runner_import_and_static_phases():
    """Verifies that LocalCIRunner can be imported and each individual static phase passes."""
    assert LocalCIRunner is not None, "LocalCIRunner must be importable from scripts/local_ci.py"

    runner = LocalCIRunner(repo_root=REPO_ROOT, auto_fix=False)

    res_sec = runner.phase_security_and_secrets()
    assert res_sec.passed is True, f"Security phase failed: {res_sec.details}"

    res_git = runner.phase_git_and_line_endings()
    assert res_git.passed is True, f"Git hygiene phase failed: {res_git.details}"

    res_ver = runner.phase_version_synchronization()
    assert res_ver.passed is True, f"Version sync phase failed: {res_ver.details}"

    res_assets = runner.phase_asset_mirrors()
    assert res_assets.passed is True, f"Asset mirrors phase failed: {res_assets.details}"

    res_skills = runner.phase_skill_and_persona_schemas()
    assert res_skills.passed is True, f"Skill schema phase failed: {res_skills.details}"

    res_docs = runner.phase_documentation_standards()
    assert res_docs.passed is True, f"Documentation phase failed: {res_docs.details}"


def test_local_ci_cli_quick_json():
    """Verifies that 'python scripts/local_ci.py --quick --json' returns valid report."""
    cmd = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "local_ci.py"),
        "--quick",
        "--json",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert res.returncode == 0, f"local_ci.py failed with code {res.returncode}: {res.stderr}"

    data = json.loads(res.stdout)
    assert data["all_passed"] is True
    assert len(data["phases"]) >= 6
    assert data["total_duration_seconds"] > 0


def test_local_ci_ctf_agent_cli_dispatch():
    """Verifies that 'python ctf_agent_cli.py ci --quick --json' correctly routes to local_ci.py."""
    cmd = [
        sys.executable,
        str(REPO_ROOT / "ctf_agent_cli.py"),
        "ci",
        "--quick",
        "--json",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert res.returncode == 0, f"ctf_agent_cli.py ci failed: {res.stderr}"

    data = json.loads(res.stdout)
    assert data["all_passed"] is True


def test_local_ci_node_launcher_dispatch():
    """Verifies that 'node bin/ctf-agent.js ci --quick --json' correctly routes to local_ci.py."""
    if shutil.which("node") is None:
        pytest.skip("Node.js runtime not found in PATH")

    cmd = [
        "node",
        str(REPO_ROOT / "bin" / "ctf-agent.js"),
        "ci",
        "--quick",
        "--json",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert res.returncode == 0, f"bin/ctf-agent.js ci failed: {res.stderr}"

    data = json.loads(res.stdout)
    assert data["all_passed"] is True
