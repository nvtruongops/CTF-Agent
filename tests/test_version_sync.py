#!/usr/bin/env python3
"""
CI Validation: Version Synchronization & Packaging Completeness
Ensures that package.json, pyproject.toml, and CLI entrypoints are 100% aligned,
and verifies that all essential assets are declared in distribution manifests.
"""

import sys
import json
import shutil
import subprocess
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None


def test_package_json_and_pyproject_version_match():
    """Verifies that package.json and pyproject.toml define the exact same version string."""
    pkg_file = REPO_ROOT / "package.json"
    pyproject_file = REPO_ROOT / "pyproject.toml"

    assert pkg_file.is_file(), "package.json must exist"
    assert pyproject_file.is_file(), "pyproject.toml must exist"

    pkg_data = json.loads(pkg_file.read_text(encoding="utf-8"))
    npm_version = pkg_data.get("version")
    assert npm_version, "package.json must have a version field"

    pyproject_content = pyproject_file.read_text(encoding="utf-8")
    python_version = None

    if tomllib:
        py_data = tomllib.loads(pyproject_content)
        python_version = py_data.get("project", {}).get("version")
    else:
        for line in pyproject_content.splitlines():
            line = line.strip()
            if line.startswith("version ="):
                python_version = line.split("=")[1].strip().strip('"').strip("'")
                break

    assert python_version, "pyproject.toml must define project.version"
    assert npm_version == python_version, f"Version mismatch: npm={npm_version} vs python={python_version}"


def test_cli_version_flag_matches():
    """Verifies that 'python ctf_agent_cli.py --version' matches package.json."""
    pkg_data = json.loads((REPO_ROOT / "package.json").read_text(encoding="utf-8"))
    expected_version = pkg_data["version"]

    cmd = [sys.executable, str(REPO_ROOT / "ctf_agent_cli.py"), "--version"]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)

    assert res.returncode == 0
    assert f"ctf-agent v{expected_version}" in res.stdout.strip()


def test_node_launcher_version_flag_matches():
    """Verifies that 'node bin/ctf-agent.js --version' matches package.json."""
    if shutil.which("node") is None:
        pytest.skip("Node.js runtime not found in PATH")

    pkg_data = json.loads((REPO_ROOT / "package.json").read_text(encoding="utf-8"))
    expected_version = pkg_data["version"]

    cmd = ["node", str(REPO_ROOT / "bin" / "ctf-agent.js"), "--version"]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)

    assert res.returncode == 0
    assert f"ctf-agent v{expected_version}" in res.stdout.strip()


def test_manifest_contains_essential_assets():
    """Verifies that MANIFEST.in includes all critical directories and files for package distribution."""
    manifest_file = REPO_ROOT / "MANIFEST.in"
    assert manifest_file.is_file(), "MANIFEST.in must be present for packaging completeness"

    content = manifest_file.read_text(encoding="utf-8")
    required_entries = [
        "README.md",
        "AGENTS.md",
        "scripts",
        "agents",
        "skills",
        "rules",
        "references",
        "Dockerfile",
        "docker-compose.yml",
    ]

    for item in required_entries:
        assert item in content, f"MANIFEST.in missing requirement: {item}"
