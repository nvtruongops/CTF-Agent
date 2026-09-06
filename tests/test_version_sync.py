#!/usr/bin/env python3
"""
CI Validation: Version Synchronization & Packaging Completeness
Ensures that package.json, pyproject.toml, uv.lock, CLI entrypoints,
README documentation, asset mirrors, and internal scripts are 100% aligned.
"""

import sys
import json
import re
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


def get_canonical_version() -> str:
    """Reads canonical package version from package.json."""
    pkg_file = REPO_ROOT / "package.json"
    assert pkg_file.is_file(), "package.json must exist"
    pkg_data = json.loads(pkg_file.read_text(encoding="utf-8"))
    version = pkg_data.get("version")
    assert version, "package.json must have a version field"
    return version


def test_package_json_and_pyproject_version_match():
    """Verifies that package.json and pyproject.toml define the exact same version string."""
    expected_version = get_canonical_version()
    pyproject_file = REPO_ROOT / "pyproject.toml"
    assert pyproject_file.is_file(), "pyproject.toml must exist"

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
    assert expected_version == python_version, (
        f"Version mismatch: package.json={expected_version} vs pyproject.toml={python_version}"
    )


def test_uv_lock_matches_package_version():
    """Verifies that uv.lock package entry for ctf-agent matches package.json."""
    expected_version = get_canonical_version()
    uv_lock_file = REPO_ROOT / "uv.lock"
    assert uv_lock_file.is_file(), "uv.lock must exist"

    content = uv_lock_file.read_text(encoding="utf-8")
    match = re.search(r'name = "ctf-agent"\s+version = "([^"]+)"', content)
    assert match, "uv.lock must declare package 'ctf-agent' with version"
    uv_version = match.group(1)
    assert uv_version == expected_version, (
        f"Version mismatch: package.json={expected_version} vs uv.lock={uv_version}"
    )


def test_cli_version_flag_matches():
    """Verifies that 'python ctf_agent_cli.py --version' matches package.json."""
    expected_version = get_canonical_version()
    cmd = [sys.executable, str(REPO_ROOT / "ctf_agent_cli.py"), "--version"]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)

    assert res.returncode == 0
    assert f"ctf-agent v{expected_version}" in res.stdout.strip()


def test_cli_version_variable_matches():
    """Verifies that __version__ defined in ctf_agent_cli.py matches package.json."""
    expected_version = get_canonical_version()
    cli_file = REPO_ROOT / "ctf_agent_cli.py"
    assert cli_file.is_file(), "ctf_agent_cli.py must exist"

    content = cli_file.read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', content)
    assert match, "ctf_agent_cli.py must define __version__"
    cli_version = match.group(1)
    assert cli_version == expected_version, (
        f"Version mismatch: package.json={expected_version} vs ctf_agent_cli.py={cli_version}"
    )


def test_node_launcher_version_flag_matches():
    """Verifies that 'node bin/ctf-agent.js --version' matches package.json."""
    if shutil.which("node") is None:
        pytest.skip("Node.js runtime not found in PATH")

    expected_version = get_canonical_version()
    cmd = ["node", str(REPO_ROOT / "bin" / "ctf-agent.js"), "--version"]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)

    assert res.returncode == 0
    assert f"ctf-agent v{expected_version}" in res.stdout.strip()


def test_readme_and_documentation_versions_valid():
    """Verifies that README.md and documentation contain valid, unexpired versions."""
    expected_version = get_canonical_version()
    major_minor = ".".join(expected_version.split(".")[:2])

    readme_file = REPO_ROOT / "README.md"
    assert readme_file.is_file(), "README.md must exist"
    readme_content = readme_file.read_text(encoding="utf-8")

    # 1. Check npm badge presence and target URL
    assert "[![npm version](https://img.shields.io/npm/v/ctf-agent.svg)](https://www.npmjs.com/package/ctf-agent)" in readme_content, (
        "README.md must contain official npm version badge pointing to ctf-agent"
    )

    # 2. If an explicit release badge exists, its version must match canonical version
    badge_match = re.search(r'badge/release-v?([0-9]+\.[0-9]+\.[0-9]+)-blue\.svg', readme_content)
    if badge_match:
        badge_version = badge_match.group(1)
        assert badge_version == expected_version, (
            f"Release badge in README.md ({badge_version}) does not match package.json ({expected_version})"
        )

    # 3. Ensure no stale versions like 1.2 or 1.0 are referenced in package installation instructions
    stale_patterns = [
        r'ctf-agent@1\.[0-2]\.[0-9]',
        r'ctf-agent v1\.[0-2]\b',
        r'release-v1\.[0-2]\.',
    ]
    for pattern in stale_patterns:
        match = re.search(pattern, readme_content)
        assert not match, (
            f"Found stale version reference '{match.group(0)}' in README.md (current is v{expected_version})"
        )


def test_mirrored_assets_integrity():
    """Verifies that all asset files in scripts/assets/ strictly match the root counterparts."""
    assets_dir = REPO_ROOT / "scripts" / "assets"
    assert assets_dir.is_dir(), "scripts/assets directory must exist"

    asset_files = ["AGENTS.md", "mcp_config.json", "skills.json", "README.md"]
    for fname in asset_files:
        asset_path = assets_dir / fname
        root_path = REPO_ROOT / fname
        assert asset_path.is_file(), f"Asset mirror missing: {asset_path}"
        assert root_path.is_file(), f"Root file missing: {root_path}"

        asset_bytes = asset_path.read_bytes()
        root_bytes = root_path.read_bytes()
        assert asset_bytes == root_bytes, (
            f"Asset synchronization mismatch between {fname} and scripts/assets/{fname}"
        )


def test_internal_scripts_version_alignment():
    """Verifies that internal scripts and utility headers are aligned with the framework version."""
    expected_version = get_canonical_version()
    major_minor = ".".join(expected_version.split(".")[:2])

    # 1. ScopeGuard version
    scope_guard_file = REPO_ROOT / "scripts" / "scope_guard.py"
    sg_content = scope_guard_file.read_text(encoding="utf-8")
    assert f'"version": "{major_minor}"' in sg_content or f'"version": "{expected_version}"' in sg_content, (
        f"scope_guard.py Security Context Object version must match {major_minor} or {expected_version}"
    )
    assert f"Scope Guard v{major_minor}" in sg_content, (
        f"scope_guard.py CLI description must match v{major_minor}"
    )

    # 2. Parallel Triage User-Agent
    triage_file = REPO_ROOT / "scripts" / "parallel_triage.py"
    triage_content = triage_file.read_text(encoding="utf-8")
    assert f"CTF-Agent-Triage/{major_minor}" in triage_content, (
        f"parallel_triage.py User-Agent version must match {major_minor}"
    )

    # 3. Preflight & Scaffolding Scripts Docstrings
    for script_name in ["ctf_init.py", "install_as_agent.py", "workspace_cleaner.py"]:
        sp = REPO_ROOT / "scripts" / script_name
        content = sp.read_text(encoding="utf-8")
        assert f"(v{major_minor})" in content, (
            f"{script_name} docstring version must indicate (v{major_minor})"
        )


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
