#!/usr/bin/env python3
"""
Unit and Integration Tests for CTF-Agent Workspace & Skill Update Engine
Validates skill diff classification, lockfile hashing, asset preservation, and CLI subcommands.
"""

import os
import sys
import shutil
import json
import tempfile
import subprocess
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from ctf_update import WorkspaceUpdater, SkillDiff
except ImportError:
    from scripts.ctf_update import WorkspaceUpdater, SkillDiff


@pytest.fixture
def mock_workspace():
    """Creates an isolated temporary CTF workspace simulating an existing deployed state."""
    tmp_dir = tempfile.mkdtemp(prefix="ctf_update_test_")
    ws = Path(tmp_dir)

    dot_agents = ws / ".agents"
    dot_agents.mkdir(parents=True)
    skills_dir = dot_agents / "skills"
    skills_dir.mkdir(parents=True)

    # 1. Simulate an up-to-date skill (copy directly from repo)
    upstream_skills = list((REPO_ROOT / "skills").iterdir())
    if upstream_skills:
        sample_skill = upstream_skills[0]
        dest_up = skills_dir / sample_skill.name
        shutil.copytree(sample_skill, dest_up)

    # 2. Simulate a custom user skill
    custom_skill = skills_dir / "my-custom-ctf-skill"
    custom_skill.mkdir()
    (custom_skill / "SKILL.md").write_text("# My Custom Skill\nDescription: Custom PoC\n", encoding="utf-8")

    # 3. Simulate user challenge assets
    solve_py = ws / "solve.py"
    solve_py.write_text("print('user original solve code')", encoding="utf-8")

    resources_dir = ws / "resources"
    resources_dir.mkdir()
    (resources_dir / "chall.bin").write_bytes(b"\x7fELFfakebinary")

    notes_dir = ws / "notes"
    notes_dir.mkdir()
    (notes_dir / "notes.txt").write_text("CTF user notes", encoding="utf-8")

    # 4. Generate initial skills-lock.json
    lock_data = {"version": 1, "skills": {}}
    if upstream_skills:
        sample_hash = WorkspaceUpdater.compute_file_hash(skills_dir / upstream_skills[0].name / "SKILL.md")
        lock_data["skills"][upstream_skills[0].name] = {
            "source": "CTF-Agent (local)",
            "sourceType": "local",
            "skillPath": f".agents/skills/{upstream_skills[0].name}/SKILL.md",
            "computedHash": sample_hash,
        }
    (ws / "skills-lock.json").write_text(json.dumps(lock_data, indent=2), encoding="utf-8")

    yield ws

    # Cleanup
    shutil.rmtree(tmp_dir, ignore_errors=True)


def test_inspect_skills_detects_new_and_custom(mock_workspace):
    """Verifies that missing upstream skills are marked NEW and custom workspace skills are marked CUSTOM."""
    diffs = WorkspaceUpdater.inspect_skills(mock_workspace)
    status_map = {d.name: d.status for d in diffs}

    assert "my-custom-ctf-skill" in status_map
    assert status_map["my-custom-ctf-skill"] == SkillDiff.STATUS_CUSTOM

    # There should be skills marked NEW since mock_workspace only has 1 skill installed
    new_skills = [d for d in diffs if d.status == SkillDiff.STATUS_NEW]
    assert len(new_skills) > 0


def test_dry_run_does_not_modify_files(mock_workspace):
    """Verifies that running update in dry-run mode modifies zero files."""
    skills_before = set(p.name for p in (mock_workspace / ".agents" / "skills").iterdir())
    result = WorkspaceUpdater.update_workspace(mock_workspace, dry_run=True)

    assert result["dry_run"] is True
    assert len(result["actions_taken"]) == 0
    skills_after = set(p.name for p in (mock_workspace / ".agents" / "skills").iterdir())
    assert skills_before == skills_after


def test_live_update_installs_new_skills_and_regenerates_lock(mock_workspace):
    """Verifies that live update installs new skills, preserves custom skills, and updates lockfile."""
    result = WorkspaceUpdater.update_workspace(mock_workspace, dry_run=False)

    assert result["dry_run"] is False
    assert len(result["actions_taken"]) > 0

    skills_dir = mock_workspace / ".agents" / "skills"
    # Custom skill must remain intact
    assert (skills_dir / "my-custom-ctf-skill" / "SKILL.md").exists()
    assert "user original solve code" in (mock_workspace / "solve.py").read_text(encoding="utf-8")

    # Lockfile must be regenerated and contain all installed skills
    lock_file = mock_workspace / "skills-lock.json"
    assert lock_file.is_file()
    lock_data = json.loads(lock_file.read_text(encoding="utf-8"))
    assert "my-custom-ctf-skill" in lock_data["skills"]
    assert len(lock_data["skills"]) >= len(list((REPO_ROOT / "skills").iterdir()))


def test_user_assets_strictly_preserved(mock_workspace):
    """Verifies that solve.py, resources/, notes/ are never overwritten or deleted."""
    solve_content = "print('important solve script')"
    (mock_workspace / "solve.py").write_text(solve_content, encoding="utf-8")

    WorkspaceUpdater.update_workspace(mock_workspace, dry_run=False)

    assert (mock_workspace / "solve.py").read_text(encoding="utf-8") == solve_content
    assert (mock_workspace / "resources" / "chall.bin").read_bytes() == b"\x7fELFfakebinary"
    assert (mock_workspace / "notes" / "notes.txt").read_text(encoding="utf-8") == "CTF user notes"


def test_missing_agents_dir_raises_error():
    """Verifies that targeting a directory without .agents/ raises FileNotFoundError."""
    tmp_empty = tempfile.mkdtemp(prefix="empty_ws_")
    try:
        with pytest.raises(FileNotFoundError):
            WorkspaceUpdater.update_workspace(Path(tmp_empty))
    finally:
        shutil.rmtree(tmp_empty, ignore_errors=True)


def test_cli_update_dry_run(mock_workspace):
    """Verifies that 'python ctf_agent_cli.py update --dry-run' executes successfully."""
    cmd = [
        sys.executable,
        str(REPO_ROOT / "ctf_agent_cli.py"),
        "update",
        str(mock_workspace),
        "--dry-run",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert res.returncode == 0
    assert "CTF-AGENT WORKSPACE & SKILL UPDATE REPORT" in res.stdout
    assert "DRY RUN" in res.stdout


def test_node_launcher_update_dry_run(mock_workspace):
    """Verifies that 'node bin/ctf-agent.js update --dry-run' executes successfully."""
    if shutil.which("node") is None:
        pytest.skip("Node.js runtime not found in PATH")

    cmd = [
        "node",
        str(REPO_ROOT / "bin" / "ctf-agent.js"),
        "update",
        str(mock_workspace),
        "--dry-run",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert res.returncode == 0
    assert "CTF-AGENT WORKSPACE & SKILL UPDATE REPORT" in res.stdout


def test_non_skill_directories_custom_file_preservation_and_backup(mock_workspace):
    """Verifies that custom files in rules/, agents/, references/, scripts/ are never wiped during update,
    and modified core files receive .bak backups."""
    agents_dir = mock_workspace / ".agents"
    (agents_dir / "agents").mkdir(parents=True, exist_ok=True)
    (agents_dir / "scripts").mkdir(parents=True, exist_ok=True)
    (agents_dir / "rules").mkdir(parents=True, exist_ok=True)
    (agents_dir / "references").mkdir(parents=True, exist_ok=True)

    # 1. Place custom files that do not exist upstream
    custom_agent = agents_dir / "agents" / "my-custom-subagent.md"
    custom_agent.write_text("# Custom CTF Agent\nCustom prompt instructions", encoding="utf-8")

    custom_script = agents_dir / "scripts" / "my_custom_tool.py"
    custom_script.write_text("print('user custom diagnostic script')", encoding="utf-8")

    custom_rule = agents_dir / "rules" / "my-custom-rule.md"
    custom_rule.write_text("# Custom Rule\nStrict local rule", encoding="utf-8")

    custom_ref = agents_dir / "references" / "my-custom-notes.md"
    custom_ref.write_text("# Custom Reference Notes", encoding="utf-8")

    # 2. Modify an existing upstream file in .agents/rules/
    upstream_rule = REPO_ROOT / "rules" / "ctf-safety-framing-rules.md"
    if upstream_rule.exists():
        local_rule = agents_dir / "rules" / "ctf-safety-framing-rules.md"
        local_rule.write_text(upstream_rule.read_text(encoding="utf-8") + "\n# USER CUSTOM MODIFICATION", encoding="utf-8")

    # 3. Perform live workspace update
    result = WorkspaceUpdater.update_workspace(mock_workspace, dry_run=False)

    # 4. Verify custom files remain completely intact
    assert custom_agent.is_file()
    assert "Custom prompt instructions" in custom_agent.read_text(encoding="utf-8")

    assert custom_script.is_file()
    assert "user custom diagnostic script" in custom_script.read_text(encoding="utf-8")

    assert custom_rule.is_file()
    assert "Strict local rule" in custom_rule.read_text(encoding="utf-8")

    assert custom_ref.is_file()
    assert "# Custom Reference Notes" in custom_ref.read_text(encoding="utf-8")

    # 5. Verify modified rule was updated and .bak backup was created
    if upstream_rule.exists():
        local_rule = agents_dir / "rules" / "ctf-safety-framing-rules.md"
        backup_rule = agents_dir / "rules" / "ctf-safety-framing-rules.md.bak"
        assert backup_rule.is_file()
        assert "# USER CUSTOM MODIFICATION" in backup_rule.read_text(encoding="utf-8")
        assert local_rule.read_text(encoding="utf-8") == upstream_rule.read_text(encoding="utf-8")


def test_update_excludes_developer_scripts(mock_workspace):
    """Verifies that updating workspace synchronizes primary scripts but strictly excludes local_ci.py and assets/."""
    result = WorkspaceUpdater.update_workspace(mock_workspace, dry_run=False)
    scripts_dir = mock_workspace / ".agents" / "scripts"

    assert scripts_dir.is_dir()
    assert (scripts_dir / "ctf_init.py").is_file(), "ctf_init.py must be synchronized"
    assert (scripts_dir / "parallel_triage.py").is_file(), "parallel_triage.py must be synchronized"
    assert not (scripts_dir / "local_ci.py").exists(), "local_ci.py must NEVER be copied into user workspace during update"
    assert not (scripts_dir / "assets").exists(), "assets/ mirror must NEVER be copied into user workspace during update"

