import sys
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from multi_agent_adapter import MultiAgentAdapter


def test_deploy_claude_adapter(tmp_path: Path):
    adapter = MultiAgentAdapter(tmp_path)
    created = adapter.deploy_claude_adapter()

    claude_md = tmp_path / "CLAUDE.md"
    assert claude_md.is_file()
    content = claude_md.read_text(encoding="utf-8")
    assert "AGENTS.md" in content
    assert "triage ladder" in content


def test_deploy_cursor_adapter(tmp_path: Path):
    adapter = MultiAgentAdapter(tmp_path)
    created = adapter.deploy_cursor_adapter()

    cursorrules = tmp_path / ".cursorrules"
    mdc_file = tmp_path / ".cursor" / "rules" / "ctf-agent.mdc"

    assert cursorrules.is_file()
    assert mdc_file.is_file()
    assert "AGENTS.md" in cursorrules.read_text(encoding="utf-8")
    assert "AGENTS.md" in mdc_file.read_text(encoding="utf-8")


def test_deploy_all_adapters(tmp_path: Path):
    adapter = MultiAgentAdapter(tmp_path)
    results = adapter.deploy("all")

    assert "claude" in results
    assert "cursor" in results
    assert "windsurf" in results
    assert "copilot" in results
    assert "aider" in results
    assert "antigravity" in results

    assert (tmp_path / "CLAUDE.md").is_file()
    assert (tmp_path / ".cursorrules").is_file()
    assert (tmp_path / ".windsurfrules").is_file()
    assert (tmp_path / ".github" / "copilot-instructions.md").is_file()
    assert (tmp_path / ".aider.conf.yml").is_file()


def test_dry_run_does_not_modify_disk(tmp_path: Path):
    adapter = MultiAgentAdapter(tmp_path)
    results = adapter.deploy("all", dry_run=True)

    assert not (tmp_path / "CLAUDE.md").exists()
    assert not (tmp_path / ".cursorrules").exists()
    assert not (tmp_path / ".windsurfrules").exists()
