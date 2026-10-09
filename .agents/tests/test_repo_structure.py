import json
from pathlib import Path

EXPECTED_AGENTS = {"ctf-controller.md", "ctf-speedrun.md", "ctf-analyzer.md"}
EXPECTED_REFERENCES = {
    "ctf-triage-ladder.md",
    "exploit-databases.md",
    "multi-agent-orchestration-and-policy-routing.md",
    "security-events-and-intelligence.md",
    "version-matrix.md",
}
EXPECTED_RULES = {
    "ctf-execution-rules.md",
    "ctf-safety-framing-rules.md",
    "flag-validation-rules.md",
}


def parse_frontmatter(path: Path) -> dict[str, str]:
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    assert lines and lines[0] == "---", f"{path} has no frontmatter"
    end = lines.index("---", 1)
    metadata = {}
    for line in lines[1:end]:
        if ":" in line:
            key, value = line.split(":", 1)
            metadata[key.strip()] = value.strip().strip(chr(34) + chr(39))
    return metadata


def test_agent_personas_have_frontmatter(repo_root: Path):
    agents_dir = repo_root / "agents"
    found = {path.name for path in agents_dir.glob("*.md")}
    assert found == EXPECTED_AGENTS
    for name in EXPECTED_AGENTS:
        metadata = parse_frontmatter(agents_dir / name)
        assert {"name", "description"} <= metadata.keys()
        assert not ({"allowed-tools", "mainAgent", "subagent", "commandExecutionPolicy"} & metadata.keys())


def test_skill_entrypoints_have_frontmatter(repo_root: Path):
    skill_files = sorted((repo_root / "skills").glob("*/SKILL.md"))
    assert len(skill_files) == 11
    for skill_file in skill_files:
        metadata = parse_frontmatter(skill_file)
        assert metadata.get("name") == skill_file.parent.name
        assert metadata.get("description")
        assert len(metadata["name"]) <= 64
        assert len(metadata["description"]) <= 1024
        assert not ({"allowed-tools", "compatibility", "metadata"} & metadata.keys())


def test_claude_entries_point_to_canonical_skills(repo_root: Path):
    canonical_dir = repo_root / "skills"
    claude_dir = repo_root / ".claude" / "skills"
    canonical_names = {path.name for path in canonical_dir.iterdir() if path.is_dir()}
    adapter_names = {path.name for path in claude_dir.iterdir() if path.is_dir()}
    assert adapter_names == canonical_names

    for name in canonical_names:
        canonical = parse_frontmatter(canonical_dir / name / "SKILL.md")
        adapter_path = claude_dir / name / "SKILL.md"
        adapter = parse_frontmatter(adapter_path)
        assert adapter.get("name") == canonical.get("name")
        assert adapter.get("description") == canonical.get("description")
        link_target = adapter_path.parent / "../../../skills" / name / "SKILL.md"
        assert link_target.resolve() == (canonical_dir / name / "SKILL.md").resolve()
        assert link_target.exists()


def test_host_setup_is_documented(repo_root: Path):
    readme = (repo_root / "README.md").read_text(encoding="utf-8")
    assert "Codex" in readme and ".agents/skills/" in readme
    assert "Antigravity" in readme and "Claude Code" in readme
    assert "claude --add-dir .agents" in readme


def test_shared_docs_are_referenced(repo_root: Path):
    docs = [repo_root / "README.md", repo_root / "AGENTS.md"]
    docs.extend((repo_root / "skills").rglob("*.md"))
    docs.extend((repo_root / "agents").rglob("*.md"))
    combined = "".join(path.read_text(encoding="utf-8") for path in docs)
    assert {path.name for path in (repo_root / "references").glob("*") if path.is_file()} == EXPECTED_REFERENCES
    assert {path.name for path in (repo_root / "rules").glob("*") if path.is_file()} == EXPECTED_RULES
    for name in EXPECTED_REFERENCES | EXPECTED_RULES:
        assert name in combined, f"{name} is kept but not referenced"


def test_runtime_and_packaging_layers_are_absent(repo_root: Path):
    removed_paths = [
        "scripts",
        ".cursor",
        ".aider.conf.yml",
        ".cursorrules",
        ".windsurfrules",
        "CLAUDE.md",
        "bin",
        "Dockerfile",
        "docker-compose.yml",
        "ctf_agent_cli.py",
        "mcp_config.json",
        "skills.json",
        ".mcp.json",
        "package.json",
        "pyproject.toml",
        "uv.lock",
        "MANIFEST.in",
        ".npmignore",
        ".github/workflows/publish-packages.yml",
        "references/dev-harness-guidelines.md",
        "references/llm-safety-and-policy-compliance.md",
    ]
    for relative in removed_paths:
        assert not (repo_root / relative).exists(), f"Runtime or packaging artifact remains: {relative}"


def test_tests_are_not_ignored(repo_root: Path):
    content = (repo_root / ".gitignore").read_text(encoding="utf-8")
    assert "tests/" not in content
