import os
import re
from pathlib import Path

EXPECTED_AGENTS = {"ctf-controller.md", "ctf-speedrun.md", "ctf-analyzer.md"}

EXPECTED_SKILLS = {
    "solve-challenge", "ctf-web", "ctf-pwn", "ctf-crypto", "ctf-reverse",
    "ctf-forensics", "ctf-ai-ml", "ctf-osint", "ctf-misc", "ctf-malware", "ctf-writeup"
}

EXPECTED_REFERENCES = {
    "ctf-triage-ladder.md", "exploit-databases.md", "llm-safety-and-policy-compliance.md",
    "multi-agent-orchestration-and-policy-routing.md", "security-events-and-intelligence.md",
    "version-matrix.md"
}

def parse_frontmatter(file_path: Path) -> dict:
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    match = re.match(r"^---\s*\n(.*?)\n---\s*\n", content, re.DOTALL)
    if not match:
        return {}
    frontmatter = {}
    for line in match.group(1).splitlines():
        if ":" in line:
            key, val = line.split(":", 1)
            frontmatter[key.strip()] = val.strip().strip('"\'')
    return frontmatter

def test_agents_exist_and_have_valid_frontmatter(repo_root: Path):
    agents_dir = repo_root / "agents"
    assert agents_dir.is_dir()
    found_agents = {f.name for f in agents_dir.iterdir() if f.is_file() and f.suffix == ".md"}
    assert EXPECTED_AGENTS.issubset(found_agents), f"Missing agents: {EXPECTED_AGENTS - found_agents}"
    
    for agent_name in EXPECTED_AGENTS:
        agent_path = agents_dir / agent_name
        fm = parse_frontmatter(agent_path)
        assert "name" in fm, f"{agent_name} missing 'name' in frontmatter"
        assert "allowed-tools" in fm, f"{agent_name} missing 'allowed-tools' in frontmatter"
        assert "description" in fm, f"{agent_name} missing 'description' in frontmatter"

def test_skills_exist_and_have_valid_frontmatter(repo_root: Path):
    skills_dir = repo_root / "skills"
    assert skills_dir.is_dir()
    found_skills = {d.name for d in skills_dir.iterdir() if d.is_dir()}
    assert EXPECTED_SKILLS.issubset(found_skills), f"Missing skills: {EXPECTED_SKILLS - found_skills}"
    
    for skill_name in EXPECTED_SKILLS:
        skill_file = skills_dir / skill_name / "SKILL.md"
        assert skill_file.is_file(), f"Missing SKILL.md for skill {skill_name}"
        fm = parse_frontmatter(skill_file)
        assert "name" in fm, f"{skill_file} missing 'name' in frontmatter"
        assert "description" in fm, f"{skill_file} missing 'description' in frontmatter"

def test_references_exist(repo_root: Path):
    ref_dir = repo_root / "references"
    assert ref_dir.is_dir()
    found_refs = {f.name for f in ref_dir.iterdir() if f.is_file()}
    assert EXPECTED_REFERENCES.issubset(found_refs), f"Missing references: {EXPECTED_REFERENCES - found_refs}"

def test_safety_rules_contain_sco_and_envelope(repo_root: Path):
    rule_file = repo_root / "rules" / "ctf-safety-framing-rules.md"
    assert rule_file.is_file()
    content = rule_file.read_text(encoding="utf-8")
    assert "Security Context Object" in content
    assert "task_envelope" in content
    assert "Type A" in content
    assert "Type B" in content
    assert "Type C" in content

def test_gitignore_ignores_tests_directory(repo_root: Path):
    gitignore = repo_root / ".gitignore"
    assert gitignore.is_file()
    content = gitignore.read_text(encoding="utf-8")
    assert "tests/" in content, ".gitignore must contain 'tests/'"


def test_scripts_ignore_and_exclusion_rules(repo_root: Path):
    """Verifies that non-primary scripts and internal developer tools are ignored across git, npm, and workspace deployment."""
    # 1. Root .gitignore
    gitignore = repo_root / ".gitignore"
    assert gitignore.is_file()
    gi_content = gitignore.read_text(encoding="utf-8")
    assert "scripts/local_ci.py" in gi_content, ".gitignore must ignore scripts/local_ci.py"
    assert "scripts/__pycache__/" in gi_content or "__pycache__/" in gi_content
    assert "scripts/*.log" in gi_content or "*.log" in gi_content

    # 2. .npmignore
    npmignore = repo_root / ".npmignore"
    assert npmignore.is_file()
    ni_content = npmignore.read_text(encoding="utf-8")
    assert "scripts/local_ci.py" in ni_content, ".npmignore must ignore scripts/local_ci.py"
    assert "scripts/assets/" in ni_content, ".npmignore must ignore scripts/assets/"

    # 3. scripts/.gitignore
    scripts_gi = repo_root / "scripts" / ".gitignore"
    assert scripts_gi.is_file(), "scripts/.gitignore must exist"
    sgi_content = scripts_gi.read_text(encoding="utf-8")
    assert "local_ci.py" in sgi_content, "scripts/.gitignore must ignore local_ci.py"
    assert "assets/" in sgi_content, "scripts/.gitignore must ignore assets/"

    # 4. install_as_agent.py deployment exclusions
    installer = repo_root / "scripts" / "install_as_agent.py"
    assert installer.is_file()
    inst_content = installer.read_text(encoding="utf-8")
    assert "local_ci.py" in inst_content, "install_as_agent.py must exclude local_ci.py from deployment"
    assert "assets" in inst_content, "install_as_agent.py must exclude assets from scripts/ deployment"
