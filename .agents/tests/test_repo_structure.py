import json
import re
from pathlib import Path

EXPECTED_AGENTS = {"ctf-controller.md", "ctf-speedrun.md", "ctf-analyzer.md"}
EXPECTED_REFERENCES = {
    "ctf-triage-ladder.md",
    "exploit-databases.md",
    "multi-agent-orchestration-and-policy-routing.md",
    "security-events-and-intelligence.md",
    "version-matrix.md",
    "ctf-mcp-tool-map.md",
}
EXPECTED_RULES = {
    "ctf-execution-rules.md",
    "ctf-safety-framing-rules.md",
    "flag-validation-rules.md",
}
EXPECTED_CTF_CATEGORIES = (
    "web",
    "pwn",
    "crypto",
    "reverse",
    "forensics",
    "osint",
    "malware",
    "misc",
    "ai-ml",
)
EXPECTED_CTF_SKILL_ROUTES = {
    "Web": "ctf-web",
    "Pwn": "ctf-pwn",
    "Crypto": "ctf-crypto",
    "Reverse": "ctf-reverse",
    "Forensics": "ctf-forensics",
    "OSINT": "ctf-osint",
    "Malware": "ctf-malware",
    "Misc": "ctf-misc",
    "AI/ML": "ctf-ai-ml",
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


def markdown_table_rows(content: str, header: str) -> list[list[str]]:
    lines = content.splitlines()
    header_index = next((i for i, line in enumerate(lines) if line.strip() == header), None)
    assert header_index is not None, f"table header is missing: {header}"

    rows = []
    for line in lines[header_index + 1 :]:
        if not line.lstrip().startswith("|"):
            break
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if all(set(cell) <= {"-", ":"} for cell in cells):
            continue
        rows.append(cells)
    return rows


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
    assert len(skill_files) == 12
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


def test_agents_content_layer_has_no_runtime_or_packaging_artifacts(repo_root: Path):
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


def test_root_mcp_package_is_present_without_project_opencode_config(repo_root: Path):
    project_root = repo_root.parent
    package = json.loads((project_root / "package.json").read_text(encoding="utf-8"))
    assert package["name"] in ("ctf-agent", "ctf-agent-mcp", "@nvtruongops/ctf-agent-mcp")
    assert package["engines"]["node"] == ">=24.11"
    assert (project_root / "ctf_mcp" / "server.js").is_file()
    assert (project_root / "ctf_mcp" / "tool-manifest.json").is_file()

    assert not (project_root / "opencode.jsonc").exists()


def test_tests_are_not_ignored(repo_root: Path):
    content = (repo_root / ".gitignore").read_text(encoding="utf-8")
    assert "tests/" not in content


def test_ctf_category_enums_match_specialist_categories(repo_root: Path):
    enum_files = [
        repo_root / "rules" / "ctf-safety-framing-rules.md",
        repo_root / "references" / "multi-agent-orchestration-and-policy-routing.md",
        repo_root / "skills" / "ctf-solve-report" / "SKILL.md",
        repo_root / "references" / "exploit-databases.md",
    ]

    for path in enum_files:
        category_line = next(
            (line.strip() for line in path.read_text(encoding="utf-8").splitlines()
             if line.strip().startswith("category:")),
            None,
        )
        assert category_line is not None, f"category enum is missing: {path}"
        values = category_line.split(":", 1)[1].strip().strip('"<> ')
        assert tuple(value.strip() for value in values.split("|")) == EXPECTED_CTF_CATEGORIES, path


def test_solver_router_covers_all_specialist_categories(repo_root: Path):
    router = (repo_root / "skills" / "ctf-solve-challenge" / "SKILL.md").read_text(encoding="utf-8")
    category_rows = markdown_table_rows(router, "| Category | Skill | When to Use |")
    routes = {row[0]: row[1].strip("`") for row in category_rows}

    assert routes == EXPECTED_CTF_SKILL_ROUTES
    for skill in routes.values():
        assert (repo_root / "skills" / skill / "SKILL.md").is_file(), skill
    assert any(
        "LLM prompt injection" in line
        and "LLM jailbreak" in line
        and "before the generic web" in line
        for line in router.splitlines()
    )


def test_solver_router_documents_parent_routes_and_ppc_limit(repo_root: Path):
    router = (repo_root / "skills" / "ctf-solve-challenge" / "SKILL.md").read_text(encoding="utf-8")
    rows = markdown_table_rows(router, "| Topic | Default route | Conditional route / limit |")
    routes = {}
    for topic, default_route, conditional_route in rows:
        default_skills = re.findall(r"`(ctf-[^`]+)`", default_route)
        assert len(default_skills) == 1, topic
        routes[topic] = (default_skills[0], set(re.findall(r"`(ctf-[^`]+)`", conditional_route)))

    assert routes == {
        "Steganography": ("ctf-forensics", {"ctf-osint"}),
        "Hardware / firmware": ("ctf-reverse", {"ctf-forensics"}),
        "Game hacking": ("ctf-reverse", {"ctf-pwn"}),
        "Web3 / smart contracts": ("ctf-web", {"ctf-crypto"}),
        "Mobile reversing": ("ctf-reverse", set()),
        "PPC / programming puzzles": ("ctf-misc", set()),
    }
    ppc_default = next(row[1] for row in rows if row[0] == "PPC / programming puzzles")
    ppc_limit = next(row[2] for row in rows if row[0] == "PPC / programming puzzles")
    assert "no dedicated ppc skill exists" in ppc_limit.lower()
    assert "best-effort fallback" in ppc_default.lower()


def test_misc_documents_a_bounded_ppc_fallback_workflow(repo_root: Path):
    misc = (repo_root / "skills" / "ctf-misc" / "SKILL.md").read_text(encoding="utf-8").lower()
    assert "programming puzzles (ppc)" in misc
    for requirement in ("input/output", "constraints", "complexity", "sample", "interactive"):
        assert requirement in misc
    assert "ctf-crypto" in misc
    assert "ctf-web" in misc
    assert "pyjail" in misc


def test_apk_routes_to_static_reverse_guidance_not_an_mcp_package_tool(repo_root: Path):
    router = (repo_root / "skills" / "ctf-solve-challenge" / "SKILL.md").read_text(encoding="utf-8").lower()
    reverse = (repo_root / "skills" / "ctf-reverse" / "SKILL.md").read_text(encoding="utf-8").lower()
    tool_map = (repo_root / "references" / "ctf-mcp-tool-map.md").read_text(encoding="utf-8").lower()

    apk_route = next(line for line in router.splitlines() if ".apk" in line)
    reverse_row = next(line for line in tool_map.splitlines() if "ctf_reverse_inspect" in line)
    assert "reverse" in apk_route
    assert "## android apk/dex" in reverse
    assert "preserve the original" in reverse
    assert "manifest" in reverse and "dex" in reverse and "native librar" in reverse
    assert "do not provide broad decompilation or apk/package analysis" in reverse
    assert "linux/elf" in reverse_row
    assert "apk" not in reverse_row and "package analysis" not in reverse_row


def test_web3_guidance_defaults_to_local_analysis_and_scopes_remote_activity(repo_root: Path):
    web3 = (repo_root / "skills" / "ctf-web" / "web3.md").read_text(encoding="utf-8").lower()
    assert "local/static analysis is the default" in web3
    assert "abi" in web3 and "calldata" in web3 and "bytecode" in web3
    assert "authorized challenge instance" in web3
    for unsafe_default in ("sepolia", "publicnode", "--private-key", "private_key", "--broadcast"):
        assert unsafe_default not in web3


def test_competition_mode_triage_requires_rules_and_does_not_expand_scope(repo_root: Path):
    router = (repo_root / "skills" / "ctf-solve-challenge" / "SKILL.md").read_text(encoding="utf-8").lower()
    assert "jeopardy" in router and "attack-defense" in router
    assert "king of the hill" in router and "livectf" in router
    assert "read the official event rules" in router
    assert "organizer-defined scope" in router
    assert "mode classification is context only" in router
    assert "does not authorize scanning, attacking, persistence, or automation" in router
    assert "does not skip hint-first analysis" in router
    assert "version matrix" in router


def test_ai_and_malware_routes_stay_guidance_only_not_mcp_tools(repo_root: Path):
    router = (repo_root / "skills" / "ctf-solve-challenge" / "SKILL.md").read_text(encoding="utf-8").lower()
    tool_map = (repo_root / "references" / "ctf-mcp-tool-map.md").read_text(encoding="utf-8").lower()
    malware = (repo_root / "skills" / "ctf-malware" / "SKILL.md").read_text(encoding="utf-8").lower()
    ai_ml = (repo_root / "skills" / "ctf-ai-ml" / "SKILL.md").read_text(encoding="utf-8").lower()

    assert any('"llm prompt injection"' in line and "-> ai-ml" in line for line in router.splitlines())
    assert any('"obfuscated"' in line and "-> malware" in line for line in router.splitlines())
    assert "ctf_ai_ml" not in tool_map and "ctf_malware" not in tool_map
    assert "dynamic analysis (sandboxed!)" not in malware
    assert "wsl and the non-sudo `ctfagent` user are not a security sandbox" in malware
    assert "sandboxed environments" not in ai_ml.splitlines()[2]


def test_event_examples_and_safety_rules_do_not_overstate_taxonomy_or_isolation(repo_root: Path):
    events = (repo_root / "references" / "security-events-and-intelligence.md").read_text(encoding="utf-8").lower()
    safety = (repo_root / "rules" / "ctf-safety-framing-rules.md").read_text(encoding="utf-8").lower()
    execution = (repo_root / "rules" / "ctf-execution-rules.md").read_text(encoding="utf-8").lower()

    assert "not a representative sample, prevalence estimate, or universal category taxonomy" in events
    assert "def con 28 safe mode ctf" in events and "do not generalize either description" in events
    assert "strictly sandboxed targets" not in safety
    assert "wsl, a linux user, localhost, `/tmp/`, and a declared scope do not by themselves provide security isolation" in safety
    assert "preserve organizer-provided binaries" in execution
