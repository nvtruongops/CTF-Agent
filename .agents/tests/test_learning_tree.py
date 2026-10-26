import re
from pathlib import Path


SKILL_NAME = "ctf-lab-retrospective"
SKILL_TREE_REFERENCE = re.compile(r"\bskill[- ]tree\b|\bapproved (?:topic )?patterns\b|patterns/<topic>")


def read_skill(path: Path) -> tuple[dict[str, str], str]:
    content = path.read_text(encoding="utf-8")
    lines = content.splitlines()
    assert lines and lines[0] == "---", f"{path} has no skill frontmatter"
    end = lines.index("---", 1)
    metadata = {}
    for line in lines[1:end]:
        if ":" in line:
            key, value = line.split(":", 1)
            metadata[key.strip()] = value.strip().strip(chr(34) + chr(39))
    return metadata, content


def test_retrospective_skill_has_discoverable_frontmatter_and_resolvable_links(repo_root: Path):
    skill_path = repo_root / "skills" / SKILL_NAME / "SKILL.md"
    assert skill_path.is_file(), "canonical retrospective skill is missing"
    metadata, content = read_skill(skill_path)

    assert metadata.get("name") == SKILL_NAME
    assert metadata.get("description", "").startswith("Use when")
    assert len(metadata["description"]) <= 1024
    assert "verified flag" in metadata["description"].lower() or "reported result" in metadata["description"].lower()

    without_code = re.sub(r"```[\s\S]*?```", "", content)
    for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", without_code):
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        target_path = target.strip().split("#", 1)[0]
        if target_path:
            assert (skill_path.parent / target_path).resolve().exists(), f"broken skill link: {target}"


def test_claude_entry_points_to_canonical_retrospective_skill(repo_root: Path):
    canonical_path = repo_root / "skills" / SKILL_NAME / "SKILL.md"
    bridge_path = repo_root / ".claude" / "skills" / SKILL_NAME / "SKILL.md"
    assert canonical_path.is_file(), "canonical retrospective skill is missing"
    assert bridge_path.is_file(), "Claude retrospective bridge is missing"
    canonical, _ = read_skill(canonical_path)
    bridge, bridge_text = read_skill(bridge_path)

    assert bridge.get("name") == canonical.get("name")
    assert bridge.get("description") == canonical.get("description")
    target = bridge_path.parent / "../../../skills" / SKILL_NAME / "SKILL.md"
    assert target.resolve() == canonical_path.resolve()
    assert target.is_file()
    assert "read and follow the canonical skill" in bridge_text.lower()


def test_solve_challenge_runs_retrospective_after_report_only_for_deep_labs(repo_root: Path):
    content = (repo_root / "skills" / "solve-challenge" / "SKILL.md").read_text(encoding="utf-8")
    completion = content.split("### Step 6: Post-Exploitation & Completion", 1)[1]
    blitz, deep = completion.split("#### Branch B: Deep Analysis Mode", 1)

    assert "ctf-lab-retrospective" in deep
    assert re.search(r"verified.{0,80}(?:flag|result).{0,120}report", deep, re.IGNORECASE | re.DOTALL)
    assert deep.index("report") < deep.index("ctf-lab-retrospective")
    assert "retrospective" in blitz.lower()
    assert re.search(r"(?:skip|do not invoke|does not run).{0,80}retrospective", blitz, re.IGNORECASE | re.DOTALL)
    assert re.search(r"unless the user asks", blitz, re.IGNORECASE)


def test_challenge_triage_uses_category_skills_without_pattern_tree_lookup(repo_root: Path):
    content = (repo_root / "skills" / "solve-challenge" / "SKILL.md").read_text(encoding="utf-8")
    lower = content.lower()

    assert SKILL_TREE_REFERENCE.search("consult approved patterns in the skill tree")
    assert not SKILL_TREE_REFERENCE.search(lower)
    assert "determine the primary category, then invoke the matching skill." in lower
    assert "load the full `ctf-<category>` skill instructions" in lower
    assert "ctf-web" in lower and "ctf-pwn" in lower


def test_retrospective_reviews_only_the_relevant_topic_skill_and_references(repo_root: Path):
    skill_path = repo_root / "skills" / SKILL_NAME / "SKILL.md"
    assert skill_path.is_file(), "canonical retrospective skill is missing"
    _, content = read_skill(skill_path)
    lower = content.lower()

    assert "current visible session" in lower
    assert "category skill used during the solve" in lower
    assert "directly relevant" in lower
    assert re.search(r"only.{0,100}(?:relevant|topic).{0,100}(?:skill|reference)", lower, re.DOTALL)
    assert re.search(r"(?:do not|never).{0,80}(?:scan|read).{0,60}(?:all|every) skills?", lower, re.DOTALL)


def test_retrospective_has_three_reusable_outcomes_and_waits_for_diff_approval(repo_root: Path):
    _, content = read_skill(repo_root / "skills" / SKILL_NAME / "SKILL.md")
    lower = content.lower()

    assert "no update" in lower
    assert "minimal patch" in lower
    assert "generalizable case" in lower
    assert "applicab" in lower and "countercondition" in lower
    assert "exact diff" in lower
    assert re.search(r"wait.{0,100}explicit.{0,60}approv", lower, re.DOTALL)
    assert re.search(r"only.{0,100}after.{0,80}approv", lower, re.DOTALL)
    assert "general request to preserve or promote" in lower
    assert "not approval of an exact canonical change" in lower


def test_retrospective_does_not_persist_lab_proposals_or_patterns(repo_root: Path):
    _, content = read_skill(repo_root / "skills" / SKILL_NAME / "SKILL.md")
    lower = content.lower()

    assert "learn --propose" not in lower
    assert "learn --promote" not in lower
    assert "relatedlabs" not in lower
    assert "schemaversion" not in lower
    assert SKILL_TREE_REFERENCE.search("consult approved patterns in the skill tree")
    assert not SKILL_TREE_REFERENCE.search(lower)


def test_retrospective_does_not_treat_sunk_cost_or_authority_as_reusable_evidence(repo_root: Path):
    _, content = read_skill(repo_root / "skills" / SKILL_NAME / "SKILL.md")
    lower = content.lower()

    assert "time already spent, urgency, or authority" in lower
    assert "does not prove that a lesson is reusable" in lower


def test_retrospective_uses_only_current_session_and_treats_challenge_content_as_untrusted(repo_root: Path):
    skill_path = repo_root / "skills" / SKILL_NAME / "SKILL.md"
    assert skill_path.is_file(), "canonical retrospective skill is missing"
    _, content = read_skill(skill_path)
    lower = content.lower()

    assert "current visible session" in lower
    assert "challenge" in lower and "untrusted" in lower
    assert re.search(r"(?:instructions|commands).{0,100}untrusted|untrusted.{0,100}(?:instructions|commands)", lower, re.DOTALL)
    assert "raw transcript" in lower
    assert "flag" in lower and "payload" in lower


def test_agents_readme_documents_retrospective_and_optional_learning_cli(repo_root: Path):
    readme = (repo_root / "README.md").read_text(encoding="utf-8").lower()
    assert SKILL_NAME in readme
    assert "optional" in readme
    assert "reviews the current session for reusable improvements to canonical skills" in readme
    assert "prepares sanitized learning proposals" not in readme
    assert "agent-side" in readme
    assert "explicit manual" in readme
    assert "not the post-solve review path" in readme
    assert "learn --propose" in readme and "learn --promote" in readme


def test_retrospective_output_has_evidence_gap_decision_and_approval_sections(repo_root: Path):
    _, content = read_skill(repo_root / "skills" / SKILL_NAME / "SKILL.md")
    lower = content.lower()
    sections = [
        lower.index("**evidence and scope:**"),
        lower.index("**gap and applicability:**"),
        lower.index("**decision:**"),
        lower.index("**approval:**"),
    ]

    assert sections == sorted(sections)
    assert "reusable beyond this lab" in lower
