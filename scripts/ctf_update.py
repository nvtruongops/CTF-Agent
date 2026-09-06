#!/usr/bin/env python3
"""
CTF-Agent Workspace & Skill Update Engine
Synchronizes CTF-Agent skills, rules, agent personas, references, and scripts
into existing workspaces with SHA-256 diffing, lockfile verification, and conflict guards.
"""

import os
import sys
import shutil
import hashlib
import json
import argparse
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

# Safe UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

REPO_ROOT = Path(__file__).resolve().parent.parent

ESSENTIAL_DIRS = ["skills", "rules", "agents", "scripts", "references"]
ESSENTIAL_FILES = ["AGENTS.md", "mcp_config.json", "skills.json", "README.md"]
WORKSPACE_ROOT_FILES = ["AGENTS.md", "mcp_config.json", "skills.json"]


class SkillDiff:
    """Represents the diff state of a specific skill between upstream and workspace."""

    STATUS_NEW = "NEW"
    STATUS_UPDATED = "UPDATED"
    STATUS_MODIFIED = "MODIFIED"
    STATUS_CUSTOM = "CUSTOM"
    STATUS_UP_TO_DATE = "UP_TO_DATE"

    def __init__(
        self,
        name: str,
        status: str,
        upstream_hash: Optional[str] = None,
        local_hash: Optional[str] = None,
        locked_hash: Optional[str] = None,
        detail: str = "",
    ):
        self.name = name
        self.status = status
        self.upstream_hash = upstream_hash
        self.local_hash = local_hash
        self.locked_hash = locked_hash
        self.detail = detail

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "upstream_hash": self.upstream_hash,
            "local_hash": self.local_hash,
            "locked_hash": self.locked_hash,
            "detail": self.detail,
        }


class WorkspaceUpdater:
    """Orchestrates workspace and skill synchronization with conflict protection."""

    @staticmethod
    def resolve_workspace(target_input: Optional[str]) -> Path:
        """Resolves target workspace directory from input string or current working directory."""
        if target_input:
            path = Path(target_input).resolve()
        else:
            path = Path.cwd().resolve()

        if path.name in (".agents", ".agent") and path.parent.is_dir():
            path = path.parent

        return path

    @staticmethod
    def compute_file_hash(path: Path) -> Optional[str]:
        """Calculates SHA-256 hash of a file if it exists."""
        if not path.is_file():
            return None
        try:
            return hashlib.sha256(path.read_bytes()).hexdigest()
        except Exception:
            return None

    @classmethod
    def inspect_skills(cls, workspace_path: Path) -> List[SkillDiff]:
        """Compares upstream skills with workspace .agents/skills/ and skills-lock.json."""
        diffs: List[SkillDiff] = []

        dot_agents = workspace_path / ".agents"
        if not dot_agents.exists() and (workspace_path / ".agent").exists():
            dot_agents = workspace_path / ".agent"

        local_skills_dir = dot_agents / "skills"
        upstream_skills_dir = REPO_ROOT / "skills"

        # Load skills-lock.json if available
        lock_file = workspace_path / "skills-lock.json"
        if not lock_file.exists():
            lock_file = dot_agents / "skills-lock.json"

        locked_skills: Dict[str, str] = {}
        if lock_file.exists():
            try:
                data = json.loads(lock_file.read_text(encoding="utf-8"))
                for s_name, s_meta in data.get("skills", {}).items():
                    if isinstance(s_meta, dict) and "computedHash" in s_meta:
                        locked_skills[s_name] = s_meta["computedHash"]
            except Exception:
                pass

        upstream_skill_names = set()
        if upstream_skills_dir.exists():
            for item in sorted(upstream_skills_dir.iterdir()):
                if item.is_dir():
                    upstream_skill_names.add(item.name)
                    up_md = item / "SKILL.md"
                    up_hash = cls.compute_file_hash(up_md)

                    loc_dir = local_skills_dir / item.name
                    loc_md = loc_dir / "SKILL.md"
                    loc_hash = cls.compute_file_hash(loc_md)
                    lock_hash = locked_skills.get(item.name)

                    if not loc_dir.exists() or not loc_md.exists():
                        diffs.append(
                            SkillDiff(
                                name=item.name,
                                status=SkillDiff.STATUS_NEW,
                                upstream_hash=up_hash,
                                local_hash=None,
                                locked_hash=lock_hash,
                                detail="New skill available upstream",
                            )
                        )
                    elif loc_hash == up_hash:
                        diffs.append(
                            SkillDiff(
                                name=item.name,
                                status=SkillDiff.STATUS_UP_TO_DATE,
                                upstream_hash=up_hash,
                                local_hash=loc_hash,
                                locked_hash=lock_hash,
                                detail="Up to date with upstream",
                            )
                        )
                    else:
                        if lock_hash and loc_hash == lock_hash:
                            diffs.append(
                                SkillDiff(
                                    name=item.name,
                                    status=SkillDiff.STATUS_UPDATED,
                                    upstream_hash=up_hash,
                                    local_hash=loc_hash,
                                    locked_hash=lock_hash,
                                    detail="Upstream update available (clean local copy)",
                                )
                            )
                        elif lock_hash is None:
                            diffs.append(
                                SkillDiff(
                                    name=item.name,
                                    status=SkillDiff.STATUS_UPDATED,
                                    upstream_hash=up_hash,
                                    local_hash=loc_hash,
                                    locked_hash=None,
                                    detail="Upstream update available",
                                )
                            )
                        else:
                            diffs.append(
                                SkillDiff(
                                    name=item.name,
                                    status=SkillDiff.STATUS_MODIFIED,
                                    upstream_hash=up_hash,
                                    local_hash=loc_hash,
                                    locked_hash=lock_hash,
                                    detail="Local modifications detected (different from lockfile)",
                                )
                            )

        # Check for custom workspace skills not in upstream
        if local_skills_dir.exists():
            for loc_item in sorted(local_skills_dir.iterdir()):
                if loc_item.is_dir() and loc_item.name not in upstream_skill_names:
                    loc_hash = cls.compute_file_hash(loc_item / "SKILL.md")
                    diffs.append(
                        SkillDiff(
                            name=loc_item.name,
                            status=SkillDiff.STATUS_CUSTOM,
                            upstream_hash=None,
                            local_hash=loc_hash,
                            locked_hash=locked_skills.get(loc_item.name),
                            detail="Custom workspace skill (preserved untouched)",
                        )
                    )

        return diffs

    @classmethod
    def update_workspace(
        cls,
        workspace_path: Path,
        skills_only: bool = False,
        dry_run: bool = False,
        force: bool = False,
    ) -> Dict[str, Any]:
        """Executes synchronization of skills and support files into target workspace."""
        dot_agents = workspace_path / ".agents"
        if not dot_agents.exists() and (workspace_path / ".agent").exists():
            dot_agents = workspace_path / ".agent"

        if not dot_agents.exists():
            raise FileNotFoundError(
                f"No .agents/ or .agent/ directory found in {workspace_path}. "
                f"Please run 'ctf-agent init' first to initialize the workspace."
            )

        diffs = cls.inspect_skills(workspace_path)
        new_skills = [d for d in diffs if d.status == SkillDiff.STATUS_NEW]
        updated_skills = [d for d in diffs if d.status == SkillDiff.STATUS_UPDATED]
        modified_skills = [d for d in diffs if d.status == SkillDiff.STATUS_MODIFIED]
        custom_skills = [d for d in diffs if d.status == SkillDiff.STATUS_CUSTOM]
        uptodate_skills = [d for d in diffs if d.status == SkillDiff.STATUS_UP_TO_DATE]

        result: Dict[str, Any] = {
            "workspace": str(workspace_path.resolve()),
            "dot_agents": str(dot_agents.resolve()),
            "dry_run": dry_run,
            "skills_only": skills_only,
            "skills_summary": {
                "new": len(new_skills),
                "updated": len(updated_skills),
                "modified": len(modified_skills),
                "custom": len(custom_skills),
                "up_to_date": len(uptodate_skills),
            },
            "skills_detail": [d.to_dict() for d in diffs],
            "actions_taken": [],
        }

        if dry_run:
            return result

        local_skills_dir = dot_agents / "skills"
        local_skills_dir.mkdir(parents=True, exist_ok=True)
        upstream_skills_dir = REPO_ROOT / "skills"

        # 1. Synchronize Skills
        for diff in diffs:
            if diff.status in (SkillDiff.STATUS_NEW, SkillDiff.STATUS_UPDATED):
                src_skill = upstream_skills_dir / diff.name
                dest_skill = local_skills_dir / diff.name
                if dest_skill.exists():
                    shutil.rmtree(dest_skill)
                shutil.copytree(src_skill, dest_skill)
                action_str = f"Installed new skill: {diff.name}" if diff.status == SkillDiff.STATUS_NEW else f"Updated skill: {diff.name}"
                result["actions_taken"].append(action_str)

            elif diff.status == SkillDiff.STATUS_MODIFIED:
                dest_skill = local_skills_dir / diff.name
                src_skill = upstream_skills_dir / diff.name
                # Backup local modified SKILL.md before overwrite
                backup_file = dest_skill / "SKILL.md.bak"
                local_md = dest_skill / "SKILL.md"
                if local_md.exists():
                    shutil.copy2(local_md, backup_file)
                if dest_skill.exists():
                    shutil.rmtree(dest_skill)
                shutil.copytree(src_skill, dest_skill)
                # Re-place backup for user inspection
                if backup_file.exists():
                    shutil.copy2(backup_file, dest_skill / "SKILL.md.bak")
                action_str = f"Updated modified skill with backup: {diff.name} (saved SKILL.md.bak)"
                result["actions_taken"].append(action_str)

            elif diff.status == SkillDiff.STATUS_CUSTOM:
                result["actions_taken"].append(f"Preserved custom skill: {diff.name}")

        # 2. Synchronize non-skill directories & files unless skills_only
        if not skills_only:
            for dir_name in ["rules", "agents", "references", "scripts"]:
                src_dir = REPO_ROOT / dir_name
                dest_dir = dot_agents / dir_name
                if src_dir.exists():
                    if dest_dir.exists():
                        shutil.rmtree(dest_dir)
                    shutil.copytree(src_dir, dest_dir)
                    result["actions_taken"].append(f"Updated .agents/{dir_name}/")

            # Essential files in .agents/
            for f_name in ESSENTIAL_FILES:
                src_file = REPO_ROOT / f_name
                dest_file = dot_agents / f_name
                if src_file.exists():
                    shutil.copy2(src_file, dest_file)
                    result["actions_taken"].append(f"Updated .agents/{f_name}")

            # Workspace root files (AGENTS.md, mcp_config.json, skills.json)
            for f_name in WORKSPACE_ROOT_FILES:
                src_file = REPO_ROOT / f_name
                dest_file = workspace_path / f_name
                if src_file.exists():
                    if f_name == "AGENTS.md" and workspace_path != REPO_ROOT:
                        content = src_file.read_text(encoding="utf-8")
                        content = content.replace("](references/", "](.agents/references/")
                        content = content.replace("](rules/", "](.agents/rules/")
                        dest_file.write_text(content, encoding="utf-8")
                    else:
                        shutil.copy2(src_file, dest_file)
                    result["actions_taken"].append(f"Updated workspace root: {f_name}")

            # Workspace scripts/ synchronization if folder exists
            ws_scripts = workspace_path / "scripts"
            if ws_scripts.is_dir():
                src_scripts = REPO_ROOT / "scripts"
                for s_file in src_scripts.iterdir():
                    if s_file.is_file():
                        shutil.copy2(s_file, ws_scripts / s_file.name)
                result["actions_taken"].append("Synchronized workspace scripts/")

        # 3. Regenerate skills-lock.json with updated SHA-256 hashes
        skills_lock: Dict[str, Any] = {"version": 1, "skills": {}}
        if local_skills_dir.exists():
            for s_dir in sorted(local_skills_dir.iterdir()):
                if s_dir.is_dir():
                    s_md = s_dir / "SKILL.md"
                    if s_md.exists():
                        h = cls.compute_file_hash(s_md)
                        skills_lock["skills"][s_dir.name] = {
                            "source": "CTF-Agent (local)",
                            "sourceType": "local",
                            "skillPath": f".agents/skills/{s_dir.name}/SKILL.md",
                            "computedHash": h or "",
                        }

        lock_target = workspace_path / "skills-lock.json"
        lock_target.write_text(json.dumps(skills_lock, indent=2), encoding="utf-8")
        result["actions_taken"].append(f"Regenerated {lock_target.name}")

        return result

    @classmethod
    def update_globally(cls, dry_run: bool = False, force: bool = False) -> Dict[str, Any]:
        """Updates global Antigravity configuration in ~/.gemini/config/."""
        global_config = Path.home() / ".gemini" / "config"
        result: Dict[str, Any] = {
            "global_config": str(global_config.resolve()),
            "dry_run": dry_run,
            "actions_taken": [],
        }

        if dry_run:
            return result

        global_config.mkdir(parents=True, exist_ok=True)

        # 1. Update Global Skills
        global_skills = global_config / "skills"
        global_skills.mkdir(exist_ok=True)
        for s_path in (REPO_ROOT / "skills").iterdir():
            if s_path.is_dir():
                dest = global_skills / s_path.name
                if dest.exists() and force:
                    shutil.rmtree(dest)
                if not dest.exists():
                    shutil.copytree(s_path, dest)
                    result["actions_taken"].append(f"Installed global skill: {s_path.name}")
                elif dest.exists():
                    shutil.rmtree(dest)
                    shutil.copytree(s_path, dest)
                    result["actions_taken"].append(f"Updated global skill: {s_path.name}")

        # 2. Update Global Agents
        global_agents = global_config / "agents"
        global_agents.mkdir(exist_ok=True)
        for a_path in (REPO_ROOT / "agents").iterdir():
            if a_path.is_file() and a_path.suffix == ".md":
                dest = global_agents / a_path.name
                shutil.copy2(a_path, dest)
                result["actions_taken"].append(f"Updated global agent: {a_path.name}")

        # 3. Update Global Rules
        global_rules = global_config / "rules"
        global_rules.mkdir(exist_ok=True)
        for r_path in (REPO_ROOT / "rules").iterdir():
            if r_path.is_file() and r_path.suffix == ".md":
                dest = global_rules / r_path.name
                shutil.copy2(r_path, dest)
                result["actions_taken"].append(f"Updated global rule: {r_path.name}")

        return result


def print_update_report(result: Dict[str, Any]):
    """Displays user-friendly terminal update report."""
    print("\n=================================================================")
    print("CTF-AGENT WORKSPACE & SKILL UPDATE REPORT")
    print("=================================================================")
    print(f"Target Workspace: {result.get('workspace', result.get('global_config'))}")
    if result.get("dry_run"):
        print("Mode            : DRY RUN (No changes written)")
    else:
        print("Mode            : LIVE SYNCHRONIZATION")
    print("-----------------------------------------------------------------")

    summary = result.get("skills_summary", {})
    if summary:
        print(f"Skills Overview:")
        print(f"  [+] New available     : {summary.get('new', 0)}")
        print(f"  [*] Updated           : {summary.get('updated', 0)}")
        print(f"  [!] Locally modified  : {summary.get('modified', 0)}")
        print(f"  [=] Up to date        : {summary.get('up_to_date', 0)}")
        print(f"  [#] Custom (preserved): {summary.get('custom', 0)}")
        print("-----------------------------------------------------------------")

    actions = result.get("actions_taken", [])
    if actions:
        print("Actions Executed:")
        for act in actions:
            print(f"  [+] {act}")
        print("-----------------------------------------------------------------")
    elif result.get("dry_run"):
        print("Planned Changes:")
        for s in result.get("skills_detail", []):
            st = s["status"]
            name = s["name"]
            detail = s["detail"]
            if st == SkillDiff.STATUS_NEW:
                print(f"  [+] {name:30} -> {detail}")
            elif st == SkillDiff.STATUS_UPDATED:
                print(f"  [*] {name:30} -> {detail}")
            elif st == SkillDiff.STATUS_MODIFIED:
                print(f"  [!] {name:30} -> {detail}")
            elif st == SkillDiff.STATUS_CUSTOM:
                print(f"  [#] {name:30} -> {detail}")
        print("-----------------------------------------------------------------")

    print("[OK] Workspace synchronization complete.")
    print("=================================================================\n")


def main():
    parser = argparse.ArgumentParser(description="CTF-Agent Workspace & Skill Updater")
    parser.add_argument("target", nargs="?", help="Target CTF workspace directory (default: current directory)")
    parser.add_argument("--global", dest="is_global", action="store_true", help="Update global Antigravity config (~/.gemini/config/)")
    parser.add_argument("--skills-only", action="store_true", help="Only update skills, preserving rules, agents, and scripts")
    parser.add_argument("--dry-run", action="store_true", help="Inspect and display planned changes without modifying files")
    parser.add_argument("--force", "-f", action="store_true", help="Overwrite modified skills without interactive prompt")
    parser.add_argument("--json", action="store_true", help="Output update report as JSON")

    args = parser.parse_args()

    try:
        if args.is_global:
            result = WorkspaceUpdater.update_globally(dry_run=args.dry_run, force=args.force)
        else:
            workspace = WorkspaceUpdater.resolve_workspace(args.target)
            result = WorkspaceUpdater.update_workspace(
                workspace,
                skills_only=args.skills_only,
                dry_run=args.dry_run,
                force=args.force,
            )

        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print_update_report(result)

    except Exception as e:
        print(f"\n[!] Error during update: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
