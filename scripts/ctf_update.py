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

def find_asset_file(filename: str) -> Optional[Path]:
    """Resolves asset file from REPO_ROOT (source) or scripts/assets/ (pip/uv wheel)."""
    p = REPO_ROOT / filename
    if p.exists():
        return p
    p_assets = Path(__file__).resolve().parent / "assets" / filename
    if p_assets.exists():
        return p_assets
    return None

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
    def sync_directory_with_guard(
        cls,
        src_dir: Path,
        dest_dir: Path,
        label: str,
        force: bool = False,
        dry_run: bool = False,
    ) -> List[str]:
        """
        Surgically synchronizes a directory file-by-file with SHA-256 diffing.
        - Installs new files from upstream
        - Updates modified files while creating <file>.bak backups
        - Preserves user custom files completely untouched
        """
        actions: List[str] = []
        if not src_dir.exists():
            return actions

        if not dry_run:
            dest_dir.mkdir(parents=True, exist_ok=True)
        upstream_rel_paths = set()

        # 1. Inspect upstream files
        for src_file in src_dir.rglob("*"):
            if src_file.is_file():
                if src_file.suffix in (".pyc", ".pyo", ".log", ".tmp", ".dmp") or "__pycache__" in src_file.parts:
                    continue
                rel = src_file.relative_to(src_dir)
                if src_dir.name == "scripts" or "scripts" in label:
                    if any(part in ("local_ci.py", "assets", ".gitignore") for part in rel.parts):
                        continue
                upstream_rel_paths.add(rel)
                target_file = dest_dir / rel

                if not target_file.exists():
                    if not dry_run:
                        target_file.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(src_file, target_file)
                    actions.append(f"{'Would install' if dry_run else 'Installed'} new {label}: {rel}")
                else:
                    up_hash = cls.compute_file_hash(src_file)
                    loc_hash = cls.compute_file_hash(target_file)
                    if up_hash != loc_hash:
                        if not dry_run:
                            bak_file = target_file.with_name(target_file.name + ".bak")
                            shutil.copy2(target_file, bak_file)
                            shutil.copy2(src_file, target_file)
                        actions.append(f"{'Would update' if dry_run else 'Updated'} {label}{' with backup' if not dry_run else ''}: {rel}{' (saved .bak)' if not dry_run else ''}")

        # 2. Inspect local directory for custom files
        if dest_dir.exists():
            for loc_file in dest_dir.rglob("*"):
                if loc_file.is_file():
                    if loc_file.suffix == ".pyc" or "__pycache__" in loc_file.parts:
                        continue
                    rel = loc_file.relative_to(dest_dir)
                    if not str(rel).endswith(".bak") and rel not in upstream_rel_paths:
                        actions.append(f"Preserved custom {label}: {rel}")

        return actions

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
            "planned_actions": [],
        }

        action_sink = result["planned_actions"] if dry_run else result["actions_taken"]

        local_skills_dir = dot_agents / "skills"
        if not dry_run:
            local_skills_dir.mkdir(parents=True, exist_ok=True)
        upstream_skills_dir = REPO_ROOT / "skills"

        # 1. Synchronize Skills
        for diff in diffs:
            if diff.status in (SkillDiff.STATUS_NEW, SkillDiff.STATUS_UPDATED):
                if not dry_run:
                    src_skill = upstream_skills_dir / diff.name
                    dest_skill = local_skills_dir / diff.name
                    if dest_skill.exists():
                        shutil.rmtree(dest_skill)
                    shutil.copytree(src_skill, dest_skill)
                action_str = f"{'Would install' if dry_run else 'Installed'} new skill: {diff.name}" if diff.status == SkillDiff.STATUS_NEW else f"{'Would update' if dry_run else 'Updated'} skill: {diff.name}"
                action_sink.append(action_str)

            elif diff.status == SkillDiff.STATUS_MODIFIED:
                dest_skill = local_skills_dir / diff.name
                src_skill = upstream_skills_dir / diff.name
                if not dry_run:
                    # Backup local modified SKILL.md before overwrite
                    local_md = dest_skill / "SKILL.md"
                    local_bytes = local_md.read_bytes() if local_md.exists() else None
                    if dest_skill.exists():
                        shutil.rmtree(dest_skill)
                    shutil.copytree(src_skill, dest_skill)
                    # Re-place backup for user inspection
                    if local_bytes is not None:
                        (dest_skill / "SKILL.md.bak").write_bytes(local_bytes)
                action_str = f"{'Would update' if dry_run else 'Updated'} modified skill with backup: {diff.name}{' (saved SKILL.md.bak)' if not dry_run else ''}"
                action_sink.append(action_str)

            elif diff.status == SkillDiff.STATUS_CUSTOM:
                custom_skill_dir = local_skills_dir / diff.name
                audit_suffix = ""
                try:
                    from scripts.skill_validator import SkillEnvelopeValidator
                    val_rep = SkillEnvelopeValidator.validate_skill_dir(custom_skill_dir)
                    if not val_rep.is_valid:
                        audit_suffix = f" (envelope issues: {len(val_rep.errors)} errors, run 'ctf-agent validate-skill {custom_skill_dir}')"
                    elif val_rep.warnings:
                        audit_suffix = f" (envelope warnings: {len(val_rep.warnings)})"
                    else:
                        audit_suffix = " (envelope verified PASS)"
                except Exception:
                    pass

                action_sink.append(f"Preserved custom skill: {diff.name}{audit_suffix}")

        # 2. Synchronize non-skill directories & files unless skills_only
        if not skills_only:
            for dir_name in ["rules", "agents", "references", "scripts"]:
                src_d = REPO_ROOT / dir_name
                dest_d = dot_agents / dir_name
                dir_actions = cls.sync_directory_with_guard(src_d, dest_d, label=f".agents/{dir_name}", force=force, dry_run=dry_run)
                action_sink.extend(dir_actions)

            # Essential files in .agents/
            for f_name in ESSENTIAL_FILES:
                src_file = find_asset_file(f_name)
                dest_file = dot_agents / f_name
                if src_file and src_file.exists():
                    up_h = cls.compute_file_hash(src_file)
                    loc_h = cls.compute_file_hash(dest_file)
                    if not dest_file.exists():
                        if not dry_run:
                            shutil.copy2(src_file, dest_file)
                        action_sink.append(f"{'Would install' if dry_run else 'Installed'} .agents/{f_name}")
                    elif up_h != loc_h:
                        if not dry_run:
                            shutil.copy2(dest_file, dest_file.with_name(f_name + ".bak"))
                            shutil.copy2(src_file, dest_file)
                        action_sink.append(f"{'Would update' if dry_run else 'Updated'} .agents/{f_name}{' (saved .bak)' if not dry_run else ''}")

            # Workspace root files (AGENTS.md, mcp_config.json, skills.json)
            # If the workspace was deployed in agent-only mode, keep root clean
            is_agent_only_workspace = not (workspace_path / "AGENTS.md").exists() and (dot_agents / "AGENTS.md").exists()
            if not is_agent_only_workspace:
                for f_name in WORKSPACE_ROOT_FILES:
                    src_file = find_asset_file(f_name)
                    dest_file = workspace_path / f_name
                    if src_file and src_file.exists():
                        if f_name == "AGENTS.md" and workspace_path != REPO_ROOT:
                            content = src_file.read_text(encoding="utf-8")
                            content = content.replace("](references/", "](.agents/references/")
                            content = content.replace("](rules/", "](.agents/rules/")
                            dest_content = dest_file.read_text(encoding="utf-8") if dest_file.exists() else None
                            if dest_content != content:
                                if not dry_run:
                                    dest_file.write_text(content, encoding="utf-8", newline="\n")
                                action_sink.append(f"{'Would update' if dry_run else 'Updated'} workspace root: {f_name}")
                        else:
                            up_h = cls.compute_file_hash(src_file)
                            loc_h = cls.compute_file_hash(dest_file)
                            if up_h != loc_h:
                                if not dry_run:
                                    shutil.copy2(src_file, dest_file)
                                action_sink.append(f"{'Would update' if dry_run else 'Updated'} workspace root: {f_name}")

            # Workspace scripts/ synchronization if folder exists
            ws_scripts = workspace_path / "scripts"
            if ws_scripts.is_dir() and not is_agent_only_workspace:
                src_scripts = REPO_ROOT / "scripts"
                ws_actions = cls.sync_directory_with_guard(src_scripts, ws_scripts, label="scripts", force=force, dry_run=dry_run)
                action_sink.extend(ws_actions)

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
        if not lock_target.exists() and (dot_agents / "skills-lock.json").exists():
            lock_target = dot_agents / "skills-lock.json"
        lock_content = json.dumps(skills_lock, indent=2) + "\n"
        existing_lock = lock_target.read_text(encoding="utf-8") if lock_target.exists() else None
        needs_lock_update = (existing_lock is None) or (existing_lock.strip() != lock_content.strip())
        if needs_lock_update:
            if not dry_run:
                lock_target.write_text(lock_content, encoding="utf-8", newline="\n")
                action_sink.append(f"Regenerated {lock_target.name}")
            else:
                action_sink.append(f"Would regenerate {lock_target.name}")

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
    planned = result.get("planned_actions", [])
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
        for act in planned:
            if not act.startswith("Would install new skill") and not act.startswith("Would update skill") and not act.startswith("Would update modified skill"):
                print(f"  [*] {act}")
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
