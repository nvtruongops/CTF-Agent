#!/usr/bin/env python3
"""
CTF-Agent Distribution & Deployment Manager (v1.0)
Deploys CTF-Agent skills, rules, subagents, and scripts into any CTF competition workspace (.agents/)
or globally into Antigravity user configuration (~/.gemini/config/).
"""

import os
import sys
import shutil
import argparse
from pathlib import Path
from typing import Optional

# Ensure safe UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

REPO_ROOT = Path(__file__).resolve().parent.parent

ESSENTIAL_DIRS = ["skills", "rules", "agents", "scripts", "references"]
ESSENTIAL_FILES = ["AGENTS.md", "mcp_config.json", "skills.json"]

def deploy_to_workspace(target_path: Path, use_symlink: bool = False, force: bool = False):
    """Deploy CTF-Agent into target directory under .agents/"""
    dot_agents = target_path / ".agents"
    print(f"[*] Deploying CTF-Agent to workspace: {dot_agents}")

    if dot_agents.exists() and not force:
        print(f"[!] Warning: {dot_agents} already exists. Use --force to overwrite.")
        sys.exit(1)

    dot_agents.mkdir(parents=True, exist_ok=True)

    for dir_name in ESSENTIAL_DIRS:
        src_dir = REPO_ROOT / dir_name
        dest_dir = dot_agents / dir_name

        if not src_dir.exists():
            continue

        if dest_dir.exists():
            if dest_dir.is_symlink() or (os.name == 'nt' and dest_dir.is_junction()):
                dest_dir.unlink()
            else:
                shutil.rmtree(dest_dir)

        if use_symlink:
            try:
                if os.name == 'nt':
                    import _winapi
                    _winapi.CreateJunction(str(src_dir), str(dest_dir))
                else:
                    dest_dir.symlink_to(src_dir, target_is_directory=True)
                print(f"  [+] Linked {dir_name}/ -> {dest_dir}")
            except Exception as e:
                print(f"  [!] Symlink/Junction failed ({e}), falling back to copy...")
                shutil.copytree(src_dir, dest_dir)
                print(f"  [+] Copied {dir_name}/ -> {dest_dir}")
        else:
            shutil.copytree(src_dir, dest_dir)
            print(f"  [+] Copied {dir_name}/ -> {dest_dir}")

    for file_name in ESSENTIAL_FILES:
        src_file = REPO_ROOT / file_name
        dest_file = dot_agents / file_name
        if src_file.exists():
            shutil.copy2(src_file, dest_file)
            print(f"  [+] Copied {file_name} -> {dest_file}")

    print(f"\n[OK] Successfully deployed CTF-Agent into {dot_agents}!")
    print(f"    Available Subagents:")
    print(f"      - @ctf-speedrun : Ultra-fast Blitz mode (Stop-on-Flag, zero doc overhead, auto-clean)")
    print(f"      - @ctf-analyzer : In-depth Lab/Audit mode (Full RCA, resources/ preservation, writeup.md)")

def deploy_globally(force: bool = False):
    """Deploy skills, rules, and subagents into ~/.gemini/config/ for global availability."""
    home = Path.home()
    global_config = home / ".gemini" / "config"
    print(f"[*] Deploying CTF-Agent globally to: {global_config}")

    if not global_config.exists():
        global_config.mkdir(parents=True, exist_ok=True)

    # 1. Deploy Skills
    global_skills = global_config / "skills"
    global_skills.mkdir(exist_ok=True)
    for skill_path in (REPO_ROOT / "skills").iterdir():
        if skill_path.is_dir():
            dest = global_skills / skill_path.name
            if dest.exists() and force:
                shutil.rmtree(dest)
            if not dest.exists():
                shutil.copytree(skill_path, dest)
                print(f"  [+] Deployed skill: {skill_path.name}")

    # 2. Deploy Agents
    global_agents = global_config / "agents"
    global_agents.mkdir(exist_ok=True)
    for agent_path in (REPO_ROOT / "agents").iterdir():
        if agent_path.is_file() and agent_path.suffix == ".md":
            dest = global_agents / agent_path.name
            shutil.copy2(agent_path, dest)
            print(f"  [+] Deployed agent: {agent_path.name}")

    # 3. Deploy Rules
    global_rules = global_config / "rules"
    global_rules.mkdir(exist_ok=True)
    for rule_path in (REPO_ROOT / "rules").iterdir():
        if rule_path.is_file() and rule_path.suffix == ".md":
            dest = global_rules / rule_path.name
            shutil.copy2(rule_path, dest)
            print(f"  [+] Deployed rule: {rule_path.name}")

    print(f"\n[OK] Successfully installed CTF-Agent globally across all Antigravity workspaces!")

def main():
    parser = argparse.ArgumentParser(description="CTF-Agent Workspace & Global Deployment Manager")
    parser.add_argument("target", nargs="?", help="Target CTF workspace directory (deploys as .agents/)")
    parser.add_argument("--global", dest="is_global", action="store_true", help="Install CTF skills, rules, and subagents globally into ~/.gemini/config/")
    parser.add_argument("--symlink", "--link", action="store_true", help="Use symlinks/junctions for workspace deployment to keep live sync")
    parser.add_argument("--force", "-f", action="store_true", help="Overwrite existing files or directories")

    args = parser.parse_args()

    if args.is_global:
        deploy_globally(force=args.force)
    elif args.target:
        target_dir = Path(args.target).resolve()
        deploy_to_workspace(target_dir, use_symlink=args.symlink, force=args.force)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
