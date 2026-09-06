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
import json
import hashlib
import subprocess
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
ESSENTIAL_FILES = ["AGENTS.md", "mcp_config.json", "skills.json", "README.md"]
WORKSPACE_ROOT_FILES = ["AGENTS.md", "mcp_config.json", "skills.json"]

def win_to_wsl_path(p: Path) -> str:
    """Converts a Windows Path (e.g. C:\\path\\to\\dir) to a WSL path (/mnt/c/path/to/dir)."""
    resolved = p.resolve()
    drive = resolved.drive.rstrip(':').lower()
    parts = list(resolved.parts[1:])
    return f"/mnt/{drive}/" + "/".join(parts)

def install_wsl_toolchain(target_path: Path, profile: str = "core", distro: str = "kali-linux"):
    """Installs CTF tools into WSL for the target workspace."""
    if shutil.which("wsl") is None:
        print("  [!] WSL command not available on this system. Skipping WSL toolchain installation.")
        return

    wsl_target = win_to_wsl_path(target_path)
    script_wsl = f"{wsl_target}/.agents/scripts/install_ctf_tools.sh"

    profiles = [p.strip() for p in profile.split(",") if p.strip()]

    print(f"\n[*] Provisioning WSL ({distro}) CTF toolchain for workspace...")
    print(f"    Target Workspace : {wsl_target}")
    print(f"    Profiles Selected: {', '.join(profiles)}")
    print(f"    Installer Script : {script_wsl}")

    for prof in profiles:
        cmd = ["wsl", "-d", distro, "bash", "-c", f"bash '{script_wsl}' {prof}"]
        try:
            print(f"\n[*] Executing install_ctf_tools.sh {prof} in WSL ({distro})...")
            res = subprocess.run(cmd, check=False)
            if res.returncode == 0:
                print(f"[OK] WSL CTF toolchain [{prof}] installed successfully!")
            else:
                print(f"[!] WSL CTF toolchain installer exited with code {res.returncode}")
        except Exception as e:
            print(f"[!] Error running WSL installer: {e}")

        # Run verification
        verify_cmd = ["wsl", "-d", distro, "bash", "-c", f"bash '{script_wsl}' --verify {prof}"]
        try:
            print(f"[*] Running toolchain verification check for [{prof}] in WSL...")
            subprocess.run(verify_cmd, check=False)
        except Exception as e:
            print(f"[!] Error running WSL verification: {e}")

def deploy_to_workspace(
    target_path: Path,
    use_symlink: bool = False,
    force: bool = False,
    setup_workspace: bool = True,
    install_wsl: bool = True,
    wsl_profile: str = "core",
    wsl_distro: str = "kali-linux"
):
    """Deploy CTF-Agent into target directory under .agents/, configure workspace files, and provision WSL toolchain."""
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

    if setup_workspace:
        print(f"\n[*] Configuring workspace root settings at {target_path}...")
        for file_name in WORKSPACE_ROOT_FILES:
            src_file = REPO_ROOT / file_name
            dest_file = target_path / file_name
            if src_file.exists():
                if file_name == "AGENTS.md" and target_path != REPO_ROOT:
                    content = src_file.read_text(encoding="utf-8")
                    content = content.replace("](references/", "](.agents/references/")
                    content = content.replace("](rules/", "](.agents/rules/")
                    dest_file.write_text(content, encoding="utf-8")
                else:
                    shutil.copy2(src_file, dest_file)
                print(f"  [+] Configured workspace root: {dest_file}")

        # Synchronize scripts into workspace scripts/ if directory exists
        ws_scripts = target_path / "scripts"
        if ws_scripts.is_dir():
            src_scripts = REPO_ROOT / "scripts"
            for s_file in src_scripts.iterdir():
                if s_file.is_file():
                    shutil.copy2(s_file, ws_scripts / s_file.name)
            print(f"  [+] Synchronized all scripts -> {ws_scripts}")

        # Generate skills-lock.json with computed hashes of local skills
        skills_lock = {"version": 1, "skills": {}}
        skills_dir = dot_agents / "skills"
        if skills_dir.exists():
            for skill_path in sorted(skills_dir.iterdir()):
                if skill_path.is_dir():
                    skill_md = skill_path / "SKILL.md"
                    if skill_md.exists():
                        h = hashlib.sha256(skill_md.read_bytes()).hexdigest()
                        skills_lock["skills"][skill_path.name] = {
                            "source": "CTF-Agent (local)",
                            "sourceType": "local",
                            "skillPath": f".agents/skills/{skill_path.name}/SKILL.md",
                            "computedHash": h
                        }
            skills_lock_file = target_path / "skills-lock.json"
            skills_lock_file.write_text(json.dumps(skills_lock, indent=2), encoding="utf-8")
            print(f"  [+] Generated {skills_lock_file}")

        # Provision CTF toolchain into WSL
        if install_wsl and os.name == 'nt':
            install_wsl_toolchain(target_path, profile=wsl_profile, distro=wsl_distro)

    print(f"\n[OK] Successfully deployed CTF-Agent into {dot_agents}!")
    print(f"    Available Subagents:")
    print(f"      - @ctf-controller : Master Orchestrator (SCO/TE context, refusal routing, deterministic fallback)")
    print(f"      - @ctf-speedrun   : Ultra-fast Blitz mode (Stop-on-Flag, zero doc overhead, auto-clean)")
    print(f"      - @ctf-analyzer   : In-depth Lab/Audit mode (Full RCA, resources/ preservation, writeup.md)")

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
    parser.add_argument("--setup-workspace", dest="setup_workspace", action="store_true", default=True, help="Configure workspace root AGENTS.md, mcp_config.json, skills.json (default: True)")
    parser.add_argument("--no-setup-workspace", dest="setup_workspace", action="store_false", help="Only deploy .agents/ without modifying workspace root files")
    parser.add_argument("--wsl", dest="install_wsl", action="store_true", default=True, help="Automatically install CTF toolchain into WSL during setup (default: True)")
    parser.add_argument("--no-wsl", dest="install_wsl", action="store_false", help="Skip WSL toolchain installation")
    parser.add_argument("--wsl-profile", default="core", help="WSL toolchain profile to install: core, pwn, rev, crypto, forensics, web, all (default: core)")
    parser.add_argument("--wsl-distro", default="kali-linux", help="WSL distribution target (default: kali-linux)")
    parser.add_argument("--force", "-f", action="store_true", help="Overwrite existing files or directories")

    args = parser.parse_args()

    if args.is_global:
        deploy_globally(force=args.force)
    elif args.target:
        target_dir = Path(args.target).resolve()
        deploy_to_workspace(
            target_dir,
            use_symlink=args.symlink,
            force=args.force,
            setup_workspace=args.setup_workspace,
            install_wsl=args.install_wsl,
            wsl_profile=args.wsl_profile,
            wsl_distro=args.wsl_distro
        )
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
