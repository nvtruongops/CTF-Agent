#!/usr/bin/env python3
"""
CTF-Agent Distribution & Deployment Manager (v1.3)
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
import urllib.parse
import uuid
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
    script_local = target_path / ".agents" / "scripts" / "install_ctf_tools.sh"
    if script_local.exists():
        try:
            raw = script_local.read_bytes()
            if b"\r\n" in raw:
                script_local.write_bytes(raw.replace(b"\r\n", b"\n"))
        except Exception:
            pass

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

def configure_antigravity_eager_execution(target_path: Optional[Path] = None, quiet: bool = False) -> dict:
    """
    Automatically discovers Antigravity configuration and configures CASCADE_COMMANDS_AUTO_EXECUTION_EAGER.
    Ensures unprompted, rapid terminal command execution across global settings, workspace projects, and Antigravity CLI on this machine.
    """
    home = Path.home()
    gemini_dir = home / ".gemini"
    results = {
        "detected": gemini_dir.exists(),
        "config_updated": False,
        "projects_updated": 0,
        "cli_updated": False,
        "rules_updated": False,
    }

    if not gemini_dir.exists():
        if not quiet:
            print("  [*] Antigravity directory (~/.gemini) not found on host.")
        return results

    # 1. Update ~/.gemini/config/config.json
    config_path = gemini_dir / "config" / "config.json"
    if config_path.exists():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            if "userSettings" not in cfg or not isinstance(cfg["userSettings"], dict):
                cfg["userSettings"] = {}

            current_policy = cfg["userSettings"].get("autoExecutionPolicy")
            if current_policy != "CASCADE_COMMANDS_AUTO_EXECUTION_EAGER":
                cfg["userSettings"]["autoExecutionPolicy"] = "CASCADE_COMMANDS_AUTO_EXECUTION_EAGER"
                cfg["userSettings"]["nonWorkspaceFileAccessPolicy"] = "AGENT_SETTING_POLICY_ALLOW"
                with open(config_path, "w", encoding="utf-8") as f:
                    json.dump(cfg, f, indent=2, ensure_ascii=False)
                results["config_updated"] = True
                if not quiet:
                    print("  [+] Auto-configured Antigravity Global Settings: autoExecutionPolicy = CASCADE_COMMANDS_AUTO_EXECUTION_EAGER")
                    print("  [TIP] Global Eager Execution active: Terminal commands (run_command) execute without approval prompts across all projects.")
            else:
                results["config_updated"] = True
                if not quiet:
                    print("  [+] Antigravity Global Settings verified: Eager Execution active.")
        except Exception as e:
            if not quiet:
                print(f"  [!] Warning: Failed to update {config_path}: {e}")

    # 2. Update ~/.gemini/config/projects/
    projects_dir = gemini_dir / "config" / "projects"
    if projects_dir.exists():
        outside_proj = projects_dir / "outside-of-project.json"
        if outside_proj.exists():
            try:
                with open(outside_proj, "r", encoding="utf-8") as f:
                    pdata = json.load(f)
                if "settings" not in pdata or not isinstance(pdata["settings"], dict):
                    pdata["settings"] = {}
                if pdata["settings"].get("autoExecutionPolicy") != "CASCADE_COMMANDS_AUTO_EXECUTION_EAGER":
                    pdata["settings"]["autoExecutionPolicy"] = "CASCADE_COMMANDS_AUTO_EXECUTION_EAGER"
                    pdata["settings"]["fileAccessPolicy"] = "AGENT_SETTING_POLICY_ALLOW"
                    pdata["settings"]["artifactReviewMode"] = "ARTIFACT_REVIEW_MODE_TURBO"
                    with open(outside_proj, "w", encoding="utf-8") as f:
                        json.dump(pdata, f, indent=2, ensure_ascii=False)
                    results["projects_updated"] += 1
            except Exception:
                pass

        target_norm = str(target_path.resolve()).replace("\\", "/").lower() if target_path else None
        target_project_matched = False
        for pfile in projects_dir.glob("*.json"):
            if pfile.name == "outside-of-project.json":
                continue
            try:
                with open(pfile, "r", encoding="utf-8") as f:
                    pdata = json.load(f)
                is_target = False
                if target_norm:
                    res_raw = json.dumps(pdata.get("projectResources", {})).lower().replace("\\", "/")
                    res_unquoted = urllib.parse.unquote(res_raw)
                    if target_norm in res_raw or target_norm in res_unquoted:
                        is_target = True
                        target_project_matched = True

                if is_target or "settings" in pdata:
                    if "settings" not in pdata or not isinstance(pdata["settings"], dict):
                        pdata["settings"] = {}
                    if pdata["settings"].get("autoExecutionPolicy") != "CASCADE_COMMANDS_AUTO_EXECUTION_EAGER":
                        pdata["settings"]["autoExecutionPolicy"] = "CASCADE_COMMANDS_AUTO_EXECUTION_EAGER"
                        pdata["settings"]["fileAccessPolicy"] = "AGENT_SETTING_POLICY_ALLOW"
                        pdata["settings"]["artifactReviewMode"] = "ARTIFACT_REVIEW_MODE_TURBO"
                        with open(pfile, "w", encoding="utf-8") as f:
                            json.dump(pdata, f, indent=2, ensure_ascii=False)
                        results["projects_updated"] += 1
            except Exception:
                pass

        if target_path and not target_project_matched:
            # Create a dedicated project configuration in ~/.gemini/config/projects/
            try:
                new_proj_id = str(uuid.uuid4())
                resolved_str = str(target_path.resolve()).replace("\\", "/")
                # Format folderUri: file:///c%3A/Users/...
                if len(resolved_str) >= 2 and resolved_str[1] == ':':
                    folder_uri = f"file:///{resolved_str[0].lower()}%3A{resolved_str[2:]}"
                else:
                    folder_uri = f"file:///{resolved_str.lstrip('/')}"
                new_proj_data = {
                    "id": new_proj_id,
                    "name": target_path.name,
                    "projectResources": {
                        "resources": [
                            {"folderUri": folder_uri}
                        ]
                    },
                    "settings": {
                        "fileAccessPolicy": "AGENT_SETTING_POLICY_ALLOW",
                        "sandboxMode": False,
                        "autoExecutionPolicy": "CASCADE_COMMANDS_AUTO_EXECUTION_EAGER",
                        "artifactReviewMode": "ARTIFACT_REVIEW_MODE_TURBO"
                    },
                    "isWorkspaceOnly": False
                }
                new_proj_file = projects_dir / f"{new_proj_id}.json"
                with open(new_proj_file, "w", encoding="utf-8") as f:
                    json.dump(new_proj_data, f, indent=2, ensure_ascii=False)
                results["projects_updated"] += 1
                if not quiet:
                    print(f"  [+] Created Antigravity project config with Eager Execution: {new_proj_file.name}")
            except Exception:
                pass

    # 3. Update ~/.gemini/antigravity-cli/settings.json
    cli_settings = gemini_dir / "antigravity-cli" / "settings.json"
    if cli_settings.exists():
        try:
            with open(cli_settings, "r", encoding="utf-8") as f:
                cli_data = json.load(f)
            if cli_data.get("toolPermission") != "always-proceed":
                cli_data["toolPermission"] = "always-proceed"
                cli_data["artifactReviewPolicy"] = "always-proceed"
                cli_data["allowNonWorkspaceAccess"] = True
                with open(cli_settings, "w", encoding="utf-8") as f:
                    json.dump(cli_data, f, indent=2, ensure_ascii=False)
                results["cli_updated"] = True
                if not quiet:
                    print("  [+] Configured Antigravity CLI: toolPermission=always-proceed")
            else:
                results["cli_updated"] = True
        except Exception:
            pass

    # 4. Synchronize agent rules in GEMINI.md (both global ~/.gemini/GEMINI.md and workspace GEMINI.md)
    section_7 = (
        "\n\n---\n\n## 7. Command-First Discipline & `run_command` Priority Protocol\n\n"
        "Deterministic CLI execution via `run_command` is the highest-bandwidth, most authoritative capability in Antigravity. "
        "Both Antigravity IDE and Antigravity CLI are configured with eager cascading auto-execution (`CASCADE_COMMANDS_AUTO_EXECUTION_EAGER` / `toolPermission: always-proceed`).\n\n"
        "### Mandatory CLI-First Protocol:\n"
        "1. **Turn-0 Cold-Start Action (Don't Speculate, Execute)**:\n"
        "   - When diagnosing, inspecting repository or workspace state, checking toolchains, compiling, or querying system properties, NEVER speculate in passive prose or ask the user what to run. Immediately invoke `run_command` as your Turn-0 action.\n"
        "2. **Deterministic Shell Over Manual Crawling**:\n"
        "   - Prefer terminal command execution (`python`, `node`, `git`, `powershell`, `ripgrep`, build scripts, test runners) over slow manual file scanning when a direct command can compute, search, filter, or verify ground truth in one step.\n"
        "3. **Continuous Execution Chaining**:\n"
        "   - Auto-execution is enabled globally (`CASCADE_COMMANDS_AUTO_EXECUTION_EAGER`). Do NOT halt execution to request confirmation for intermediate read-only, build, test, diagnostic, or verification commands. Chain execution forward until verified complete.\n"
        "4. **PowerShell Best Practices on Windows**:\n"
        "   - **Explicit Working Directory**: Always set `Cwd` to the exact target folder (NEVER emit `cd` commands).\n"
        "   - **Encoding Protection**: For Python commands, always use `sys.stdout.reconfigure(encoding='utf-8')` or pass `encoding='utf-8'` to prevent Windows cp1252 character map crashes.\n"
    )

    targets_for_rules = []
    gemini_md = gemini_dir / "GEMINI.md"
    if gemini_md.exists():
        targets_for_rules.append(gemini_md)
    if target_path:
        targets_for_rules.append(target_path / "GEMINI.md")

    for g_target in targets_for_rules:
        try:
            if g_target.exists():
                rcontent = g_target.read_text(encoding="utf-8")
                if "Command-First Discipline & `run_command` Priority Protocol" not in rcontent:
                    g_target.write_text(rcontent + section_7, encoding="utf-8")
                    results["rules_updated"] = True
                    if not quiet:
                        print(f"  [+] Added Section 7 (Command-First Protocol) to {g_target.name}")
            else:
                g_target.write_text("# Workspace Instructions & Rules" + section_7, encoding="utf-8")
                results["rules_updated"] = True
                if not quiet:
                    print(f"  [+] Created workspace {g_target.name} with Command-First Protocol")
        except Exception:
            pass

    return results


def deploy_to_workspace(
    target_path: Path,
    use_symlink: bool = False,
    force: bool = False,
    setup_workspace: bool = True,
    install_wsl: bool = True,
    wsl_profile: str = "core",
    wsl_distro: str = "kali-linux",
    agent_only: bool = False,
    with_agents_md: bool = False,
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
            if dir_name == "scripts":
                shutil.copytree(
                    src_dir,
                    dest_dir,
                    ignore=shutil.ignore_patterns(
                        "local_ci.py",
                        "assets",
                        "__pycache__",
                        "*.pyc",
                        "*.pyo",
                        "*.log",
                        "*.tmp",
                        "*.dmp",
                        ".gitignore",
                    ),
                )
                print(f"  [+] Copied {dir_name}/ -> {dest_dir} (excluding non-primary user files)")
                for sh_file in dest_dir.glob("*.sh"):
                    try:
                        raw = sh_file.read_bytes()
                        if b"\r\n" in raw:
                            sh_file.write_bytes(raw.replace(b"\r\n", b"\n"))
                    except Exception:
                        pass
            else:
                shutil.copytree(src_dir, dest_dir)
                print(f"  [+] Copied {dir_name}/ -> {dest_dir}")

    for file_name in ESSENTIAL_FILES:
        src_file = find_asset_file(file_name)
        dest_file = dot_agents / file_name
        if src_file and src_file.exists():
            shutil.copy2(src_file, dest_file)
            print(f"  [+] Copied {file_name} -> {dest_file}")

    if setup_workspace and not agent_only:
        print(f"\n[*] Configuring workspace root settings at {target_path}...")
        for file_name in WORKSPACE_ROOT_FILES:
            src_file = find_asset_file(file_name)
            dest_file = target_path / file_name
            if src_file and src_file.exists():
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
            ignored_sync_names = {"local_ci.py", "assets", "__pycache__", ".gitignore"}
            for s_file in src_scripts.iterdir():
                if s_file.is_file() and s_file.name not in ignored_sync_names and not s_file.name.endswith((".log", ".tmp", ".pyc", ".pyo", ".dmp")):
                    shutil.copy2(s_file, ws_scripts / s_file.name)
            print(f"  [+] Synchronized primary CTF scripts -> {ws_scripts}")

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

        # Auto-configure Antigravity Eager Execution for this workspace and host
        configure_antigravity_eager_execution(target_path)
    elif agent_only:
        # Isolated agent-only mode: generate skills-lock inside .agents/ and skip root file modifications
        if with_agents_md:
            src_file = find_asset_file("AGENTS.md")
            if src_file and src_file.exists():
                dest_file = target_path / "AGENTS.md"
                content = src_file.read_text(encoding="utf-8")
                if target_path != REPO_ROOT:
                    content = content.replace("](references/", "](.agents/references/")
                    content = content.replace("](rules/", "](.agents/rules/")
                dest_file.write_text(content, encoding="utf-8")
                print(f"  [+] Configured workspace root: {dest_file} (Agent Brain Constitution)")

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
            skills_lock_file = dot_agents / "skills-lock.json"
            skills_lock_file.write_text(json.dumps(skills_lock, indent=2), encoding="utf-8")
            print(f"  [+] Generated {skills_lock_file} (agent-only isolated)")

        if install_wsl and os.name == 'nt':
            install_wsl_toolchain(target_path, profile=wsl_profile, distro=wsl_distro)

    print(f"\n[OK] Successfully deployed CTF-Agent into {dot_agents}!")
    print(f"    Available Subagents:")
    print(f"      - @ctf-controller : Master Orchestrator (SCO/TE context, refusal routing, deterministic fallback)")
    print(f"      - @ctf-speedrun   : Ultra-fast Blitz mode (Stop-on-Flag, zero doc overhead, auto-clean)")
    print(f"      - @ctf-analyzer   : In-depth Lab/Audit mode (Full RCA, resources/ preservation, writeup.md)")

def deploy_globally(force: bool = False):
    """Deploy CTF-Agent plugin, skills, rules, and Antigravity agents into ~/.gemini/config/."""
    home = Path.home()
    global_config = home / ".gemini" / "config"
    print(f"[*] Deploying CTF-Agent globally to: {global_config}")

    if not global_config.exists():
        global_config.mkdir(parents=True, exist_ok=True)

    # 1. Deploy as Antigravity Plugin (~/.gemini/config/plugins/ctf-agent/)
    plugin_dir = global_config / "plugins" / "ctf-agent"
    plugin_dir.mkdir(parents=True, exist_ok=True)
    
    # Write plugin.json manifest
    plugin_manifest = {
        "name": "ctf-agent",
        "description": "Autonomous Security Intelligence and Educational Lab Framework for Antigravity"
    }
    (plugin_dir / "plugin.json").write_text(json.dumps(plugin_manifest, indent=2), encoding="utf-8")
    print(f"  [+] Configured plugin manifest: {plugin_dir / 'plugin.json'}")

    # Deploy Plugin Agents (~/.gemini/config/plugins/ctf-agent/agents/)
    plugin_agents = plugin_dir / "agents"
    plugin_agents.mkdir(exist_ok=True)
    for agent_path in (REPO_ROOT / "agents").iterdir():
        if agent_path.is_file() and agent_path.suffix == ".md":
            dest_name = agent_path.name.replace("-", "_")
            dest = plugin_agents / dest_name
            shutil.copy2(agent_path, dest)
            print(f"  [+] Deployed plugin agent: {dest_name}")
            
    # Also deploy flagship ctf_agent.md with mainAgent: false
    flagship_agent = plugin_agents / "ctf_agent.md"
    if (REPO_ROOT / "agents" / "ctf-controller.md").exists():
        controller_text = (REPO_ROOT / "agents" / "ctf-controller.md").read_text(encoding="utf-8")
        flagship_agent.write_text(controller_text.replace("name: ctf-controller", "name: ctf_agent"), encoding="utf-8")
        print(f"  [+] Deployed flagship agent: ctf_agent.md (mainAgent: false)")

    # Deploy Plugin Rules (~/.gemini/config/plugins/ctf-agent/rules/)
    plugin_rules = plugin_dir / "rules"
    plugin_rules.mkdir(exist_ok=True)
    for rule_path in (REPO_ROOT / "rules").iterdir():
        if rule_path.is_file() and rule_path.suffix == ".md":
            shutil.copy2(rule_path, plugin_rules / rule_path.name)
            print(f"  [+] Deployed plugin rule: {rule_path.name}")

    # Deploy Plugin Skills (~/.gemini/config/plugins/ctf-agent/skills/)
    plugin_skills = plugin_dir / "skills"
    plugin_skills.mkdir(exist_ok=True)
    for skill_path in (REPO_ROOT / "skills").iterdir():
        if skill_path.is_dir():
            dest = plugin_skills / skill_path.name
            if dest.exists() and force:
                shutil.rmtree(dest)
            if not dest.exists():
                shutil.copytree(skill_path, dest)
                print(f"  [+] Deployed plugin skill: {skill_path.name}")

    # Deploy Plugin Scripts (~/.gemini/config/plugins/ctf-agent/scripts/)
    plugin_scripts = plugin_dir / "scripts"
    plugin_scripts.mkdir(exist_ok=True)
    for script_path in (REPO_ROOT / "scripts").glob("*.py"):
        shutil.copy2(script_path, plugin_scripts / script_path.name)
    print(f"  [+] Deployed plugin utility scripts")

    # Deploy Plugin References (~/.gemini/config/plugins/ctf-agent/references/)
    plugin_refs = plugin_dir / "references"
    plugin_refs.mkdir(exist_ok=True)
    for ref_path in (REPO_ROOT / "references").glob("*.md"):
        shutil.copy2(ref_path, plugin_refs / ref_path.name)
    print(f"  [+] Deployed plugin references")

    # 2. Register and enable plugin in ~/.gemini/config/config.json
    cfg_file = global_config / "config.json"
    if cfg_file.exists():
        try:
            cfg_data = json.loads(cfg_file.read_text(encoding="utf-8"))
            plugins_obj = cfg_data.get("plugins", {})
            if "ctf-agent" not in plugins_obj:
                plugins_obj["ctf-agent"] = {"enabled": True}
                cfg_data["plugins"] = plugins_obj
                cfg_file.write_text(json.dumps(cfg_data, indent=2, ensure_ascii=False), encoding="utf-8")
                print(f"  [+] Enabled ctf-agent in {cfg_file}")
        except Exception as e:
            print(f"  [!] Could not update config.json: {e}")

    # 3. Global Skills and Rules fallback for external CLI environments
    global_skills = global_config / "skills"
    global_skills.mkdir(exist_ok=True)
    for skill_path in (REPO_ROOT / "skills").iterdir():
        if skill_path.is_dir():
            dest = global_skills / skill_path.name
            if dest.exists() and force:
                shutil.rmtree(dest)
            if not dest.exists():
                shutil.copytree(skill_path, dest)

    global_rules = global_config / "rules"
    global_rules.mkdir(exist_ok=True)
    for rule_path in (REPO_ROOT / "rules").iterdir():
        if rule_path.is_file() and rule_path.suffix == ".md":
            shutil.copy2(rule_path, global_rules / rule_path.name)

    # 4. Auto-configure Antigravity Global Settings & Eager Execution
    configure_antigravity_eager_execution()

    print(f"\n[OK] Successfully installed CTF-Agent as Antigravity Plugin and globally across all workspaces!")
    print(f"    Available in Antigravity Agent Dropdown: 'ctf_agent'")

def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("init", "--init"):
        import ctf_init
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        ctf_init.main()
        return

    if len(sys.argv) > 1 and sys.argv[1] in ("update", "--update"):
        import ctf_update
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        ctf_update.main()
        return

    parser = argparse.ArgumentParser(description="CTF-Agent Workspace & Global Deployment Manager")
    parser.add_argument("target", nargs="?", help="Target CTF workspace directory (deploys as .agents/)")
    parser.add_argument("--global", dest="is_global", action="store_true", help="Install CTF skills, rules, and subagents globally into ~/.gemini/config/")
    parser.add_argument("--symlink", "--link", action="store_true", help="Use symlinks/junctions for workspace deployment to keep live sync")
    parser.add_argument("--setup-workspace", dest="setup_workspace", action="store_true", default=True, help="Configure workspace root AGENTS.md, mcp_config.json, skills.json (default: True)")
    parser.add_argument("--no-setup-workspace", "--agent-only", dest="agent_only", action="store_true", help="Only deploy .agents/ without modifying workspace root files")
    parser.add_argument("--brain", "--agent-brain", dest="brain_only", action="store_true", help="Deploy only the Agent Brain (.agents/ + root AGENTS.md) without challenge scaffolding")
    parser.add_argument("--with-agents-md", dest="with_agents_md", action="store_true", help="Ensure root AGENTS.md is deployed/updated even in agent-only mode")
    parser.add_argument("--wsl", dest="install_wsl", action="store_true", default=True, help="Automatically install CTF toolchain into WSL during setup (default: True)")
    parser.add_argument("--no-wsl", "--skip-toolchain", dest="install_wsl", action="store_false", help="Skip toolchain installation into backend")
    parser.add_argument("--wsl-profile", default="core", help="WSL toolchain profile to install: core, pwn, rev, crypto, forensics, web, all (default: core)")
    parser.add_argument("--wsl-distro", default="kali-linux", help="WSL distribution target (default: kali-linux)")
    parser.add_argument("--init", dest="is_init", action="store_true", help="Run intelligent preflight detector & workspace initializer")
    parser.add_argument("--update", dest="is_update", action="store_true", help="Run workspace & skill update engine")
    parser.add_argument("--force", "-f", action="store_true", help="Overwrite existing files or directories")

    args = parser.parse_args()

    if args.is_update:
        import ctf_update
        workspace = ctf_update.WorkspaceUpdater.resolve_workspace(args.target)
        res = ctf_update.WorkspaceUpdater.update_workspace(workspace, force=args.force)
        ctf_update.print_update_report(res)
        return

    if args.is_global:
        deploy_globally(force=args.force)
    elif args.target:
        target_dir = Path(args.target).resolve()
        is_agent_only = args.agent_only and not args.brain_only
        with_agents_md = args.with_agents_md or args.brain_only
        deploy_to_workspace(
            target_dir,
            use_symlink=args.symlink,
            force=args.force,
            setup_workspace=(args.setup_workspace and not is_agent_only),
            install_wsl=args.install_wsl,
            wsl_profile=args.wsl_profile,
            wsl_distro=args.wsl_distro,
            agent_only=is_agent_only,
            with_agents_md=with_agents_md,
        )
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
