#!/usr/bin/env python3
"""
CTF-Agent Universal Multi-Agent Adapter Engine
---------------------------------------------
Generates thin, native configuration pointers and adapters for diverse AI coding agents
(Claude Code, Cursor, Windsurf, GitHub Copilot, OpenAI Codex, Aider), establishing
AGENTS.md and mcp_config.json as the Universal Single Source of Truth (SSOT).

Supported Agent Runtimes:
  - antigravity : Google Gemini Antigravity IDE (native AGENTS.md + .agents/ brain)
  - claude      : Anthropic Claude Code (CLAUDE.md + .mcp.json)
  - cursor      : Cursor IDE (.cursorrules + .cursor/rules/ctf-agent.mdc + .cursor/mcp.json)
  - windsurf    : Codeium Windsurf (.windsurfrules)
  - copilot     : GitHub Copilot Workspace (.github/copilot-instructions.md)
  - aider       : Aider CLI (.aider.conf.yml)
  - all         : Deploy all adapter pointers simultaneously
"""

import sys
import json
import argparse
from pathlib import Path
from typing import Dict, List, Optional

# Ensure safe UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

SUPPORTED_AGENTS = ["antigravity", "claude", "cursor", "windsurf", "copilot", "aider", "all"]


class MultiAgentAdapter:
    """Configures workspace pointers for various AI coding agents to reference AGENTS.md."""

    def __init__(self, workspace_path: Path):
        self.workspace_path = workspace_path.resolve()

    def deploy_claude_adapter(self, dry_run: bool = False) -> List[Path]:
        """Deploy CLAUDE.md and .mcp.json for Anthropic Claude Code."""
        created = []
        claude_md = self.workspace_path / "CLAUDE.md"
        content_claude_md = (
            "# Claude Code CTF Integration\n\n"
            "This repository uses the CTF-Agent universal operational architecture.\n"
            "All security lab, CTF triage, execution boundaries, and toolfallbacks are defined in:\n"
            "- [AGENTS.md](AGENTS.md)\n\n"
            "## Primary Guidelines:\n"
            "1. Strictly adhere to the 4-tier triage ladder in `references/ctf-triage-ladder.md`.\n"
            "2. Execute native Linux binaries, gdb, and pwntools via WSL Kali Linux.\n"
            "3. Use diagnostic academic framing (PoC, RCA) to prevent safety policy triggers.\n"
            "4. Keep original challenge assets read-only; clean scratch scripts with `workspace_cleaner.py`.\n"
        )
        if not dry_run:
            claude_md.write_text(content_claude_md, encoding="utf-8")
        created.append(claude_md)

        # Deploy .mcp.json if mcp_config.json exists
        mcp_src = self.workspace_path / "mcp_config.json"
        if mcp_src.is_file():
            mcp_dest = self.workspace_path / ".mcp.json"
            if not dry_run:
                try:
                    data = json.loads(mcp_src.read_text(encoding="utf-8"))
                    # Claude format: {"mcpServers": {...}}
                    mcp_payload = {"mcpServers": data.get("mcpServers", data)}
                    mcp_dest.write_text(json.dumps(mcp_payload, indent=2), encoding="utf-8")
                    created.append(mcp_dest)
                except Exception as e:
                    print(f"  [!] Warning: Could not generate .mcp.json: {e}")

        return created

    def deploy_cursor_adapter(self, dry_run: bool = False) -> List[Path]:
        """Deploy .cursorrules and .cursor/rules/ctf-agent.mdc for Cursor."""
        created = []
        cursor_rules = self.workspace_path / ".cursorrules"
        content_cursorrules = (
            "# Cursor AI CTF Agent Rules\n\n"
            "Follow the comprehensive operational constitution in [AGENTS.md](AGENTS.md).\n"
            "- Active operational modes: --blitz (fast time-to-flag) vs --deep (RCA + writeup.md).\n"
            "- Never run native Linux ELF binaries on Windows; execute via WSL Kali Linux.\n"
            "- Validate flags against platform regex before asserting completion.\n"
        )
        if not dry_run:
            cursor_rules.write_text(content_cursorrules, encoding="utf-8")
        created.append(cursor_rules)

        # Modern Cursor rules directory (.cursor/rules/)
        rules_dir = self.workspace_path / ".cursor" / "rules"
        mdc_file = rules_dir / "ctf-agent.mdc"
        content_mdc = (
            "---\n"
            "description: CTF Agent Autonomous Security Rules & Triage\n"
            "globs: *\n"
            "---\n\n"
            "# CTF Agent Rules\n\n"
            "Read and strictly enforce [AGENTS.md](AGENTS.md) for all security tasks.\n"
        )
        if not dry_run:
            rules_dir.mkdir(parents=True, exist_ok=True)
            mdc_file.write_text(content_mdc, encoding="utf-8")
        created.append(mdc_file)

        return created

    def deploy_windsurf_adapter(self, dry_run: bool = False) -> List[Path]:
        """Deploy .windsurfrules for Codeium Windsurf."""
        created = []
        windsurf_file = self.workspace_path / ".windsurfrules"
        content = (
            "# Windsurf CTF Operational Rules\n\n"
            "Refer to [AGENTS.md](AGENTS.md) for core CTF triage, safety framing, and environment isolation.\n"
            "- Triage: Plaintext/Trivial -> Textbook -> Exploit Chains -> Advanced Meta.\n"
            "- Tools: WSL Kali Linux for ELF/GDB execution.\n"
            "- Documentation: Author standard 5-section writeup.md in --deep mode.\n"
        )
        if not dry_run:
            windsurf_file.write_text(content, encoding="utf-8")
        created.append(windsurf_file)
        return created

    def deploy_copilot_adapter(self, dry_run: bool = False) -> List[Path]:
        """Deploy .github/copilot-instructions.md for GitHub Copilot."""
        created = []
        github_dir = self.workspace_path / ".github"
        copilot_file = github_dir / "copilot-instructions.md"
        content = (
            "# GitHub Copilot Instructions for CTF-Agent\n\n"
            "When assisting in this CTF competition workspace, adhere strictly to [AGENTS.md](../AGENTS.md).\n"
            "- Use diagnostic, educational CTF framing to comply with safety filters.\n"
            "- Isolate payloads and solver scripts into solve.py.\n"
            "- Clean scratch files using python3 scripts/workspace_cleaner.py.\n"
        )
        if not dry_run:
            github_dir.mkdir(parents=True, exist_ok=True)
            copilot_file.write_text(content, encoding="utf-8")
        created.append(copilot_file)
        return created

    def deploy_aider_adapter(self, dry_run: bool = False) -> List[Path]:
        """Deploy .aider.conf.yml for Aider CLI."""
        created = []
        aider_conf = self.workspace_path / ".aider.conf.yml"
        content = (
            "# Aider Configuration for CTF-Agent\n"
            "read:\n"
            "  - AGENTS.md\n"
            "auto-commits: false\n"
            "attribute-author: false\n"
        )
        if not dry_run:
            aider_conf.write_text(content, encoding="utf-8")
        created.append(aider_conf)
        return created

    def deploy(self, agent_name: str, dry_run: bool = False) -> Dict[str, List[Path]]:
        """Deploys adapter for specified agent name or 'all'."""
        results: Dict[str, List[Path]] = {}
        target = agent_name.lower()

        if target in ("claude", "all"):
            results["claude"] = self.deploy_claude_adapter(dry_run=dry_run)
        if target in ("cursor", "all"):
            results["cursor"] = self.deploy_cursor_adapter(dry_run=dry_run)
        if target in ("windsurf", "all"):
            results["windsurf"] = self.deploy_windsurf_adapter(dry_run=dry_run)
        if target in ("copilot", "all"):
            results["copilot"] = self.deploy_copilot_adapter(dry_run=dry_run)
        if target in ("aider", "all"):
            results["aider"] = self.deploy_aider_adapter(dry_run=dry_run)
        if target in ("antigravity", "all"):
            # Antigravity natively reads root AGENTS.md and .agents/
            results["antigravity"] = [self.workspace_path / "AGENTS.md"]

        return results


def main():
    parser = argparse.ArgumentParser(description="CTF-Agent Universal Multi-Agent Adapter Engine")
    parser.add_argument(
        "--agent", "-a",
        choices=SUPPORTED_AGENTS,
        default="all",
        help="Target AI agent runtime adapter to configure (default: all)",
    )
    parser.add_argument(
        "--workspace", "-w",
        default=".",
        help="Target workspace directory (default: current directory)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List files that would be generated without writing to disk",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all supported AI agent runtimes",
    )

    args = parser.parse_args()

    if args.list:
        print("Supported AI Coding Agent Runtimes:")
        print("  - antigravity : Google Gemini Antigravity IDE (native AGENTS.md + .agents/)")
        print("  - claude      : Anthropic Claude Code (CLAUDE.md + .mcp.json)")
        print("  - cursor      : Cursor IDE (.cursorrules + .cursor/rules/ctf-agent.mdc)")
        print("  - windsurf    : Codeium Windsurf (.windsurfrules)")
        print("  - copilot     : GitHub Copilot Workspace (.github/copilot-instructions.md)")
        print("  - aider       : Aider CLI (.aider.conf.yml)")
        print("  - all         : Generate adapters for all agents simultaneously")
        sys.exit(0)

    target_dir = Path(args.workspace).resolve()
    if not target_dir.is_dir():
        print(f"[-] Error: {target_dir} is not a valid directory.")
        sys.exit(1)

    adapter = MultiAgentAdapter(target_dir)
    res = adapter.deploy(args.agent, dry_run=args.dry_run)

    action_label = "[DRY-RUN] Would configure" if args.dry_run else "[+] Configured"
    print("=" * 65)
    print(f"{action_label} Multi-Agent Adapters in: {target_dir.name}")
    print("=" * 65)
    for agent, files in res.items():
        print(f"  Agent: {agent.upper()}")
        for f in files:
            rel = f.relative_to(target_dir) if f.is_relative_to(target_dir) else f.name
            print(f"    - {rel}")
    print("=" * 65)
    print("Single Source of Truth: AGENTS.md")


if __name__ == "__main__":
    main()
