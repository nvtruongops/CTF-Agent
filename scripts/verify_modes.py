#!/usr/bin/env python3
"""
CTF-Agent Dual Modes End-to-End Verification Suite
Validates all mode logic, scripts, agent definitions, and workspace sanitation.
"""

import os
import sys
import tempfile
import shutil
import subprocess
from pathlib import Path

# Ensure UTF-8 output on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

REPO_ROOT = Path(__file__).resolve().parent.parent

def test_extract_flags():
    print("[*] Testing extract_flags.py banner & JSON...")
    # Test 1: Flag detection with banner
    cmd = [sys.executable, str(REPO_ROOT / "scripts" / "extract_flags.py"), "Well done: picoCTF{speedrun_test_flag_99}", "--banner"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0, f"extract_flags banner failed: {res.stderr}"
    assert "FLAG ACQUIRED: picoCTF{speedrun_test_flag_99}" in res.stdout, f"Banner mismatch: {res.stdout}"

    # Test 2: JSON output and exit-code
    cmd_json = [sys.executable, str(REPO_ROOT / "scripts" / "extract_flags.py"), "flag{json_mode_pass}", "--json", "--exit-code"]
    res_json = subprocess.run(cmd_json, capture_output=True, text=True)
    assert res_json.returncode == 0
    assert '"success": true' in res_json.stdout
    assert "flag{json_mode_pass}" in res_json.stdout

    # Test 3: Negative lookbehind prevents picoCTF being truncated to CTF
    cmd_pico = [sys.executable, str(REPO_ROOT / "scripts" / "extract_flags.py"), "picoCTF{valid_flag}", "--json"]
    res_pico = subprocess.run(cmd_pico, capture_output=True, text=True)
    assert '"top_flag": "picoCTF{valid_flag}"' in res_pico.stdout

    print("  [OK] extract_flags.py passed all tests.")

def test_workspace_cleaner():
    print("[*] Testing workspace_cleaner.py fast vs deep...")
    tmp = Path(tempfile.mkdtemp())
    try:
        # Populate scratch files
        (tmp / "test_sqli.py").write_text("# scratch")
        (tmp / "fuzz.py").write_text("# fuzzer")
        (tmp / "payload.bin").write_bytes(b"\x90" * 20)
        (tmp / "core.1234").write_bytes(b"\x00" * 100)
        (tmp / "solve.py").write_text("# final solve")
        (tmp / "vuln_service").write_bytes(b"\x7fELF")

        # 1. Fast cleanup
        cmd_fast = [sys.executable, str(REPO_ROOT / "scripts" / "workspace_cleaner.py"), str(tmp), "--fast"]
        res_fast = subprocess.run(cmd_fast, capture_output=True, text=True)
        assert res_fast.returncode == 0

        remaining = {p.name for p in tmp.iterdir()}
        assert remaining == {"solve.py", "vuln_service"}, f"Unexpected files after fast clean: {remaining}"

        # 2. Deep organize
        (tmp / "writeup.md").write_text("# Writeup")
        cmd_deep = [sys.executable, str(REPO_ROOT / "scripts" / "workspace_cleaner.py"), str(tmp), "--deep"]
        res_deep = subprocess.run(cmd_deep, capture_output=True, text=True)
        assert res_deep.returncode == 0

        final_root = {p.name for p in tmp.iterdir()}
        assert final_root == {"writeup.md", "solve.py", "resources"}, f"Unexpected root structure: {final_root}"
        resources = {p.name for p in (tmp / "resources").iterdir()}
        assert "vuln_service" in resources, "Original binary not organized into resources/"

        print("  [OK] workspace_cleaner.py passed fast & deep tests.")
    finally:
        shutil.rmtree(tmp)

def test_agent_definitions():
    print("[*] Testing agent YAML definitions...")
    agents_dir = REPO_ROOT / "agents"
    assert agents_dir.exists(), "agents directory missing"

    speedrun = agents_dir / "ctf-speedrun.md"
    analyzer = agents_dir / "ctf-analyzer.md"
    assert speedrun.exists(), "ctf-speedrun.md missing"
    assert analyzer.exists(), "ctf-analyzer.md missing"

    sr_content = speedrun.read_text(encoding="utf-8")
    assert "name: ctf-speedrun" in sr_content
    assert "Stop-on-Flag" in sr_content
    assert "workspace_cleaner.py --fast" in sr_content

    an_content = analyzer.read_text(encoding="utf-8")
    assert "name: ctf-analyzer" in an_content
    assert "Root Cause Analysis" in an_content
    assert "writeup.md" in an_content

    print("  [OK] Agent definitions verified.")

def test_distribution():
    print("[*] Testing .agents distribution manager...")
    tmp = Path(tempfile.mkdtemp())
    try:
        cmd = [sys.executable, str(REPO_ROOT / "scripts" / "install_as_agent.py"), str(tmp)]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 0, f"install_as_agent failed: {res.stderr}"

        dot_agents = tmp / ".agents"
        assert (dot_agents / "agents" / "ctf-speedrun.md").exists()
        assert (dot_agents / "agents" / "ctf-analyzer.md").exists()
        assert (dot_agents / "skills" / "solve-challenge" / "SKILL.md").exists()
        assert (dot_agents / "rules" / "ctf-execution-rules.md").exists()
        assert (dot_agents / "scripts" / "workspace_cleaner.py").exists()

        print("  [OK] Distribution manager successfully verified.")
    finally:
        shutil.rmtree(tmp)

def main():
    print("=== CTF-Agent Dual Modes Verification Suite ===")
    test_extract_flags()
    test_workspace_cleaner()
    test_agent_definitions()
    test_distribution()
    print("\n[SUCCESS] All dual-mode components verified with 0 errors!")

if __name__ == "__main__":
    main()
