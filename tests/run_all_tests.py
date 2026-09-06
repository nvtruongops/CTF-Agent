#!/usr/bin/env python3
"""
CTF-Agent Local Integrity & Validation Test Runner
--------------------------------------------------
Runs all local verification tests:
  1. 100% English documentation check (0 Vietnamese characters)
  2. 0 decorative emojis / icons across repo
  3. All markdown relative links point to existing files
  4. Prompt Policy Sanitizer logic & link protection
  5. Repository structural integrity (agents, skills, rules, gitignore)

Usage:
  python tests/run_all_tests.py
  python -m pytest tests/ -v
"""

import sys
import subprocess
from pathlib import Path

# Ensure safe UTF-8 terminal encoding on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

REPO_ROOT = Path(__file__).resolve().parent.parent

def main():
    print("=" * 65)
    print("CTF-AGENT LOCAL INTEGRITY & VALIDATION SUITE")
    print("=" * 65)
    
    try:
        import pytest
        print("[*] Running test suite via pytest...")
        exit_code = pytest.main([str(REPO_ROOT / "tests"), "-v", "--tb=short"])
        if exit_code == 0:
            print("\n" + "=" * 65)
            print("[OK] ALL REPOSITORY VALIDATION TESTS PASSED SUCCESSFULLY!")
            print("=" * 65)
        sys.exit(exit_code)
    except ImportError:
        print("[!] pytest not found, running tests via unittest discovery...")
        import unittest
        loader = unittest.TestLoader()
        suite = loader.discover(str(REPO_ROOT / "tests"))
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        if result.wasSuccessful():
            print("\n" + "=" * 65)
            print("[OK] ALL REPOSITORY VALIDATION TESTS PASSED SUCCESSFULLY!")
            print("=" * 65)
            sys.exit(0)
        else:
            sys.exit(1)

if __name__ == "__main__":
    main()
