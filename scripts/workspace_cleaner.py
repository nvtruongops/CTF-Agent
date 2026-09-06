#!/usr/bin/env python3
"""
CTF Workspace Cleaner & Environment Sanitizer (v1.3)
Cleans up temporary scratch scripts, ephemeral payloads, core dumps, and compiles artifacts.
Supports two modes:
  --fast / --blitz: Quick sweep of temporary scratch/test files while preserving the winning solve script and original challenge assets.
  --deep / --organize: Enforces the ctf-writeup standard directory structure (writeup.md, solve.py, resources/).
"""

import os
import sys
import shutil
import argparse
from pathlib import Path
from typing import List, Set

# Ensure safe UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ephemeral file patterns generated during rapid exploitation
EPHEMERAL_PATTERNS = [
    "test*.py",
    "test_*.py",
    "tmp*",
    "temp*",
    "*_tmp.py",
    "scratch*",
    "fuzz*.py",
    "fuzz*.txt",
    "payload*.bin",
    "payload*.txt",
    "exploit_tmp*.py",
    "core",
    "core.*",
    "vgcore.*",
    "gmon.out",
    "*.pyc",
    "*.swp",
    "*~",
    "*.o",
    "*.out",
    "peda-session-*",
    ".gdb_history",
]

# Essential files that must NEVER be deleted in fast mode
PROTECTED_FILES = {
    "solve.py",
    "writeup.md",
    "Dockerfile",
    "docker-compose.yml",
    "requirements.txt",
}

def clean_ephemeral_files(target_dir: Path, dry_run: bool = False) -> List[Path]:
    """Identify and remove scratch/temporary files from target directory."""
    deleted_files = []
    
    for pattern in EPHEMERAL_PATTERNS:
        for p in target_dir.glob(pattern):
            if p.is_file() and p.name not in PROTECTED_FILES:
                deleted_files.append(p)
                if not dry_run:
                    try:
                        p.unlink()
                    except Exception as e:
                        print(f"[!] Warning: Could not delete {p.name}: {e}")
            elif p.is_dir() and p.name == "__pycache__":
                deleted_files.append(p)
                if not dry_run:
                    try:
                        shutil.rmtree(p)
                    except Exception as e:
                        print(f"[!] Warning: Could not delete {p.name}: {e}")
                        
    return deleted_files

def organize_deep_directory(target_dir: Path, dry_run: bool = False) -> List[Path]:
    """Organize workspace into writeup.md, solve.py, and resources/ folder."""
    resources_dir = target_dir / "resources"
    moved_files = []

    if not dry_run:
        resources_dir.mkdir(exist_ok=True)

    # First clean ephemeral debris
    clean_ephemeral_files(target_dir, dry_run=dry_run)

    for item in target_dir.iterdir():
        if item == resources_dir or item.name in PROTECTED_FILES or item.name.startswith("."):
            continue

        moved_files.append(item)
        if not dry_run:
            dest = resources_dir / item.name
            try:
                if dest.exists():
                    if item.is_dir():
                        shutil.rmtree(dest)
                    else:
                        dest.unlink()
                shutil.move(str(item), str(dest))
            except Exception as e:
                print(f"[!] Warning: Could not move {item.name} to resources/: {e}")

    return moved_files

def main():
    parser = argparse.ArgumentParser(description="CTF Workspace Sanitizer & Cleaner")
    parser.add_argument("directory", nargs="?", default=".", help="Target workspace directory (default: current directory)")
    parser.add_argument("--fast", "--blitz", action="store_true", help="Fast mode: wipe scratch/debris files, preserve challenge & solve.py")
    parser.add_argument("--deep", "--organize", action="store_true", help="Deep mode: enforce resources/ directory structure")
    parser.add_argument("--dry-run", action="store_true", help="List files that would be cleaned without deleting")
    parser.add_argument("--quiet", "-q", action="store_true", help="Quiet output")

    args = parser.parse_args()
    target = Path(args.directory).resolve()

    if not target.is_dir():
        print(f"[-] Error: {target} is not a valid directory.")
        sys.exit(1)

    if args.deep:
        moved = organize_deep_directory(target, dry_run=args.dry_run)
        if not args.quiet:
            prefix = "[DRY-RUN] Would organize" if args.dry_run else "[+] Deep organized"
            print(f"{prefix} {len(moved)} item(s) into resources/ inside {target.name}")
    else:
        # Default is fast cleanup
        removed = clean_ephemeral_files(target, dry_run=args.dry_run)
        if not args.quiet:
            prefix = "[DRY-RUN] Would remove" if args.dry_run else "[+] Cleaned"
            print(f"{prefix} {len(removed)} temporary scratch/debris file(s) in {target.name}")

if __name__ == "__main__":
    main()
