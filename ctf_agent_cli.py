#!/usr/bin/env python3
"""
CTF-Agent Universal CLI Entrypoint
Enables command line execution via uvx, pipx, and setuptools console scripts.
Dispatches subcommands: 'init' (preflight & scaffolding) and 'update' (skill & workspace sync).
"""

import sys
import importlib.util
from pathlib import Path

__version__ = "1.3.4"

REPO_ROOT = Path(__file__).resolve().parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))


def _load_entrypoint(module_name: str, file_name: str):
    try:
        mod = __import__(f"scripts.{module_name}", fromlist=["main"])
        return mod.main
    except ImportError:
        try:
            mod = __import__(module_name, fromlist=["main"])
            return mod.main
        except ImportError:
            script_path = SCRIPTS_DIR / file_name
            if script_path.exists():
                spec = importlib.util.spec_from_file_location(module_name, str(script_path))
                if spec and spec.loader:
                    m = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(m)
                    return m.main
            raise ImportError(f"Unable to load {module_name} from {script_path}")


def main():
    """Main CLI dispatcher routing subcommands."""
    args = sys.argv[1:]

    if args and args[0] in ("-v", "--version", "version"):
        print(f"ctf-agent v{__version__}")
        sys.exit(0)

    if args and args[0] == "update":
        sys.argv = [sys.argv[0]] + args[1:]
        updater = _load_entrypoint("ctf_update", "ctf_update.py")
        updater()
    elif args and args[0] in ("validate-skill", "check-skill", "check-skills", "audit-skill"):
        sys.argv = [sys.argv[0]] + args[1:]
        validator = _load_entrypoint("skill_validator", "skill_validator.py")
        validator()
    elif args and args[0] in ("triage", "parallel-triage"):
        sys.argv = [sys.argv[0]] + args[1:]
        triage = _load_entrypoint("parallel_triage", "parallel_triage.py")
        triage()
    elif args and args[0] in ("scope-guard", "guard"):
        sys.argv = [sys.argv[0]] + args[1:]
        guard = _load_entrypoint("scope_guard", "scope_guard.py")
        guard()
    elif args and args[0] in ("clean", "clean-workspace", "sanitize"):
        sys.argv = [sys.argv[0]] + args[1:]
        cleaner = _load_entrypoint("workspace_cleaner", "workspace_cleaner.py")
        cleaner()
    elif args and args[0] in ("cve", "cve-lookup"):
        sys.argv = [sys.argv[0]] + args[1:]
        cve_util = _load_entrypoint("cve_lookup", "cve_lookup.py")
        cve_util()
    elif args and args[0] in ("ci", "test", "check"):
        sys.argv = [sys.argv[0]] + args[1:]
        ci_runner = _load_entrypoint("local_ci", "local_ci.py")
        ci_runner()
    elif args and args[0] == "init":
        sys.argv = [sys.argv[0]] + args[1:]
        initializer = _load_entrypoint("ctf_init", "ctf_init.py")
        initializer()
    else:
        initializer = _load_entrypoint("ctf_init", "ctf_init.py")
        initializer()


if __name__ == "__main__":
    main()
