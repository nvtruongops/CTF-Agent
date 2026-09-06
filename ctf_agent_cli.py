#!/usr/bin/env python3
"""
CTF-Agent Universal CLI Entrypoint
Enables command line execution via uvx, pipx, and setuptools console scripts.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

try:
    from scripts.ctf_init import main as ctf_init_main
except ImportError:
    try:
        from ctf_init import main as ctf_init_main
    except ImportError:
        import importlib.util
        init_py = SCRIPTS_DIR / "ctf_init.py"
        if init_py.exists():
            spec = importlib.util.spec_from_file_location("ctf_init", str(init_py))
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                ctf_init_main = module.main
            else:
                raise ImportError(f"Unable to load ctf_init from {init_py}")
        else:
            raise ImportError(f"ctf_init.py not found at {init_py}")


def main():
    """Main CLI entrypoint normalizing subcommand arguments for ctf_init."""
    args = sys.argv[1:]
    if args and args[0] == "init":
        sys.argv = [sys.argv[0]] + args[1:]
    ctf_init_main()


if __name__ == "__main__":
    main()
