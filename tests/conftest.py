import os
import pytest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

EXCLUDED_DIRS = {".git", "tests", ".pytest_cache", "__pycache__", "venv", ".venv", "env", ".gemini", ".codegraph", "node_modules"}

@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT

@pytest.fixture(scope="session")
def markdown_files() -> list[Path]:
    md_files = []
    for root, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for f in files:
            if f.endswith(".md"):
                md_files.append(Path(root) / f)
    return md_files

@pytest.fixture(scope="session")
def all_repo_files() -> list[Path]:
    targets = []
    for root, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for f in files:
            if f.endswith((".md", ".py", ".sh", ".json", ".yaml", ".yml")):
                targets.append(Path(root) / f)
    return targets
