import sys
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from workspace_cleaner import clean_ephemeral_files, organize_deep_directory


def test_clean_ephemeral_files_at_root(tmp_path: Path):
    # Setup files in workspace root
    (tmp_path / "test_exploit.py").write_text("print('test')")
    (tmp_path / "tmp_payload.txt").write_text("payload")
    (tmp_path / "fuzz_target.py").write_text("fuzzing")
    (tmp_path / "solve.py").write_text("print('flag')")
    (tmp_path / "writeup.md").write_text("# Writeup")
    (tmp_path / "chall.py").write_text("# Challenge source")

    removed = clean_ephemeral_files(tmp_path, clean_resources=False)
    removed_names = {p.name for p in removed}

    assert "test_exploit.py" in removed_names
    assert "tmp_payload.txt" in removed_names
    assert "fuzz_target.py" in removed_names
    assert "solve.py" not in removed_names
    assert "writeup.md" not in removed_names
    assert (tmp_path / "solve.py").exists()
    assert (tmp_path / "writeup.md").exists()
    assert (tmp_path / "chall.py").exists()


def test_clean_ephemeral_files_inside_resources(tmp_path: Path):
    resources_dir = tmp_path / "resources"
    resources_dir.mkdir()

    # Create original challenge assets inside resources
    (resources_dir / "chall.py").write_text("# Original challenge")
    (resources_dir / "param.txt").write_text("p = 12345")
    (resources_dir / "server.py").write_text("# Server")

    # Create debris inside resources
    (resources_dir / "test_1query.py").write_text("# test script")
    (resources_dir / "bing_search.py").write_text("# search script")
    (resources_dir / "explore_target.py").write_text("# explore script")
    (resources_dir / "tmp_test.py").write_text("# tmp script")

    removed = clean_ephemeral_files(tmp_path, clean_resources=True)
    removed_names = {p.name for p in removed}

    assert "test_1query.py" in removed_names
    assert "bing_search.py" in removed_names
    assert "explore_target.py" in removed_names
    assert "tmp_test.py" in removed_names

    # Ensure protected assets remain
    assert (resources_dir / "chall.py").exists()
    assert (resources_dir / "param.txt").exists()
    assert (resources_dir / "server.py").exists()


def test_organize_deep_directory(tmp_path: Path):
    (tmp_path / "chall.py").write_text("# Challenge")
    (tmp_path / "test_debris.py").write_text("# Debris")
    (tmp_path / "solve.py").write_text("# Solve")
    (tmp_path / "writeup.md").write_text("# Writeup")

    moved = organize_deep_directory(tmp_path, clean_resources=True)

    # Debris should be deleted
    assert not (tmp_path / "test_debris.py").exists()
    assert not (tmp_path / "resources" / "test_debris.py").exists()

    # Solve and writeup stay at root
    assert (tmp_path / "solve.py").exists()
    assert (tmp_path / "writeup.md").exists()

    # Challenge asset moved to resources
    assert (tmp_path / "resources" / "chall.py").exists()
