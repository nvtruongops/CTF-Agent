import sys
import subprocess
import json
import shutil
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from ctf_init import (
    EnvironmentDetector,
    CapabilityScoringEngine,
    PURPOSE_PROFILES,
    HealthCheckRunner,
    WorkspaceProvisioner,
)


def test_detect_os_structure():
    os_info = EnvironmentDetector.detect_os()
    assert "system" in os_info
    assert "arch" in os_info
    assert "cpu_cores" in os_info
    assert isinstance(os_info["cpu_cores"], int)
    assert os_info["cpu_cores"] >= 1
    assert "is_windows" in os_info
    assert "is_linux" in os_info


def test_detect_memory_non_negative():
    mem = EnvironmentDetector.detect_memory()
    assert "total_gb" in mem
    assert "avail_gb" in mem
    assert mem["total_gb"] >= 0.0
    assert mem["avail_gb"] >= 0.0


def test_detect_disk_positive():
    disk = EnvironmentDetector.detect_disk(REPO_ROOT)
    assert "total_gb" in disk
    assert "free_gb" in disk
    assert disk["free_gb"] > 0.0


def test_purpose_profiles_contain_required_presets():
    expected_keys = ["live-ctf", "security-lab", "rev-pwn", "full"]
    for k in expected_keys:
        assert k in PURPOSE_PROFILES
        preset = PURPOSE_PROFILES[k]
        assert "title" in preset
        assert "description" in preset
        assert "profiles" in preset
        assert len(preset["profiles"]) > 0


def test_scoring_windows_with_kali():
    mock_env = {
        "os": {
            "system": "Windows",
            "is_windows": True,
            "is_linux": False,
            "is_macos": False,
        },
        "wsl": {
            "available": True,
            "kali_present": True,
            "kali_running": True,
            "wsl2_supported": True,
        },
        "docker": {
            "available": True,
            "daemon_running": False,
        },
        "disk": {"free_gb": 100.0},
        "memory": {"total_gb": 16.0},
    }
    scoring = CapabilityScoringEngine.calculate_scores(mock_env)
    assert scoring["recommended"] == "wsl"
    assert scoring["distro_target"] == "kali-linux"
    assert scoring["wsl_score"] >= 10
    assert scoring["docker_score"] < scoring["wsl_score"]


def test_scoring_linux_with_docker():
    mock_env = {
        "os": {
            "system": "Linux",
            "is_windows": False,
            "is_linux": True,
            "is_macos": False,
        },
        "wsl": {
            "available": False,
            "kali_present": False,
            "kali_running": False,
            "wsl2_supported": False,
        },
        "docker": {
            "available": True,
            "daemon_running": True,
        },
        "disk": {"free_gb": 80.0},
        "memory": {"total_gb": 16.0},
    }
    scoring = CapabilityScoringEngine.calculate_scores(mock_env)
    assert scoring["recommended"] == "docker"
    assert scoring["wsl_score"] == 0
    assert scoring["docker_score"] >= 8


def test_scoring_low_disk_penalty():
    mock_env = {
        "os": {
            "system": "Windows",
            "is_windows": True,
            "is_linux": False,
            "is_macos": False,
        },
        "wsl": {
            "available": True,
            "kali_present": True,
            "kali_running": False,
            "wsl2_supported": True,
        },
        "docker": {
            "available": False,
            "daemon_running": False,
        },
        "disk": {"free_gb": 5.0},  # Low storage
        "memory": {"total_gb": 4.0},
    }
    scoring = CapabilityScoringEngine.calculate_scores(mock_env)
    assert any("Storage low" in f for f in scoring["wsl_factors"])


def test_health_check_runner_structure(tmp_path: Path):
    report = HealthCheckRunner.check_workspace(tmp_path, backend="none", distro="")
    assert "workspace" in report
    assert "checks" in report
    assert isinstance(report["checks"], list)
    assert not report["all_passed"]  # Empty tmp_path fails checks


def test_cli_dry_run():
    script_path = REPO_ROOT / "scripts" / "ctf_init.py"
    res = subprocess.run(
        [sys.executable, str(script_path), "--dry-run"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0
    assert "Dry-run mode enabled" in res.stdout
    assert "Backend Capability Evaluation" in res.stdout


def test_cli_json():
    script_path = REPO_ROOT / "scripts" / "ctf_init.py"
    res = subprocess.run(
        [sys.executable, str(script_path), "--json"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert "environment" in data
    assert "scoring" in data
    assert "purpose_profiles" in data
    assert data["environment"]["os"]["system"] in ["Windows", "Linux", "Darwin"]


def test_node_launcher_dry_run():
    node_bin = shutil.which("node")
    if not node_bin:
        pytest.skip("Node.js runtime not installed on host")
    js_path = REPO_ROOT / "bin" / "ctf-agent.js"
    assert js_path.exists()
    res = subprocess.run(
        [node_bin, str(js_path), "init", "--dry-run"],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert res.returncode == 0
    assert "Dry-run mode enabled" in res.stdout


def test_ctf_agent_cli_dry_run():
    cli_path = REPO_ROOT / "ctf_agent_cli.py"
    assert cli_path.exists()
    res = subprocess.run(
        [sys.executable, str(cli_path), "init", "--dry-run"],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert res.returncode == 0
    assert "Dry-run mode enabled" in res.stdout


def test_uv_runner_dry_run():
    uv_bin = shutil.which("uv")
    if not uv_bin:
        pytest.skip("uv toolchain not installed on host")
    cli_path = REPO_ROOT / "ctf_agent_cli.py"
    res = subprocess.run(
        [uv_bin, "run", str(cli_path), "init", "--dry-run"],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert res.returncode == 0
    assert "Dry-run mode enabled" in res.stdout


def test_workload_aware_scoring_adjustments():
    mock_env = {
        "os": {"is_windows": True, "is_linux": False, "is_macos": False},
        "wsl": {"available": True, "kali_present": True, "kali_running": True, "wsl2_supported": True},
        "docker": {"available": True, "daemon_running": True},
        "disk": {"free_gb": 40.0},
        "memory": {"total_gb": 16.0},
    }

    base_scores = CapabilityScoringEngine.calculate_scores(mock_env, workload="live-ctf")
    pwn_scores = CapabilityScoringEngine.calculate_scores(mock_env, workload="rev-pwn")

    # rev-pwn on Windows WSL should receive additional +2 bonus
    assert pwn_scores["wsl_score"] > base_scores["wsl_score"]
    assert any("rev-pwn" in r for r in pwn_scores["wsl_factors"])


def test_non_interactive_output_notice():
    cli_path = REPO_ROOT / "ctf_agent_cli.py"
    res = subprocess.run(
        [sys.executable, str(cli_path), "init", "--auto", "--dry-run"],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert res.returncode == 0
    assert "Automated flag (--auto)" in res.stdout or "Non-interactive" in res.stdout


def test_existing_project_detection_preflight(tmp_path):
    # Empty directory
    pre1 = EnvironmentDetector.run_preflight(tmp_path)
    assert pre1["is_empty"] is True
    assert pre1["existing_items_count"] == 0

    # Directory with metadata only
    (tmp_path / ".git").mkdir()
    (tmp_path / ".codegraph").mkdir()
    pre2 = EnvironmentDetector.run_preflight(tmp_path)
    assert pre2["is_empty"] is True
    assert pre2["existing_items_count"] == 0

    # Directory with actual project files (e.g. flagyard-labs style)
    (tmp_path / "Web").mkdir()
    (tmp_path / "README.md").write_text("# My Labs", encoding="utf-8")
    pre3 = EnvironmentDetector.run_preflight(tmp_path)
    assert pre3["is_empty"] is False
    assert pre3["existing_items_count"] == 2


def test_provision_agent_only_clean_root(tmp_path):
    # Provision with agent_only=True
    success = WorkspaceProvisioner.provision(
        workspace_path=tmp_path,
        backend="none",
        distro="kali-linux",
        profiles="core",
        skip_toolchain=True,
        agent_only=True,
    )
    assert success is True

    # .agents directory exists
    dot_agents = tmp_path / ".agents"
    assert dot_agents.is_dir()
    assert (dot_agents / "AGENTS.md").is_file()
    assert (dot_agents / "skills-lock.json").is_file()
    assert (dot_agents / "agents" / "ctf-controller.md").is_file()

    # Workspace root has ZERO added files
    assert not (tmp_path / "AGENTS.md").exists()
    assert not (tmp_path / "skills-lock.json").exists()
    assert not (tmp_path / "mcp_config.json").exists()
    assert not (tmp_path / "resources").exists()
    assert not (tmp_path / "notes").exists()
    assert not (tmp_path / "solve.py").exists()
    assert not (tmp_path / ".env.example").exists()

    # Health check in agent_only mode passes
    check_res = HealthCheckRunner.check_workspace(tmp_path, "none", "kali-linux", agent_only=True)
    assert check_res["all_passed"] is True


def test_provision_no_scaffold(tmp_path):
    # Provision with no_scaffold=True (agent_only=False)
    success = WorkspaceProvisioner.provision(
        workspace_path=tmp_path,
        backend="none",
        distro="kali-linux",
        profiles="core",
        skip_toolchain=True,
        agent_only=False,
        no_scaffold=True,
    )
    assert success is True

    # Root config exists for IDE
    assert (tmp_path / "AGENTS.md").is_file()
    assert (tmp_path / "skills-lock.json").is_file()
    assert (tmp_path / "mcp_config.json").is_file()

    # Scaffolding does NOT exist
    assert not (tmp_path / "resources").exists()
    assert not (tmp_path / "notes").exists()
    assert not (tmp_path / "solve.py").exists()
    assert not (tmp_path / ".env.example").exists()


def test_cli_dry_run_auto_detects_existing_project(tmp_path):
    # Simulate existing project like flagyard-labs
    (tmp_path / "Crypto").mkdir()
    (tmp_path / "custom_tool.py").write_text("# tool", encoding="utf-8")

    cli_path = REPO_ROOT / "ctf_agent_cli.py"
    res = subprocess.run(
        [sys.executable, str(cli_path), "init", str(tmp_path), "--dry-run"],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert res.returncode == 0
    assert "Skip Scaffolding : True" in res.stdout
    assert "Existing project layout preserved" in res.stdout


