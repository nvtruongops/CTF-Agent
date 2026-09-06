#!/usr/bin/env python3
"""
CTF-Agent Preflight Environment Detector & Workspace Initializer (v1.3)
Analyzes host capabilities, scores execution backends (WSL vs Docker),
selects workload profiles, provisions workspaces, and verifies health.
"""

import os
import sys
import platform
import shutil
import argparse
import subprocess
import json
import socket
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

# Ensure safe UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

REPO_ROOT = Path(__file__).resolve().parent.parent

# Import deployment logic from install_as_agent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
try:
    import install_as_agent
except ImportError:
    install_as_agent = None


# ---------------------------------------------------------------------------
# Workload & Profile Definitions
# ---------------------------------------------------------------------------

PURPOSE_PROFILES = {
    "live-ctf": {
        "title": "Live CTF Competition (Blitz / Speedrun)",
        "description": "Fastest time-to-flag, minimal documentation overhead, stop-on-flag workflow.",
        "profiles": "core,pwn,web,crypto",
        "agent_mode": "@ctf-speedrun (--blitz)",
    },
    "security-lab": {
        "title": "Security Lab & Research (Deep Analysis / RCA)",
        "description": "Exhaustive root-cause analysis, standardized writeup.md, resources/ preservation.",
        "profiles": "core,pwn,rev,crypto,forensics,web,cloud,ad,kernel,web3",
        "agent_mode": "@ctf-analyzer (--deep)",
    },
    "rev-pwn": {
        "title": "Reverse Engineering & Binary Exploitation",
        "description": "Dedicated disassemblers, decompilers, ROP, heap, and symbolic execution.",
        "profiles": "core,pwn,rev,kernel,wasm",
        "agent_mode": "@ctf-speedrun / @ctf-analyzer",
    },
    "full": {
        "title": "Full Comprehensive CTF Workstation",
        "description": "All 15 category profiles installed into the isolated backend.",
        "profiles": "all",
        "agent_mode": "@ctf-controller",
    },
}


# ---------------------------------------------------------------------------
# Environment Preflight Detector
# ---------------------------------------------------------------------------

class EnvironmentDetector:
    """Detects host platform, resources, WSL distro state, Docker state, and network."""

    @staticmethod
    def detect_os() -> Dict[str, Any]:
        os_type = platform.system()
        return {
            "system": os_type,
            "platform": sys.platform,
            "release": platform.release(),
            "arch": platform.machine(),
            "cpu_cores": os.cpu_count() or 1,
            "is_windows": os_type == "Windows",
            "is_linux": os_type == "Linux",
            "is_macos": os_type == "Darwin",
        }

    @staticmethod
    def detect_memory() -> Dict[str, float]:
        total_gb = 0.0
        avail_gb = 0.0

        if platform.system() == "Windows":
            try:
                import ctypes
                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [
                        ("dwLength", ctypes.c_ulong),
                        ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong),
                        ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                    ]
                stat = MEMORYSTATUSEX()
                stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
                if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                    total_gb = round(stat.ullTotalPhys / (1024 ** 3), 2)
                    avail_gb = round(stat.ullAvailPhys / (1024 ** 3), 2)
            except Exception:
                pass
        elif platform.system() == "Linux":
            try:
                with open("/proc/meminfo", "r", encoding="utf-8") as f:
                    mem_data = {}
                    for line in f:
                        parts = line.split(":")
                        if len(parts) == 2:
                            mem_data[parts[0].strip()] = parts[1].strip()
                    if "MemTotal" in mem_data:
                        kb = float(mem_data["MemTotal"].split()[0])
                        total_gb = round(kb / (1024 ** 2), 2)
                    if "MemAvailable" in mem_data:
                        kb = float(mem_data["MemAvailable"].split()[0])
                        avail_gb = round(kb / (1024 ** 2), 2)
            except Exception:
                pass
        elif platform.system() == "Darwin":
            try:
                out = subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True).strip()
                bytes_mem = float(out)
                total_gb = round(bytes_mem / (1024 ** 3), 2)
                avail_gb = total_gb * 0.5
            except Exception:
                pass

        return {"total_gb": total_gb, "avail_gb": avail_gb}

    @staticmethod
    def detect_disk(path: Path) -> Dict[str, float]:
        target = path.resolve()
        if not target.exists():
            target = target.parent if target.parent.exists() else Path.cwd()
        try:
            total, used, free = shutil.disk_usage(str(target))
            return {
                "total_gb": round(total / (1024 ** 3), 2),
                "free_gb": round(free / (1024 ** 3), 2),
                "used_gb": round(used / (1024 ** 3), 2),
            }
        except Exception:
            return {"total_gb": 0.0, "free_gb": 0.0, "used_gb": 0.0}

    @staticmethod
    def detect_wsl() -> Dict[str, Any]:
        if platform.system() != "Windows":
            return {
                "available": False,
                "reason": "WSL is only available on Windows",
                "distros": [],
                "kali_present": False,
                "kali_running": False,
                "wsl2_supported": False,
            }

        wsl_bin = shutil.which("wsl.exe") or shutil.which("wsl")
        if not wsl_bin:
            return {
                "available": False,
                "reason": "wsl.exe executable not found in PATH",
                "distros": [],
                "kali_present": False,
                "kali_running": False,
                "wsl2_supported": False,
            }

        try:
            res = subprocess.run(
                [wsl_bin, "-l", "-v"],
                capture_output=True,
                check=False,
                timeout=5,
            )
            raw = res.stdout
            text = ""
            try:
                decoded_utf16 = raw.decode("utf-16le", errors="ignore")
                if "NAME" in decoded_utf16 or "Name" in decoded_utf16:
                    text = decoded_utf16
                else:
                    text = raw.decode("utf-8", errors="replace")
            except Exception:
                text = raw.decode("utf-8", errors="replace")

            distros = []
            kali_present = False
            kali_running = False
            wsl2_supported = False

            for line in text.splitlines():
                line = line.strip()
                if not line or "NAME" in line or "---" in line:
                    continue
                is_default = line.startswith("*")
                clean = line.lstrip("*").strip()
                parts = clean.split()
                if len(parts) >= 2:
                    distro_name = parts[0]
                    state = parts[1]
                    version = parts[2] if len(parts) >= 3 else "Unknown"
                    if version == "2":
                        wsl2_supported = True
                    is_kali = "kali" in distro_name.lower()
                    if is_kali:
                        kali_present = True
                        if state.lower() == "running":
                            kali_running = True
                    distros.append({
                        "name": distro_name,
                        "state": state,
                        "version": version,
                        "is_default": is_default,
                        "is_kali": is_kali,
                    })

            return {
                "available": True,
                "reason": f"Found {len(distros)} registered distribution(s)",
                "distros": distros,
                "kali_present": kali_present,
                "kali_running": kali_running,
                "wsl2_supported": wsl2_supported,
            }
        except subprocess.TimeoutExpired:
            return {
                "available": False,
                "reason": "WSL command timed out",
                "distros": [],
                "kali_present": False,
                "kali_running": False,
                "wsl2_supported": False,
            }
        except Exception as e:
            return {
                "available": False,
                "reason": f"Error querying WSL: {e}",
                "distros": [],
                "kali_present": False,
                "kali_running": False,
                "wsl2_supported": False,
            }

    @staticmethod
    def detect_docker() -> Dict[str, Any]:
        docker_bin = shutil.which("docker")
        if not docker_bin:
            return {
                "available": False,
                "daemon_running": False,
                "reason": "docker executable not found in PATH",
                "version": "",
            }

        version_str = ""
        daemon_running = False

        try:
            res_ver = subprocess.run(
                [docker_bin, "--version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=4,
            )
            if res_ver.returncode == 0:
                version_str = res_ver.stdout.strip()
        except Exception:
            pass

        try:
            res_info = subprocess.run(
                [docker_bin, "info", "--format", "{{.ServerVersion}}"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            if res_info.returncode == 0 and res_info.stdout.strip():
                daemon_running = True
        except Exception:
            daemon_running = False

        return {
            "available": True,
            "daemon_running": daemon_running,
            "reason": "Docker daemon running" if daemon_running else "Docker CLI present, but daemon is stopped",
            "version": version_str,
        }

    @staticmethod
    def detect_network() -> Dict[str, bool]:
        connected = False
        try:
            socket.create_connection(("1.1.1.1", 53), timeout=1.5).close()
            connected = True
        except OSError:
            try:
                socket.create_connection(("8.8.8.8", 53), timeout=1.5).close()
                connected = True
            except OSError:
                connected = False
        return {"connected": connected}

    @classmethod
    def run_preflight(cls, workspace_path: Path) -> Dict[str, Any]:
        dot_agents = workspace_path / ".agents"
        dot_agent_legacy = workspace_path / ".agent"
        return {
            "os": cls.detect_os(),
            "memory": cls.detect_memory(),
            "disk": cls.detect_disk(workspace_path),
            "wsl": cls.detect_wsl(),
            "docker": cls.detect_docker(),
            "network": cls.detect_network(),
            "workspace_path": str(workspace_path.resolve()),
            "existing_agents": dot_agents.exists() or dot_agent_legacy.exists(),
        }


# ---------------------------------------------------------------------------
# Backend Capability Scoring Engine
# ---------------------------------------------------------------------------

class CapabilityScoringEngine:
    """Calculates weighted scores for WSL vs Docker execution backends."""

    @staticmethod
    def calculate_scores(env: Dict[str, Any], workload: str = "live-ctf") -> Dict[str, Any]:
        os_info = env["os"]
        wsl_info = env["wsl"]
        docker_info = env["docker"]
        disk_info = env["disk"]
        mem_info = env["memory"]

        free_disk = disk_info.get("free_gb", 0.0)
        total_ram = mem_info.get("total_gb", 0.0)

        wsl_score = 0
        wsl_reasons: List[str] = []

        docker_score = 0
        docker_reasons: List[str] = []

        # WSL Evaluation
        if os_info["is_windows"]:
            wsl_score += 3
            wsl_reasons.append("Windows native OS environment (+3)")

            if wsl_info["available"]:
                wsl_score += 3
                wsl_reasons.append("WSL service active (+3)")

                if wsl_info["kali_present"]:
                    wsl_score += 3
                    wsl_reasons.append("Kali Linux distribution installed (+3)")
                    if wsl_info["kali_running"]:
                        wsl_score += 1
                        wsl_reasons.append("Kali Linux instance currently running (+1)")
                else:
                    wsl_reasons.append("Kali Linux distribution missing (0)")

                if wsl_info["wsl2_supported"]:
                    wsl_score += 1
                    wsl_reasons.append("WSL2 virtualization architecture verified (+1)")
            else:
                wsl_reasons.append("WSL not available on host (0)")

            if free_disk >= 25.0:
                wsl_score += 2
                wsl_reasons.append(f"Storage ample ({free_disk} GB free) (+2)")
            elif free_disk >= 15.0:
                wsl_score += 1
                wsl_reasons.append(f"Storage sufficient ({free_disk} GB free) (+1)")
            else:
                wsl_score -= 2
                wsl_reasons.append(f"Storage low ({free_disk} GB free) (-2)")

            if total_ram >= 8.0:
                wsl_score += 1
                wsl_reasons.append(f"RAM sufficient ({total_ram} GB) (+1)")
        else:
            wsl_score = 0
            wsl_reasons.append("Non-Windows OS: WSL not applicable (0)")

        # Docker Evaluation
        if docker_info["available"]:
            docker_score += 2
            docker_reasons.append("Docker CLI installed (+2)")

            if docker_info["daemon_running"]:
                docker_score += 3
                docker_reasons.append("Docker daemon running and responsive (+3)")

                if os_info["is_linux"]:
                    docker_score += 3
                    docker_reasons.append("Native Linux container execution (+3)")
                elif os_info["is_macos"]:
                    docker_score += 2
                    docker_reasons.append("macOS container execution (+2)")
                elif os_info["is_windows"]:
                    docker_score -= 1
                    docker_reasons.append("Windows Docker 9P filesystem interop penalty (-1)")

                if free_disk >= 25.0:
                    docker_score += 2
                    docker_reasons.append(f"Storage ample ({free_disk} GB free) (+2)")
                elif free_disk >= 15.0:
                    docker_score += 1
                    docker_reasons.append(f"Storage sufficient ({free_disk} GB free) (+1)")
                else:
                    docker_score -= 2
                    docker_reasons.append(f"Storage low ({free_disk} GB free) (-2)")

                if total_ram >= 8.0:
                    docker_score += 1
                    docker_reasons.append(f"RAM sufficient ({total_ram} GB) (+1)")
            else:
                docker_reasons.append("Docker daemon stopped (0)")
        else:
            docker_reasons.append("Docker CLI not installed (0)")

        # Workload-Aware Capability Scoring adjustments
        if workload == "rev-pwn":
            if os_info["is_windows"] and wsl_info["available"]:
                wsl_score += 2
                wsl_reasons.append("Workload 'rev-pwn': native ELF debugging & GDB kernel syscalls (+2)")
            elif os_info["is_linux"]:
                docker_score += 1
                docker_reasons.append("Workload 'rev-pwn': native Linux execution (+1)")
        elif workload == "security-lab":
            if docker_info["daemon_running"]:
                docker_score += 2
                docker_reasons.append("Workload 'security-lab': Docker containment sandbox for research (+2)")
        elif workload == "live-ctf":
            if wsl_info["available"] and wsl_info["kali_running"]:
                wsl_score += 1
                wsl_reasons.append("Workload 'live-ctf': Zero spin-up latency with active Kali instance (+1)")
        elif workload == "full":
            if free_disk < 30.0:
                wsl_score -= 1
                docker_score -= 1
                wsl_reasons.append(f"Workload 'full': high storage footprint ({free_disk} GB free) (-1)")
                docker_reasons.append(f"Workload 'full': high storage footprint ({free_disk} GB free) (-1)")

        # Decision synthesis
        if os_info["is_windows"]:
            if wsl_score >= docker_score and wsl_info["available"]:
                recommended = "wsl"
                distro_target = "kali-linux" if wsl_info["kali_present"] else "kali-linux"
                if wsl_info["kali_present"]:
                    reason = "Native Windows + Kali Linux distro verified in WSL2"
                else:
                    reason = "Windows detected with WSL available; Kali Linux installation recommended"
            elif docker_score > wsl_score and docker_info["daemon_running"]:
                recommended = "docker"
                distro_target = ""
                reason = "Docker daemon is active and scored higher than WSL"
            elif wsl_info["available"]:
                recommended = "wsl"
                distro_target = "kali-linux"
                reason = "WSL is available and Docker daemon is stopped"
            elif docker_info["available"]:
                recommended = "docker"
                distro_target = ""
                reason = "Docker CLI is present; start daemon to proceed"
            else:
                recommended = "manual"
                distro_target = ""
                reason = "Neither WSL nor Docker is currently ready"
        else:
            if docker_info["daemon_running"]:
                recommended = "docker"
                distro_target = ""
                reason = "Native container runtime active for Unix platform"
            elif os_info["is_linux"]:
                recommended = "host"
                distro_target = ""
                reason = "Native Linux host execution available directly"
            else:
                recommended = "docker"
                distro_target = ""
                reason = "Docker runtime recommended for macOS/Linux"

        return {
            "wsl_score": max(0, wsl_score),
            "docker_score": max(0, docker_score),
            "recommended": recommended,
            "distro_target": distro_target,
            "reason": reason,
            "wsl_factors": wsl_reasons,
            "docker_factors": docker_reasons,
            "workload": workload,
        }


# ---------------------------------------------------------------------------
# Workspace Provisioning & Initialization
# ---------------------------------------------------------------------------

class WorkspaceProvisioner:
    """Configures workspace scaffolding, templates, and backend toolchain."""

    @staticmethod
    def setup_templates(workspace_path: Path):
        """Creates standard resources/, solve.py, and .env.example files."""
        resources_dir = workspace_path / "resources"
        resources_dir.mkdir(parents=True, exist_ok=True)

        notes_dir = workspace_path / "notes"
        notes_dir.mkdir(parents=True, exist_ok=True)

        env_example = workspace_path / ".env.example"
        if not env_example.exists():
            env_content = (
                "# CTF-Agent Target & Competition Credentials\n"
                "CTFD_URL=https://ctf.example.com\n"
                "CTFD_TOKEN=your_ctfd_token_here\n"
                "TARGET_HOST=127.0.0.1\n"
                "TARGET_PORT=1337\n"
                "TARGET_URL=http://127.0.0.1:8000\n"
            )
            env_example.write_text(env_content, encoding="utf-8")
            print("  [+] Created .env.example template")

        solve_py = workspace_path / "solve.py"
        if not solve_py.exists():
            solve_content = (
                "#!/usr/bin/env python3\n"
                "# ===========================================================================\n"
                "# CTF Educational PoC & Vulnerability Verification Script\n"
                "# Scope: Authorized CTF sandbox challenge\n"
                "# ===========================================================================\n"
                "import sys\n"
                "import os\n"
                "\n"
                "def solve():\n"
                "    print('[*] Initializing verification sequence...')\n"
                "    # Implementation here\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    solve()\n"
            )
            solve_py.write_text(solve_content, encoding="utf-8")
            print("  [+] Created solve.py template")

    @classmethod
    def provision(
        cls,
        workspace_path: Path,
        backend: str,
        distro: str,
        profiles: str,
        use_symlink: bool = False,
        force: bool = False,
        skip_toolchain: bool = False,
    ) -> bool:
        print(f"\n[*] Initializing workspace at: {workspace_path.resolve()}")

        # 1. Deploy .agents/ and configuration
        if install_as_agent:
            install_as_agent.deploy_to_workspace(
                workspace_path,
                use_symlink=use_symlink,
                force=force,
                setup_workspace=True,
                install_wsl=(backend == "wsl" and not skip_toolchain),
                wsl_profile=profiles,
                wsl_distro=distro,
            )
        else:
            print("[!] Error: install_as_agent module unavailable")
            return False

        # 2. Setup standard challenge templates
        cls.setup_templates(workspace_path)

        # 3. Handle Docker backend guidance if selected
        if backend == "docker" and not skip_toolchain:
            cls.provision_docker(workspace_path, profiles)

        return True

    @classmethod
    def provision_docker(cls, workspace_path: Path, profiles: str, dry_run: bool = False):
        print(f"\n[*] Provisioning Docker backend for workspace...")
        compose_file = REPO_ROOT / "docker-compose.yml"
        dockerfile = REPO_ROOT / "Dockerfile"
        target_compose = workspace_path / "docker-compose.yml"

        if compose_file.exists() and not target_compose.exists():
            shutil.copy2(compose_file, target_compose)
            print(f"  [+] Copied docker-compose.yml -> {target_compose}")

        if dockerfile.exists() and not (workspace_path / "Dockerfile").exists():
            shutil.copy2(dockerfile, workspace_path / "Dockerfile")
            print(f"  [+] Copied Dockerfile -> {workspace_path / 'Dockerfile'}")

        if dry_run:
            print("  [*] Dry-run enabled: skipping container execution.")
            return

        docker_bin = shutil.which("docker")
        if not docker_bin:
            print("  [!] Docker CLI not detected on system PATH.")
            return

        # 1. Validate compose configuration
        try:
            res_cfg = subprocess.run(
                [docker_bin, "compose", "-f", str(target_compose), "config"],
                capture_output=True,
                text=True,
                check=False,
                timeout=6,
            )
            if res_cfg.returncode == 0:
                print("  [+] Validated docker compose configuration syntax")
            else:
                print(f"  [!] Compose config warning: {res_cfg.stderr.strip()[:120]}")
        except Exception:
            pass

        # 2. Check docker daemon and test container readiness
        try:
            res_info = subprocess.run(
                [docker_bin, "info"],
                capture_output=True,
                check=False,
                timeout=4,
            )
            if res_info.returncode == 0:
                print("  [*] Docker daemon is active. Verifying container readiness...")
                test_cmd = [
                    docker_bin, "compose", "-f", str(target_compose),
                    "run", "--rm", "ctf-agent", "python3", "--version"
                ]
                test_run = subprocess.run(test_cmd, capture_output=True, text=True, check=False, timeout=12)
                if test_run.returncode == 0:
                    print(f"  [OK] Docker CTF container ready: {test_run.stdout.strip()}")
                else:
                    print("  [*] Container image not yet built. To build:")
                    print(f"      docker compose -f '{target_compose}' build")
            else:
                print("  [!] Docker daemon is not running. Please start Docker to activate container sandbox.")
        except Exception as e:
            print(f"  [!] Docker readiness check skipped: {e}")


# ---------------------------------------------------------------------------
# Health Check Runner
# ---------------------------------------------------------------------------

class HealthCheckRunner:
    """Verifies workspace file integrity, agent components, and backend availability."""

    @staticmethod
    def check_workspace(workspace_path: Path, backend: str, distro: str) -> Dict[str, Any]:
        results: Dict[str, Any] = {
            "workspace": str(workspace_path.resolve()),
            "backend": backend,
            "checks": [],
            "all_passed": True,
        }

        def record(check_name: str, passed: bool, detail: str):
            results["checks"].append({
                "name": check_name,
                "passed": passed,
                "detail": detail,
            })
            if not passed:
                results["all_passed"] = False

        dot_agents = workspace_path / ".agents"
        record("dot_agents_directory", dot_agents.is_dir(), f"Checked {dot_agents}")

        agents_md = workspace_path / "AGENTS.md"
        record("workspace_agents_md", agents_md.is_file(), f"Checked {agents_md}")

        skills_lock = workspace_path / "skills-lock.json"
        record("skills_lock_file", skills_lock.is_file(), f"Checked {skills_lock}")

        controller_md = dot_agents / "agents" / "ctf-controller.md"
        record("agent_ctf_controller", controller_md.is_file(), f"Checked {controller_md}")

        speedrun_md = dot_agents / "agents" / "ctf-speedrun.md"
        record("agent_ctf_speedrun", speedrun_md.is_file(), f"Checked {speedrun_md}")

        analyzer_md = dot_agents / "agents" / "ctf-analyzer.md"
        record("agent_ctf_analyzer", analyzer_md.is_file(), f"Checked {analyzer_md}")

        scripts_dir = dot_agents / "scripts"
        record("scripts_present", scripts_dir.is_dir() and any(scripts_dir.iterdir()), f"Checked {scripts_dir}")

        if backend == "wsl":
            try:
                test_cmd = ["wsl", "-d", distro, "bash", "-c", "python3 --version"]
                res = subprocess.run(test_cmd, capture_output=True, text=True, check=False, timeout=5)
                wsl_ok = res.returncode == 0
                record("wsl_kali_python", wsl_ok, f"Output: {res.stdout.strip() if wsl_ok else res.stderr.strip()}")
            except Exception as e:
                record("wsl_kali_python", False, f"WSL execution error: {e}")

        elif backend == "docker":
            docker_bin = shutil.which("docker")
            if docker_bin:
                try:
                    res = subprocess.run([docker_bin, "info"], capture_output=True, text=True, check=False, timeout=5)
                    record("docker_daemon_active", res.returncode == 0, "Docker daemon connection verified" if res.returncode == 0 else "Daemon stopped")
                except Exception as e:
                    record("docker_daemon_active", False, f"Docker query error: {e}")
            else:
                record("docker_daemon_active", False, "docker CLI not found in PATH")

        return results


# ---------------------------------------------------------------------------
# Presentation & CLI Formatting Helpers
# ---------------------------------------------------------------------------

def print_banner(env: Dict[str, Any], scoring: Dict[str, Any]):
    os_info = env["os"]
    mem_info = env["memory"]
    disk_info = env["disk"]
    wsl_info = env["wsl"]
    docker_info = env["docker"]

    print("=================================================================")
    print("CTF-AGENT ENVIRONMENT PREFLIGHT & WORKSPACE INITIALIZER")
    print("=================================================================")
    print(f"Platform : {os_info['system']} {os_info['release']} ({os_info['arch']})")
    print(f"Hardware : {os_info['cpu_cores']} CPU cores | {mem_info['total_gb']} GB RAM")
    print(f"Storage  : {disk_info['free_gb']} GB Free / {disk_info['total_gb']} GB Total")
    ws_status = "Existing .agents/ configuration found" if env.get("existing_agents", False) else "Fresh directory (clean)"
    print(f"Workspace: {ws_status}")
    print("-----------------------------------------------------------------")
    print("Detected Backends:")

    if os_info["is_windows"]:
        if wsl_info["available"]:
            kali_status = "READY & RUNNING" if wsl_info["kali_running"] else ("INSTALLED" if wsl_info["kali_present"] else "MISSING")
            print(f"  [+] WSL2        : Available ({len(wsl_info['distros'])} distros)")
            print(f"  [{'+' if wsl_info['kali_present'] else '!'}] Kali Linux  : {kali_status}")
        else:
            print(f"  [-] WSL2        : Unavailable ({wsl_info.get('reason', 'N/A')})")
    else:
        print(f"  [*] Host Native : {os_info['system']} Linux/Unix Environment")

    if docker_info["available"]:
        doc_status = "RUNNING" if docker_info["daemon_running"] else "STOPPED"
        print(f"  [{'+' if docker_info['daemon_running'] else '!'}] Docker      : {doc_status} ({docker_info.get('version', 'CLI found')})")
    else:
        print("  [-] Docker      : Not Installed")

    print("-----------------------------------------------------------------")
    print("Backend Capability Evaluation:")
    print(f"  WSL Score    : {scoring['wsl_score']:2d} / 12  (Factors: {len(scoring['wsl_factors'])})")
    print(f"  Docker Score : {scoring['docker_score']:2d} / 12  (Factors: {len(scoring['docker_factors'])})")
    print(f"  Recommended  : {scoring['recommended'].upper()} {'(' + scoring['distro_target'] + ')' if scoring['distro_target'] else ''}")
    print(f"  Rationale    : {scoring['reason']}")
    print("=================================================================")


def print_health_report(report: Dict[str, Any]):
    print("\n=================================================================")
    print("WORKSPACE HEALTH VERIFICATION REPORT")
    print("=================================================================")
    for c in report["checks"]:
        status = "[PASS]" if c["passed"] else "[FAIL]"
        print(f"  {status} {c['name']:<25} : {c['detail']}")
    print("-----------------------------------------------------------------")
    if report["all_passed"]:
        print("[OK] Workspace initialized successfully! All components verified.")
    else:
        print("[!] Workspace initialized with warnings or missing components.")
    print("=================================================================")


# ---------------------------------------------------------------------------
# Main CLI Entrypoint
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="CTF-Agent Preflight Environment Detector & Workspace Initializer"
    )
    parser.add_argument(
        "workspace",
        nargs="?",
        default=".",
        help="Target workspace directory (default: current directory .)",
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Run non-interactively, automatically accepting recommended backend and profile",
    )
    parser.add_argument(
        "--backend",
        choices=["wsl", "docker", "host", "none"],
        help="Explicitly override execution backend",
    )
    parser.add_argument(
        "--distro",
        default="kali-linux",
        help="WSL distribution target (default: kali-linux)",
    )
    parser.add_argument(
        "--purpose",
        choices=list(PURPOSE_PROFILES.keys()),
        default="live-ctf",
        help="Workload purpose: live-ctf, security-lab, rev-pwn, full (default: live-ctf)",
    )
    parser.add_argument(
        "--profile",
        help="Explicit comma-separated toolchain profiles (overrides purpose preset)",
    )
    parser.add_argument(
        "--symlink",
        action="store_true",
        help="Use symlinks/junctions for .agents/ deployment",
    )
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Overwrite existing workspace configuration",
    )
    parser.add_argument(
        "--skip-toolchain",
        action="store_true",
        help="Deploy agent workspace without executing backend toolchain installations",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Perform preflight checks and output recommendation without modifying workspace",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output preflight detection, scoring, and plan as JSON",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Run health check on existing workspace without modifying it",
    )

    args = parser.parse_args()
    ws_path = Path(args.workspace).resolve()

    # Preflight Detection
    env = EnvironmentDetector.run_preflight(ws_path)
    scoring = CapabilityScoringEngine.calculate_scores(env, workload=args.purpose)

    # Health check only mode
    if args.check_only:
        backend_target = args.backend or scoring["recommended"]
        distro_target = args.distro or scoring["distro_target"] or "kali-linux"
        report = HealthCheckRunner.check_workspace(ws_path, backend_target, distro_target)
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print_health_report(report)
        sys.exit(0 if report["all_passed"] else 1)

    # JSON output mode
    if args.json:
        payload = {
            "environment": env,
            "scoring": scoring,
            "purpose_profiles": PURPOSE_PROFILES,
            "selected_purpose": args.purpose,
            "selected_profiles": args.profile or PURPOSE_PROFILES[args.purpose]["profiles"],
        }
        print(json.dumps(payload, indent=2))
        sys.exit(0)

    # Print summary banner
    print_banner(env, scoring)

    # Dry-run mode
    if args.dry_run:
        target_backend = args.backend or scoring["recommended"]
        target_distro = args.distro if target_backend == "wsl" else ""
        selected_prof = args.profile or PURPOSE_PROFILES[args.purpose]["profiles"]
        print("\n[*] Dry-run mode enabled. Planned actions:")
        print(f"    Target Workspace : {ws_path}")
        print(f"    Selected Backend : {target_backend}")
        if target_distro:
            print(f"    WSL Distro       : {target_distro}")
        print(f"    Workload Purpose : {args.purpose} ({PURPOSE_PROFILES[args.purpose]['title']})")
        print(f"    Tool Profiles    : {selected_prof}")
        print(f"    Skip Toolchain   : {args.skip_toolchain}")
        if args.auto or not sys.stdin.isatty():
            mode_desc = "Automated flag (--auto)" if args.auto else "Non-interactive environment (headless/non-TTY)"
            print(f"    Execution Mode   : {mode_desc}")
        print("\n[OK] Preflight checks passed without modifications.")
        sys.exit(0)

    # Interactive vs Non-interactive selection
    chosen_backend = args.backend or scoring["recommended"]
    chosen_distro = args.distro or scoring["distro_target"] or "kali-linux"
    chosen_purpose = args.purpose
    chosen_profiles = args.profile or PURPOSE_PROFILES[chosen_purpose]["profiles"]
    chosen_skip_toolchain = args.skip_toolchain

    if not args.auto and sys.stdin.isatty():
        while True:
            print("\nAvailable Actions:")
            rec_label = f"Recommended ({scoring['recommended'].upper()})"
            tool_status = "DISABLED (Agent workspace only)" if chosen_skip_toolchain else f"ENABLED ({chosen_profiles})"
            print(f"  [1] Continue with {rec_label} [{chosen_backend.upper()}]")
            print("  [2] Switch backend (WSL <-> Docker)")
            print("  [3] Select workload purpose (Live CTF, Lab, Rev/Pwn, Full)")
            print(f"  [4] Toggle backend toolchain installation (Currently: {tool_status})")
            print("  [5] Exit")

            try:
                choice = input("\nSelect option [1-5] (default: 1): ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\n[!] Operation cancelled by user.")
                sys.exit(0)

            if not choice or choice == "1":
                break
            elif choice == "2":
                chosen_backend = "docker" if chosen_backend == "wsl" else "wsl"
                print(f"[*] Backend switched to: {chosen_backend.upper()}")
            elif choice == "3":
                print("\nSelect Workload Purpose:")
                purpose_keys = list(PURPOSE_PROFILES.keys())
                for idx, k in enumerate(purpose_keys, 1):
                    p = PURPOSE_PROFILES[k]
                    print(f"  [{idx}] {p['title']}")
                    print(f"      Profiles: {p['profiles']}")
                try:
                    p_choice = input(f"\nSelect purpose [1-{len(purpose_keys)}] (default: 1): ").strip()
                    if p_choice.isdigit() and 1 <= int(p_choice) <= len(purpose_keys):
                        chosen_purpose = purpose_keys[int(p_choice) - 1]
                        chosen_profiles = PURPOSE_PROFILES[chosen_purpose]["profiles"]
                        print(f"[*] Selected purpose: {PURPOSE_PROFILES[chosen_purpose]['title']}")
                except (KeyboardInterrupt, EOFError):
                    pass
            elif choice == "4":
                chosen_skip_toolchain = not chosen_skip_toolchain
                new_state = "DISABLED (Agent workspace only)" if chosen_skip_toolchain else "ENABLED"
                print(f"[*] Toolchain installation is now: {new_state}")
            elif choice == "5":
                print("[*] Exiting without changes.")
                sys.exit(0)
    else:
        env_mode = "Automated flag (--auto)" if args.auto else "Non-interactive environment detected (headless/non-TTY)"
        print(f"\n[*] {env_mode}.")
        print(f"    Auto-selected backend    : {chosen_backend.upper()} ({chosen_distro})")
        print(f"    Workload purpose         : {chosen_purpose} ({PURPOSE_PROFILES[chosen_purpose]['title']})")
        print(f"    Toolchain installation   : {'DISABLED' if chosen_skip_toolchain else 'ENABLED (' + chosen_profiles + ')'}")

    # Check for existing workspace directory (.agents or legacy .agent)
    dot_agents = ws_path / ".agents"
    dot_agent_legacy = ws_path / ".agent"
    existing_agents_found = dot_agents.exists() or dot_agent_legacy.exists()
    effective_force = args.force

    if existing_agents_found and not args.force:
        if not args.auto and sys.stdin.isatty():
            print("\n[!] CONFLICT / UPDATE DETECTED:")
            target_name = ".agents/" if dot_agents.exists() else ".agent/ (legacy)"
            print(f"    Found existing {target_name} in target workspace: {ws_path}")
            print("    Overwriting will refresh agent skills, rules, and scripts, while")
            print("    preserving your existing challenge files (resources/, notes/, solve.py).")
            try:
                ov_choice = input("    Proceed to update/overwrite agent framework? [y/N]: ").strip().lower()
                if ov_choice in ("y", "yes"):
                    effective_force = True
                    print("  [+] Overwrite confirmed. Updating agent framework...")
                else:
                    print("  [*] Operation cancelled by user. Existing files left intact.")
                    sys.exit(0)
            except (KeyboardInterrupt, EOFError):
                print("\n[!] Operation cancelled by user.")
                sys.exit(0)
        else:
            print(f"\n[!] Error: Target workspace already contains .agents/: {ws_path}")
            print("    Re-run with --force (-f) to overwrite or update agent configuration.")
            sys.exit(1)

    # Execute Provisioning
    success = WorkspaceProvisioner.provision(
        workspace_path=ws_path,
        backend=chosen_backend,
        distro=chosen_distro,
        profiles=chosen_profiles,
        use_symlink=args.symlink,
        force=effective_force,
        skip_toolchain=chosen_skip_toolchain,
    )

    if not success:
        print("[!] Workspace provisioning failed.")
        sys.exit(1)

    # Post-provision Health Check
    health_report = HealthCheckRunner.check_workspace(ws_path, chosen_backend, chosen_distro)
    print_health_report(health_report)


if __name__ == "__main__":
    main()
