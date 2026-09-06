#!/usr/bin/env bash
# shellcheck disable=SC2024  # redirects target user-owned log file, not sudo
# ===========================================================================
# CTF Security Workstation Installer & Profile Manager (v2.0)
# Modular 3-Tier Architecture: Core, Category Profiles & Heavy Research
# ===========================================================================
#
# Usage:
#   bash scripts/install_ctf_tools.sh [OPTIONS] [PROFILE]
#
# Available Profiles:
#   core        - Tier 1: Essential system utilities, compilers, network tools, and base libraries
#   pwn         - Tier 2: Binary exploitation, ROP generation, seccomp bypass, and heap tooling
#   rev         - Tier 2: Reverse engineering, disassemblers, decompilers, and symbolics
#   crypto      - Tier 2: Cryptanalysis, lattice reduction, number theory, and solvers
#   forensics   - Tier 2: Digital forensics, memory analysis, PCAP carvers, and file parsing
#   stego       - Tier 2: Steganography, bit-plane inspection, and audio/image recovery
#   web         - Tier 2: Modern web exploitation, fuzzers, JWT, HTTP/2/3, and crawler pipelines
#   mobile      - Tier 2: Android & iOS reverse engineering, APK patching, and dynamic instrumentation
#   cloud       - Tier 2: Container security, Kubernetes inspection, and cloud metadata testing
#   ad          - Tier 2: Active Directory, Kerberos, SMB, and Windows penetration testing
#   kernel      - Tier 2: Linux kernel exploitation, eBPF inspection, debugging, and tracing
#   hardware    - Tier 2: IoT firmware, serial debugging, JTAG, and multi-architecture cross tools
#   web3        - Tier 2: Smart contract auditing, EVM interaction, and bytecode analysis
#   wasm        - Tier 2: WebAssembly binary analysis, disassembling, and execution
#   ai          - Tier 2: Machine learning security, adversarial models, and safetensors analysis
#   all         - Install all category profiles sequentially
#
# Legacy Modes (Backwards Compatibility):
#   python, apt, brew, gems, go, manual
#
# Options:
#   --list-profiles Show available profiles, descriptions, and package breakdowns
#   --verify [PROF] Verify tool availability and exact Python package versions
#   --dry-run       Preview packages and commands without executing installations
#   --force         Reinstall packages even if already present
#   --update        Upgrade packages to match locked definitions
#
# Examples:
#   bash scripts/install_ctf_tools.sh core
#   bash scripts/install_ctf_tools.sh web
#   bash scripts/install_ctf_tools.sh --verify pwn
#   bash scripts/install_ctf_tools.sh --list-profiles
#   bash scripts/install_ctf_tools.sh all

set -euo pipefail

# ---------------------------------------------------------------------------
# Globals & Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCKFILE="${SCRIPT_DIR}/ctf-tools.lock"
LOG_DIR="${HOME}/.ctf-tools"
CTF_VENV="${HOME}/.ctf-tools/venv"

DRY_RUN=false
FORCE=false
UPDATE=false
MODE=""
TARGET_PROFILE=""
LOG_FILE=""

FAILED=()
SUCCEEDED=()
SKIPPED=()

ALL_PROFILES=(
  "core" "pwn" "rev" "crypto" "forensics" "stego"
  "web" "mobile" "cloud" "ad" "kernel" "hardware"
  "web3" "wasm" "ai"
)

# ---------------------------------------------------------------------------
# Logging & Output Helpers
# ---------------------------------------------------------------------------

setup_logging() {
  mkdir -p "$LOG_DIR"
  LOG_FILE="${LOG_DIR}/install-$(date +%Y-%m-%d_%H%M%S).log"
  log_info "Session log: $LOG_FILE"
}

log_info()   { echo "==> $*" | tee -a "${LOG_FILE:-/dev/null}"; }
log_warn()   { echo "WARNING: $*" | tee -a "${LOG_FILE:-/dev/null}" >&2; }
log_error()  { echo "ERROR: $*" | tee -a "${LOG_FILE:-/dev/null}" >&2; }
log_detail() { echo "    $*" >> "${LOG_FILE:-/dev/null}"; }

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log_error "'$cmd' is required but not found in PATH"
    return 1
  fi
}

# ---------------------------------------------------------------------------
# Version & Installation Verification Checks
# ---------------------------------------------------------------------------

# Check if exact Python package version matches requested version via importlib.metadata
py_pkg_version_matches() {
  local pkg_name="$1"
  local req_ver="$2"

  python3 -c "
import sys
try:
    import importlib.metadata as m
    v = m.version('$pkg_name')
    req = '$req_ver'.strip()
    if not req or v == req:
        sys.exit(0)
    sys.exit(1)
except Exception:
    sys.exit(1)
" 2>/dev/null
}

# Check if an apt package is installed
apt_pkg_installed() {
  dpkg -s "$1" >/dev/null 2>&1
}

# Check if a Homebrew formula is installed
brew_pkg_installed() {
  brew list --formula "$1" >/dev/null 2>&1
}

# Check if a Ruby gem is installed
gem_installed() {
  local gem_name="$1"
  local gem_ver="${2:-}"
  if [ -n "$gem_ver" ]; then
    gem list -i "^${gem_name}$" -v "$gem_ver" >/dev/null 2>&1
  else
    gem list -i "^${gem_name}$" >/dev/null 2>&1
  fi
}

# ---------------------------------------------------------------------------
# Lockfile Query Engine
# ---------------------------------------------------------------------------

query_lockfile() {
  local profile="$1"
  local query_type="$2" # apt, pip, gem, go, verify_bins, manual, description

  if [ ! -f "$LOCKFILE" ]; then
    log_warn "Lockfile not found at $LOCKFILE, operating with internal fallbacks."
    return 1
  fi

  python3 -c "
import json, sys
try:
    with open('$LOCKFILE', 'r') as f:
        data = json.load(f)
    prof = data.get('profiles', {}).get('$profile', {})
    qtype = '$query_type'

    if qtype == 'description':
        print(prof.get('description', 'No description available.'))
    elif qtype == 'apt':
        for pkg in prof.get('apt', []):
            print(pkg)
    elif qtype == 'pip':
        pips = prof.get('pip', {})
        for name, meta in pips.items():
            ver = meta.get('version', '')
            imp = meta.get('import', name)
            if ver:
                print(f'{name}=={ver}:{imp}')
            else:
                print(f'{name}:{imp}')
    elif qtype == 'gem':
        for g in prof.get('gem', []):
            print(f\"{g.get('name')}:{g.get('version', '')}\")
    elif qtype == 'go':
        for g in prof.get('go', []):
            print(f\"{g.get('package')}@{g.get('version')}:{g.get('bin')}\")
    elif qtype == 'verify_bins':
        for b in prof.get('verify_bins', []):
            print(b)
    elif qtype == 'manual':
        for m in prof.get('manual', []):
            print(m)
except Exception as e:
    sys.exit(1)
" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Dedicated Virtualenv Setup (PEP 668 Compliant)
# ---------------------------------------------------------------------------

ensure_virtualenv() {
  require_cmd python3 || return 1

  if [ -n "${VIRTUAL_ENV:-}" ]; then
    return 0
  fi

  if [ ! -d "$CTF_VENV" ]; then
    if [ "$DRY_RUN" = true ]; then
      log_info "Would create dedicated virtualenv at $CTF_VENV"
      return 0
    fi
    log_info "Creating dedicated CTF virtualenv at $CTF_VENV"
    python3 -m venv "$CTF_VENV" >>"${LOG_FILE:-/dev/null}" 2>&1 || {
      log_warn "venv creation failed, defaulting to active Python runtime"
      return 0
    }
  fi

  if [ -f "$CTF_VENV/bin/activate" ]; then
    # shellcheck disable=SC1091
    source "$CTF_VENV/bin/activate"
    log_info "Active virtualenv: $CTF_VENV"
  fi
}

# ---------------------------------------------------------------------------
# Installation Primitives
# ---------------------------------------------------------------------------

install_apt_packages() {
  local packages=("$@")
  if [ ${#packages[@]} -eq 0 ]; then return 0; fi
  if ! command -v apt-get >/dev/null 2>&1; then
    log_warn "apt-get not available; skipping APT packages"
    return 0
  fi

  local to_install=()
  for pkg in "${packages[@]}"; do
    if [ "$FORCE" = false ] && apt_pkg_installed "$pkg"; then
      SKIPPED+=("apt:$pkg")
      continue
    fi
    to_install+=("$pkg")
  done

  if [ ${#to_install[@]} -eq 0 ]; then
    log_info "APT: All ${#packages[@]} packages already installed"
    return 0
  fi

  log_info "APT: Installing ${#to_install[@]} package(s): ${to_install[*]}"
  if [ "$DRY_RUN" = true ]; then return 0; fi

  sudo DEBIAN_FRONTEND=noninteractive apt-get update -q >>"${LOG_FILE:-/dev/null}" 2>&1 || true
  for pkg in "${to_install[@]}"; do
    if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$pkg" >>"${LOG_FILE:-/dev/null}" 2>&1; then
      SUCCEEDED+=("apt:$pkg")
    else
      log_warn "APT installation failed: $pkg"
      FAILED+=("apt:$pkg")
    fi
  done
}

install_pip_packages() {
  local entries=("$@")
  if [ ${#entries[@]} -eq 0 ]; then return 0; fi
  ensure_virtualenv

  local to_install=()
  local to_install_names=()

  for entry in "${entries[@]}"; do
    local spec="${entry%%:*}"
    local name="${spec%%==*}"
    local ver="${spec#*==}"
    if [ "$ver" = "$spec" ]; then ver=""; fi

    if [ "$FORCE" = false ] && [ "$UPDATE" = false ] && py_pkg_version_matches "$name" "$ver"; then
      SKIPPED+=("pip:$name")
      continue
    fi

    to_install+=("$spec")
    to_install_names+=("$name")
  done

  if [ ${#to_install[@]} -eq 0 ]; then
    log_info "Pip: All ${#entries[@]} package(s) up-to-date and matching locked versions"
    return 0
  fi

  log_info "Pip: Installing/Updating ${#to_install[@]} package(s): ${to_install_names[*]}"
  if [ "$DRY_RUN" = true ]; then return 0; fi

  python3 -m pip install --upgrade pip setuptools wheel >>"${LOG_FILE:-/dev/null}" 2>&1 || true

  for spec in "${to_install[@]}"; do
    local name="${spec%%==*}"
    if python3 -m pip install "$spec" >>"${LOG_FILE:-/dev/null}" 2>&1; then
      SUCCEEDED+=("pip:$name")
    else
      log_warn "Pip installation failed: $spec"
      FAILED+=("pip:$name")
    fi
  done
}

install_gem_packages() {
  local entries=("$@")
  if [ ${#entries[@]} -eq 0 ]; then return 0; fi
  if ! command -v gem >/dev/null 2>&1; then
    log_warn "gem command not found; skipping Ruby gems"
    for e in "${entries[@]}"; do SKIPPED+=("gem:${e%%:*}"); done
    return 0
  fi

  for entry in "${entries[@]}"; do
    local name="${entry%%:*}"
    local ver="${entry##*:}"

    if [ "$FORCE" = false ] && gem_installed "$name" "$ver"; then
      SKIPPED+=("gem:$name")
      continue
    fi

    log_info "Gem: Installing $name ($ver)"
    if [ "$DRY_RUN" = true ]; then continue; fi

    local cmd=(gem install "$name")
    if [ -n "$ver" ]; then cmd+=(-v "$ver"); fi

    if "${cmd[@]}" >>"${LOG_FILE:-/dev/null}" 2>&1; then
      SUCCEEDED+=("gem:$name")
    else
      log_warn "Gem installation failed: $name"
      FAILED+=("gem:$name")
    fi
  done
}

install_go_packages() {
  local entries=("$@")
  if [ ${#entries[@]} -eq 0 ]; then return 0; fi
  if ! command -v go >/dev/null 2>&1; then
    log_warn "go command not found; skipping Go binaries"
    for e in "${entries[@]}"; do SKIPPED+=("go:${e##*:}"); done
    return 0
  fi

  for entry in "${entries[@]}"; do
    local spec="${entry%%:*}"
    local bin="${entry##*:}"

    if [ "$FORCE" = false ] && command -v "$bin" >/dev/null 2>&1; then
      SKIPPED+=("go:$bin")
      continue
    fi

    log_info "Go: Installing $bin from $spec"
    if [ "$DRY_RUN" = true ]; then continue; fi

    if go install "$spec" >>"${LOG_FILE:-/dev/null}" 2>&1; then
      SUCCEEDED+=("go:$bin")
    else
      log_warn "Go installation failed: $bin"
      FAILED+=("go:$bin")
    fi
  done
}

# ---------------------------------------------------------------------------
# Profile Dispatcher
# ---------------------------------------------------------------------------

install_profile() {
  local profile="$1"
  log_info "Processing Profile: [$profile]"

  local desc
  desc="$(query_lockfile "$profile" "description" || echo "")"
  if [ -n "$desc" ]; then
    log_info "Description: $desc"
  fi

  # 1. APT packages
  mapfile -t apt_pkgs < <(query_lockfile "$profile" "apt" || true)
  if [ ${#apt_pkgs[@]} -gt 0 ]; then
    install_apt_packages "${apt_pkgs[@]}"
  fi

  # 2. Pip packages
  mapfile -t pip_pkgs < <(query_lockfile "$profile" "pip" || true)
  if [ ${#pip_pkgs[@]} -gt 0 ]; then
    install_pip_packages "${pip_pkgs[@]}"
  fi

  # 3. Ruby Gems
  mapfile -t gem_pkgs < <(query_lockfile "$profile" "gem" || true)
  if [ ${#gem_pkgs[@]} -gt 0 ]; then
    install_gem_packages "${gem_pkgs[@]}"
  fi

  # 4. Go binaries
  mapfile -t go_pkgs < <(query_lockfile "$profile" "go" || true)
  if [ ${#go_pkgs[@]} -gt 0 ]; then
    install_go_packages "${go_pkgs[@]}"
  fi

  # 5. Manual Tools Advisories
  mapfile -t manual_notes < <(query_lockfile "$profile" "manual" || true)
  if [ ${#manual_notes[@]} -gt 0 ]; then
    echo ""
    echo "  [i] Note for profile [$profile] - Additional tools available:"
    for m in "${manual_notes[@]}"; do
      echo "      * $m"
    done
    echo ""
  fi
}

# ---------------------------------------------------------------------------
# Verification Engine
# ---------------------------------------------------------------------------

verify_profile() {
  local profile="$1"
  echo "======================================================================"
  echo "[*] VERIFYING PROFILE: [$profile]"
  echo "======================================================================"

  ensure_virtualenv 2>/dev/null || true

  local found_bins=()
  local missing_bins=()
  local found_py=()
  local missing_py=()

  # 1. Check binaries
  mapfile -t bins < <(query_lockfile "$profile" "verify_bins" || true)
  for b in "${bins[@]}"; do
    [ -z "$b" ] && continue
    if command -v "$b" >/dev/null 2>&1; then
      found_bins+=("$b")
    else
      missing_bins+=("$b")
    fi
  done

  # 2. Check Pip Packages with exact version validation
  mapfile -t pips < <(query_lockfile "$profile" "pip" || true)
  for p in "${pips[@]}"; do
    [ -z "$p" ] && continue
    local spec="${p%%:*}"
    local name="${spec%%==*}"
    local ver="${spec#*==}"
    if [ "$ver" = "$spec" ]; then ver=""; fi

    if py_pkg_version_matches "$name" "$ver"; then
      found_py+=("$name ($ver)")
    else
      missing_py+=("$name ($ver)")
    fi
  done

  echo "  - CLI Binaries Verified:   ${#found_bins[@]}/${#bins[@]}"
  if [ ${#missing_bins[@]} -gt 0 ]; then
    echo "    Missing Binaries: ${missing_bins[*]}"
  fi

  echo "  - Python Packages Verified: ${#found_py[@]}/${#pips[@]}"
  if [ ${#missing_py[@]} -gt 0 ]; then
    echo "    Missing/Version Mismatch: ${missing_py[*]}"
  fi
  echo ""
}

verify_all() {
  local target="${1:-all}"
  if [ "$target" = "all" ]; then
    for p in "${ALL_PROFILES[@]}"; do
      verify_profile "$p"
    done
  else
    verify_profile "$target"
  fi
}

# ---------------------------------------------------------------------------
# List Profiles
# ---------------------------------------------------------------------------

list_profiles() {
  echo "======================================================================"
  echo " CTF Security Workstation - Available Profiles (v2.0)"
  echo "======================================================================"
  for p in "${ALL_PROFILES[@]}"; do
    local desc
    desc="$(query_lockfile "$p" "description" || echo "")"
    printf "  %-12s : %s\n" "$p" "$desc"
  done
  printf "  %-12s : %s\n" "all" "Install all 15 category profiles sequentially"
  echo "======================================================================"
}

# ---------------------------------------------------------------------------
# Execution Summary
# ---------------------------------------------------------------------------

print_summary() {
  echo ""
  echo "========================================"
  echo " Installation Summary"
  echo "========================================"
  echo " Installed: ${#SUCCEEDED[@]}"
  echo " Skipped:   ${#SKIPPED[@]} (already up to date)"
  echo " Failed:    ${#FAILED[@]}"
  if [ ${#FAILED[@]} -gt 0 ]; then
    echo ""
    echo " Failed Packages:"
    for f in "${FAILED[@]}"; do
      echo "   - $f"
    done
  fi
  echo "========================================"
  if [ -n "${LOG_FILE:-}" ]; then
    echo " Session Log: $LOG_FILE"
    echo "========================================"
  fi
}

# ---------------------------------------------------------------------------
# CLI Argument Parser & Entry Point
# ---------------------------------------------------------------------------

main() {
  local positional=()

  while [ $# -gt 0 ]; do
    case "$1" in
      --dry-run)       DRY_RUN=true; shift ;;
      --force)         FORCE=true; shift ;;
      --update)        UPDATE=true; shift ;;
      --list-profiles) list_profiles; exit 0 ;;
      --verify)        MODE="verify"; shift ;;
      -*)              echo "Unknown option: $1" >&2; exit 2 ;;
      *)               positional+=("$1"); shift ;;
    esac
  done

  TARGET_PROFILE="${positional[0]:-}"

  # Verification Mode
  if [ "$MODE" = "verify" ]; then
    verify_all "${TARGET_PROFILE:-all}"
    exit 0
  fi

  # Default to 'all' if no positional profile was supplied
  TARGET_PROFILE="${TARGET_PROFILE:-all}"

  # Backwards compatibility with legacy mode strings
  case "$TARGET_PROFILE" in
    python) TARGET_PROFILE="core" ;;
    apt)    TARGET_PROFILE="core" ;;
    brew)   TARGET_PROFILE="core" ;;
    gems)   TARGET_PROFILE="pwn" ;;
    go)     TARGET_PROFILE="web" ;;
    manual) TARGET_PROFILE="rev" ;;
  esac

  if [ "$DRY_RUN" = false ]; then
    setup_logging
  fi

  if [ "$TARGET_PROFILE" = "all" ]; then
    log_info "Initiating Full Workstation Installation Across All Profiles"
    for p in "${ALL_PROFILES[@]}"; do
      install_profile "$p"
    done
  else
    install_profile "$TARGET_PROFILE"
  fi

  print_summary

  if [ ${#FAILED[@]} -gt 0 ]; then
    exit 1
  fi
}

main "$@"
