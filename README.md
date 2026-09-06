# CTF-Agent: Autonomous Security Intelligence & Competitive Exploitation Framework

[![npm version](https://img.shields.io/npm/v/ctf-agent.svg)](https://www.npmjs.com/package/ctf-agent)
[![Release](https://img.shields.io/badge/release-v1.3.2-blue.svg)](https://github.com/nvtruongops/CTF-Agent/releases)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Docker Image](https://img.shields.io/badge/docker-ghcr.io%2Fnvtruongops%2Fctf--agent-blue.svg)](https://github.com/nvtruongops/CTF-Agent/pkgs/container/ctf-agent)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **A High-Performance AI Agent Architecture for Live CTF Competitions, Lab Vulnerability Audits, and Security Research.**  
> Compatible with **Antigravity IDE**, **Cursor**, **Claude Code**, and **OpenAI Codex/Agent** ecosystems.

---

## Quick Navigation

- [CRITICAL: Environment Backend Selection (WSL vs Docker)](#critical-environment-backend-selection-wsl-vs-docker)
- [Operational Modes: Blitz vs Deep Analysis](#operational-modes-blitz-vs-deep-analysis)
- [LLM Safety Guardrails & Policy Compliance](#llm-safety-guardrails--policy-compliance)
- [Machine-Enforced Scope Guard](#machine-enforced-scope-guard-runtime-execution-boundary)
- [Specialized Category Skills](#specialized-category-skills)
- [Parallel Triage & High-Speed Reconnaissance](#parallel-triage--high-speed-reconnaissance-p0-engine)
- [Quick Start & Workspace Installation](#quick-start--workspace-installation)
- [References & Deep Knowledge Base](#references--deep-knowledge-base)
- [Constitution & Architectural Governance](#constitution--architectural-governance)

---

## CRITICAL: Environment Backend Selection (WSL vs Docker)

> [!CAUTION]
> ### ANTI-DISK-OVERFLOW RULE (DO NOT INITIALIZE BOTH ENVIRONMENTS!)
> **DO NOT build the Docker container AND install the full WSL toolchain at the same time.**  
> Installing full multi-tier CTF tools (compilers, SMT solvers, `sagemath`, `pwntools`, `angr`, `torch`, `volatility3`, `hashcat`) requires **15 to 25 GB of disk space per environment**.  
> Initializing **BOTH** will consume **30 to 50 GB+**, risking catastrophic host drive exhaustion and environment conflicts.  
>
> **AI Agents & Players MUST detect and choose EXACTLY ONE backend:**

```
                               ┌─────────────────────────────┐
                               │  Choose ONE Backend Engine  │
                               └──────────────┬──────────────┘
                                              │
               ┌──────────────────────────────┴──────────────────────────────┐
               ▼                                                             ▼
     [OPTION A: WSL Kali Linux]                                    [OPTION B: Docker Sandbox]
  Best for: Windows Host Development                            Best for: Linux, macOS, or CI/CD
  - Zero VM overhead, fast host I/O                             - 100% ephemeral and disposable
  - Direct file access via /mnt/c/Users/...                     - Clean host isolation
  - Direct GUI/GDB debugging support                            - Standardized container image
```

### Option A: WSL Kali Linux (Recommended on Windows)
1. **Verify WSL Kali Availability**:
   ```powershell
   wsl -d kali-linux uname -a
   ```
2. **Install CTF Toolchain Inside WSL (Select Profiles to Save Disk)**:
   ```bash
   # Inside WSL or wrapped from PowerShell:
   wsl -d kali-linux bash -c "bash scripts/install_ctf_tools.sh core"
   # To install specific profiles: pwn, rev, crypto, web, forensics
   wsl -d kali-linux bash -c "bash scripts/install_ctf_tools.sh pwn crypto web"
   ```
3. **Execution Wrapper**:
   ```powershell
   wsl -d kali-linux bash -c "source ~/.ctf-tools/venv/bin/activate && <command>"
   ```

### Option B: Docker Container Sandbox (Recommended on Linux / macOS / CI)
1. **Build Container Image**:
   ```bash
   docker compose build
   ```
2. **Execute Inside Container Sandbox**:
   ```bash
   docker compose run --rm ctf-agent <command>
   ```
3. **Interactive Shell**:
   ```bash
   docker compose run --rm ctf-agent /bin/bash
   ```

---

## Operational Profiles & Specialized Modes (Text Flags)

> [!TIP]
> ### HOW MODES WORK (PROMPT TEXT FLAGS)
> Operational modes (`--fast`, `--blitz`, `--deep`, `--lab`) are **instructional text flags** recognized by the Agent through [AGENTS.md](AGENTS.md).  
> **How to use**: Simply write the flags as plain text in your chat prompt or combine them with slash commands (e.g. `/ctf-web --fast <url>` or `/solve-challenge --mode blitz <dir>`).  
> *(Note: In Antigravity IDE, typing `@` searches files/symbols in the workspace; modes are passed directly as text flags in your prompt text).*

`CTF-Agent` provides 3 specialized agent personas designed to eliminate multi-agent refusal cascades and optimize for both speedrun competitions and deep lab audits:

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   CTF-AGENT PERSONA MATRIX                                      │
├──────────────────────────┬───────────────────────────────┬──────────────────────────────────────┤
│  MASTER ORCHESTRATOR     │  BLITZ / SPEEDRUN SOLVER      │  DEEP RESEARCH AUDITOR               │
│  @ctf-controller         │  @ctf-speedrun (--blitz)      │  @ctf-analyzer (--deep)              │
├──────────────────────────┼───────────────────────────────┼──────────────────────────────────────┤
│  Role: State Controller  │  Role: First Blood Hunter     │  Role: Security Auditor / RCA        │
│  Enforces: Shallow depth │  Stop Condition: On Flag HALT │  Stop Condition: Verified Writeup    │
│  Context: SCO & Envelope │  Documentation: ZERO overhead │  Documentation: 5-Section writeup    │
│  Refusal: 3-Tier Router  │  Workspace: Auto-purge debris │  Workspace: Organize resources/      │
│  Fallback: Deterministic │  Output: Verified Flag Banner │  Output: Authoritative RCA report    │
└──────────────────────────┴───────────────────────────────┴──────────────────────────────────────┘
```

### 1. Master Controller (`@ctf-controller` / `/solve-challenge`)
Use as the primary entrypoint for complex multi-step labs or challenges.
- **Prompt Examples**:
  - `/solve-challenge http://challenge.ctf.site:8000`
  - `/solve-challenge ./challenge_directory`
- **Security Context & Task Envelope**: Wraps target endpoints or local lab files in machine-readable context objects (`security_context`, `task_envelope`) to prevent subagents from evaluating prompts with zero inherited context.
- **Shallow Orchestration (Depth = 1)**: Dispatches directly to a single specialist skill or agent. Prohibits deep recursive agent chaining (`Agent A -> Agent B -> Agent C`).
- **3-Tier Refusal Router**: Automatically classifies model refusals (Type A Wording, Type B Ambiguity, Type C Hard Policy) and shifts execution immediately to deterministic CLI tools without entering infinite paraphrasing loops.

### 2. Blitz / Speedrun Mode (`@ctf-speedrun` / `--blitz` / `--fast`)
Use during active CTF competitions where time is points.
- **Prompt Examples**:
  - `/ctf-web --fast http://challenge.ctf.site:8080`
  - `/solve-challenge --mode blitz ./pwn_challenge`
  - `--blitz Solve this crypto puzzle: c = 12345, e = 3, n = 99999`
- **Stop-on-Flag (HALT immediately)**: The instant a valid flag matching target regex (`flag{...}`, `picoCTF{...}`) is confirmed, all tool invocations and probing **stop immediately**.
- **High-Visibility Flag Banner**:
  ```text
  ============================================================
  [+] FLAG ACQUIRED: picoCTF{example_flag_value}
  Confidence: 100% | Source: HTTP 200 Response
  ============================================================
  ```
- **Automated Workspace Cleanup**:
  ```bash
  python3 scripts/workspace_cleaner.py --fast
  ```
  Automatically removes temporary scratch files (`test*.py`, `fuzz*.py`, `tmp*`, `core.*`, `payload*.bin`), keeping only the original challenge files and the winning `solve.py`.
- **Zero Overhead**: Does **not** invoke `ctf-writeup` and does **not** create `writeup.md`.

### 3. Deep Analysis / Lab Mode (`@ctf-analyzer` / `--deep` / `--lab`)
Use when solving challenge labs (HackTheBox, PortSwigger, pwnable.tw), post-mortems, or security research.
- **Prompt Examples**:
  - `/ctf-pwn --deep ./vulnerable_binary`
  - `/solve-challenge --mode deep ./web_lab`
  - `--lab Perform deep root cause analysis and generate writeup`
- **Root Cause Analysis (RCA)**: Deep analysis of memory corruption layouts, AST flaws, or cryptographic mathematical proofs.
- **Directory Standardization**:
  ```bash
  python3 scripts/workspace_cleaner.py --deep
  ```
  Enforces clean lab layout: only `writeup.md`, `solve.py`, and a `resources/` folder containing all challenge binaries, PCAPs, dumps, and source archives.
- **Standardized Writeup**: Automatically invokes `ctf-writeup` to author a publication-ready 5-section `writeup.md`.

---

## LLM Safety Guardrails & Policy Compliance (Prompt Sanitization & Guardrail Navigation)

When working on cybersecurity labs (HackTheBox, TryHackMe, PortSwigger) or participating in CTF competitions, user prompts and challenge descriptions often contain aggressive adversarial terminology (`exploit`, `attack`, `bypass policy`, `reverse shell`, `weaponize`...). Modern backend LLM safety classifiers (Gemini, Claude, GPT) can mistakenly flag these requests as unauthorized intrusions and **prematurely halt agent execution mid-lab**.

`CTF-Agent` integrates an authorized educational framing standard and an automated **Prompt Policy Sanitizer** to eliminate false-positive policy blocks while preserving 100% technical solving capabilities:

### 1. How to Apply in Labs & CTF Competitions

Before submitting complex prompts or challenge descriptions to the Agent, run the sanitizer utility to automatically rewrite the text into safe academic phrasing and attach the authorized educational context preamble:

```bash
# Sanitize an input prompt with high-risk keywords:
python scripts/prompt_policy_sanitizer.py "Write an exploit payload to bypass security policy and extract the flag"

# Sanitize a prompt with specific language support:
python scripts/prompt_policy_sanitizer.py "Write script to bypass filter and capture flag" --lang en

# Scan and sanitize an entire challenge prompt file or writeup:
python scripts/prompt_policy_sanitizer.py --file path/to/prompt.txt --check
```

### 2. Automated Sanitization Mechanism

- **Risk Scoring**: Assesses policy risk from `SAFE` (0) to `CRITICAL` (100) across 5 high-risk trigger families (Evasion, Redteam, Exploit, Payload, Exfiltration).
- **Academic Lexicon Standard**: Automatically replaces adversarial attack jargon with defensive and diagnostic testing equivalents:
  - *exploit vulnerability* -> *verify vulnerability with proof-of-concept (PoC)*
  - *bypass policy* -> *evaluate mitigation boundaries*
  - *steal credentials / exfiltrate* -> *retrieve challenge flag token*
  - *redteam attack* -> *diagnostic security assessment*
- **Educational CTF Context Preamble**: Injects explicit authorized testing boundaries (`localhost`, Docker, designated CTF target) to satisfy upstream safety filters.
- **Path & Link Preservation**: Automatically preserves markdown links `[text](target.md)` and URLs without unwanted corruption.

For comprehensive guidelines and full replacement dictionaries, see [ctf-safety-framing-rules.md](rules/ctf-safety-framing-rules.md) and [llm-safety-and-policy-compliance.md](references/llm-safety-and-policy-compliance.md).

### 3. Machine-Enforced Scope Guard (Runtime Execution Boundary)

While the Prompt Policy Sanitizer protects prompts from semantic upstream LLM filter rejections, the **Scope Guard** ([scripts/scope_guard.py](scripts/scope_guard.py)) converts the Security Context Object (SCO) and Task Envelope into an active, machine-enforced runtime execution fence.

- **Network Boundary Validation**: Only authorized CTF targets are permitted:
  - Local loopback: `127.0.0.1`, `localhost`, `::1`
  - RFC1918 private subnets: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
  - Authorized CTF domains & competition platforms: `*.challs.io`, `*.picoctf.net`, `*.ctfd.io`, `*.tryhackme.com`, `*.hackthebox.com`, `*.flagyard.com`, and localhost ports.
  - Arbitrary external IP addresses and unauthorized internet endpoints are rejected with explicit policy violations.
- **Prohibited Action Guard**: Automatically intercepts and blocks commands containing:
  - Destructive disk actions (`rm -rf /`, `mkfs`, `dd if=/dev/zero`)
  - Backdoor persistence mechanisms (`crontab`, systemd services, SSH key installation in `~/.ssh/authorized_keys`, root password modification)
  - Wide automated network sweeps (`nmap -iR`, masscan against external CIDR blocks)
- **Runtime Execution**:
  ```bash
  # Validate a target endpoint before probing:
  python scripts/scope_guard.py http://127.0.0.1:8080

  # Validate a diagnostic CLI command before running:
  python scripts/scope_guard.py --command "checksec --file=chall"

  # Generate a formal Security Context Object (SCO):
  python scripts/scope_guard.py --target http://chall.ctf.site:9000 --json
  ```

---

## Specialized Category Skills

`CTF-Agent` equips models with 11 domain-specific skills accessible via slash commands or subagent delegation:

| Skill | Description | Key Capabilities |
|:---|:---|:---|
| [`solve-challenge`](skills/solve-challenge/SKILL.md) | **Master Dispatcher & Orchestrator** | Hint-First triage, category routing, mode branching (Blitz vs Deep). |
| [`ctf-web`](skills/ctf-web/SKILL.md) | **Web Vulnerability Assessment** | SQLi, SSTI, JWT verification, prototype pollution, RSC Flight RCE, SSRF. |
| [`ctf-pwn`](skills/ctf-pwn/SKILL.md) | **Binary Security Analysis** | Glibc heap (House of Apple 2, TLS dtors), ROP, ret2libc, boundary testing. |
| [`ctf-crypto`](skills/ctf-crypto/SKILL.md) | **Cryptanalysis & Math** | RSA, ECC, LLL/BKZ lattice reduction, HNP/CVP, padding oracle, ZKP. |
| [`ctf-reverse`](skills/ctf-reverse/SKILL.md) | **Reverse Engineering** | Anti-analysis, custom VMs, WASM, `.pyc` (`pycdc`), Ghidra/radare2/GDB. |
| [`ctf-forensics`](skills/ctf-forensics/SKILL.md) | **Digital Forensics** | Memory dumps (Volatility 3), PCAP analysis, disk recovery, steganography. |
| [`ctf-ai-ml`](skills/ctf-ai-ml/SKILL.md) | **AI & Machine Learning** | Adversarial ML, model robustness, extraction evaluation, AI puzzle triage. |
| [`ctf-osint`](skills/ctf-osint/SKILL.md) | **Open Source Intelligence** | Geolocation, social media tracking, Tor relay tracing, DNS footprinting. |
| [`ctf-misc`](skills/ctf-misc/SKILL.md) | **Miscellaneous & Jails** | PyJails, bash jails, esoteric encodings, RF/SDR signals, game reversing. |
| [`ctf-malware`](skills/ctf-malware/SKILL.md) | **Malware Analysis** | C2 protocol decoding, PE/.NET unpackers, obfuscated script analysis. |
| [`ctf-writeup`](skills/ctf-writeup/SKILL.md) | **Write-up Generator** | Standardized 5-section submission writeup and directory organizer. |

### Custom Skill Extension & Envelope Validation

When adding external or custom CTF skills into `.agents/skills/`, run the built-in validator ([scripts/skill_validator.py](scripts/skill_validator.py)) to ensure prompt envelope compatibility and prevent model policy rejections:

```bash
# Validate a specific custom skill:
ctf-agent validate-skill .agents/skills/my-custom-skill

# Audit all skills in the workspace:
ctf-agent validate-skill --all

# Via NPX:
npx ctf-agent validate-skill .agents/skills/my-custom-skill
```

**Compatibility Rules Checked**:
- **Shallow Orchestration (Depth <= 1)**: Verifies the skill operates as a direct specialist without recursive subagent chaining.
- **YAML Frontmatter Integrity**: Verifies `name`, `description` (>= 20 chars), and checks against collisions with reserved core skills.
- **Operational Mode Handling**: Checks for Blitz Mode (Stop-on-Flag) and Deep Mode (RCA / writeup).
- **LLM Safety Policy Lexicon**: Flags unshielded adversarial triggers (`evil_payload`, `jailbreak`, `weaponize`) and recommends academic diagnostic equivalents.
- **Command Boundary Guard**: Intercepts destructive host commands (`rm -rf /`, `mkfs`) and backdoor persistence attempts (`crontab`, `authorized_keys`).

---

## Parallel Triage & High-Speed Reconnaissance (P0 Engine)

To maximize Time-to-Flag during live CTF competitions, `CTF-Agent` integrates a high-speed parallel reconnaissance scheduler ([scripts/parallel_triage.py](scripts/parallel_triage.py)) that executes Tier 1 and Tier 2 diagnostics concurrently:

```
                               ┌────────────────────────────────┐
                               │   Target Challenge Diagnostic  │
                               └───────────────┬────────────────┘
                                               │
               ┌───────────────────────────────┴───────────────────────────────┐
               ▼                                                               ▼
     [Binary / ELF Target]                                           [Web / HTTP Target]
  ThreadPoolExecutor Concurrency                                  ThreadPoolExecutor Concurrency
  - Pure-Python ELF Parser (Arch, Endian, NX, PIE)               - HTTP Server & Powered-By Headers
  - checksec security mitigations                                - /robots.txt & /sitemap.xml leaks
  - strings pattern match (flags, /bin/sh, libc)                 - Sensitive paths (.git/HEAD, .env)
  - readelf / symbol table analysis                              - Flag regex candidate pre-scan
               │                                                               │
               └───────────────────────────────┬───────────────────────────────┘
                                               ▼
                               ┌────────────────────────────────┐
                               │    Synthesized Triage Plan     │
                               │   - Discovered Vulnerabilities │
                               │   - Recommended Specialist     │
                               │   - Immediate Exploit Vector   │
                               └────────────────────────────────┘
```

- **Zero-Dependency Native ELF Parser**: Reads ELF binary headers using pure Python standard library (`struct`), extracting machine architecture, bitness, endianness, entry point, section counts, NX stack protection, and PIE position independence without requiring external tools.
- **Concurrent Execution Modes**:
  ```bash
  # Concurrent triage of a binary challenge:
  python scripts/parallel_triage.py ./chall.bin

  # Concurrent triage of a web challenge:
  python scripts/parallel_triage.py http://127.0.0.1:8080

  # Machine-readable output for automated agent pipelines:
  python scripts/parallel_triage.py ./chall.bin --json
  ```

---

## Quick Start & Workspace Installation

### Method 0: Intelligent Workspace Initialization (Triple-Engine Architecture)

```
                            ┌─────────────────────────────────────────┐
                            │    User Workspace Initialization        │
                            └────────────────────┬────────────────────┘
                                                 │
                ┌────────────────────────────────┼────────────────────────────────┐
                ▼                                ▼                                ▼
      [1. Zero-Install NPX]           [2. Python Workstation]           [3. Modern UV Toolchain]
       npx ctf-agent init               ctf-agent init (pip)           uvx --from git+... init
                │                                │                                │
                └────────────────────────────────┼────────────────────────────────┘
                                                 ▼
                            ┌─────────────────────────────────────────┐
                            │      Step 1: Preflight Detection        │
                            │   - OS, CPU, RAM & Disk Storage Free    │
                            │   - WSL2 & Kali Linux Distro Status     │
                            │   - Docker CLI & Daemon Connectivity    │
                            │   - Check for Existing .agents/ Folder  │
                            └────────────────────┬────────────────────┘
                                                 │
                                                 ▼
                            ┌─────────────────────────────────────────┐
                            │    Step 2: Backend Capability Score     │
                            │   WSL Kali Score vs Docker Daemon Score │
                            │   (Objective transparent recommendation)│
                            └────────────────────┬────────────────────┘
                                                 │
                                                 ▼
                            ┌─────────────────────────────────────────┐
                            │   Step 3: Workload Purpose Selection    │
                            │   [1] Live CTF: core, pwn, web, crypto  │
                            │   [2] Security Lab: 10 deep profiles    │
                            │   [3] Rev & Binary: pwn, rev, kernel    │
                            │   [4] Full Workstation: all 15 profiles │
                            └────────────────────┬────────────────────┘
                                                 │
                                                 ▼
                            ┌─────────────────────────────────────────┐
                            │   Step 4: Provision & Conflict Guard    │
                            │   - If .agents exists: Prompt / Confirm │
                            │   - Deploy .agents/ & AGENTS.md config  │
                            │   - Preserve solve.py & resources/      │
                            │   - Provision Toolchain into Backend    │
                            └────────────────────┬────────────────────┘
                                                 │
                                                 ▼
                            ┌─────────────────────────────────────────┐
                            │      Step 5: Health Verification        │
                            │   Verify subagents, venv & CLI tools    │
                            │   [OK] WORKSPACE READY TO SOLVE!        │
                            └─────────────────────────────────────────┘
```

CTF-Agent provides three interchangeable execution engines tailored to different developer environments and host constraints:

#### 1. Zero-Install Global NPX (`npx ctf-agent init`) - Recommended Default
Zero-clone setup for developers accustomed to npm and modern command-line toolchains:
```bash
# Initialize current workspace (Zero clone, zero manual install):
npx ctf-agent init

# Target a specific challenge workspace:
npx ctf-agent init /path/to/ctf-workspace

# Run preflight inspection in dry-run mode (zero filesystem writes):
npx ctf-agent init --dry-run

# Or run bleeding-edge unreleased commits directly from GitHub:
npx github:nvtruongops/CTF-Agent init /path/to/ctf-workspace
```
> [!NOTE]
> **Prerequisites**: Node.js (v18+) and Python 3 (v3.10+). The `ctf-agent` npm package acts as a lightweight global launcher bridge that orchestrates the Python backend engine.

#### 2. Native Python Security Workstation (`ctf-agent` / `ctf_agent_cli.py`)
Pure standard library execution with zero third-party dependencies. Recommended for headless Linux boxes, Kali Linux, offline environments, or systems where Node.js is not installed:
```bash
# Scenario A: Globally installed CLI command (available anywhere):
pip install -e .  # run once inside cloned repository
ctf-agent init /path/to/ctf-workspace

# Scenario B: Run directly from cloned repository root:
python ctf_agent_cli.py init /path/to/ctf-workspace

# Automated unattended setup (auto-selects highest-scored backend and purpose):
ctf-agent init /path/to/ctf-workspace --auto --purpose live-ctf

# Preflight analysis and dry-run inspection:
ctf-agent init --dry-run

# Health check verification on an existing workspace:
ctf-agent init /path/to/ctf-workspace --check-only
```
> [!IMPORTANT]
> **Prevent Relative Path Errors**: Do not execute `python scripts/ctf_init.py` from outside the cloned `CTF-Agent` directory. If you are in an arbitrary target folder without cloning, use `npx ctf-agent init`, the installed `ctf-agent` CLI, or the `uvx` toolchain below.

#### 3. Ephemeral Modern Python Toolchain (`uvx`)
Ultra-fast ephemeral execution powered by the Rust-based `uv` package manager without Node.js or local `venv` activation:
```bash
# Execute directly from repository source without cloning or manual installation:
uvx --from git+https://github.com/nvtruongops/CTF-Agent ctf-agent init

# Target a specific workspace:
uvx --from git+https://github.com/nvtruongops/CTF-Agent ctf-agent init /path/to/ctf-workspace

# Automated speedrun profile:
uvx --from git+https://github.com/nvtruongops/CTF-Agent ctf-agent init --auto --purpose live-ctf
```
> [!NOTE]
> **Why `--from git+...` is Required**: Because `ctf-agent` is hosted on GitHub and npm rather than PyPI, the `--from git+https://github.com/nvtruongops/CTF-Agent` flag directs `uvx` to build directly from the verified source repository.

---

### Workspace & Skill Updates (`ctf-agent update`)

Keep deployed CTF workspaces up to date with new skills, agent personas, rules, and security references without losing custom modifications or challenge files:

```bash
# Method 1: Zero-install NPX:
npx ctf-agent update /path/to/ctf-workspace

# Method 2: Native CLI (if installed via pip or npm link):
ctf-agent update /path/to/ctf-workspace

# Method 3: Ephemeral modern toolchain (uvx):
uvx --from git+https://github.com/nvtruongops/CTF-Agent ctf-agent update /path/to/ctf-workspace

# Method 4: Native Python from cloned repository root:
python ctf_agent_cli.py update /path/to/ctf-workspace

# Preview planned skill & rule updates without writing changes:
npx ctf-agent update --dry-run

# Only synchronize skills (preserve rules, agents, and scripts):
npx ctf-agent update --skills-only

# Update global configuration (~/.gemini/config/):
python scripts/ctf_update.py --global
```

**Zero Data Loss Guarantees**:
- **Conflict Guard**: Inspects SHA-256 hashes against `skills-lock.json`. If you made local modifications to a skill, it creates a safe backup (`SKILL.md.bak`) before updating.
- **Custom Skills & Non-Skill Directory Preservation**: Custom skills in `.agents/skills/`, custom subagents in `.agents/agents/`, custom rules in `.agents/rules/`, and custom scripts in `.agents/scripts/` that are not part of upstream CTF-Agent are preserved completely untouched without wholesale directory wipes.
- **Automated Backups for Modified Support Files**: Any modified upstream files in `.agents/rules/`, `.agents/agents/`, `.agents/references/`, or `scripts/` receive `.bak` backup files prior to update.
- **Challenge Assets Protected**: Exploit scripts (`solve.py`), challenge binaries (`resources/`), CTF notes (`notes/`), and credentials (`.env`) are never overwritten or deleted.

---

### Method 1: Deploy CTF-Agent into a CTF Challenge Project (`.agents/`)
Deploy CTF-Agent as an `.agents` bundle into any target CTF directory:
```bash
# Using symlinks/junctions (live synced with updates):
python scripts/install_as_agent.py /path/to/ctf-workspace --symlink

# Or standalone copy:
python scripts/install_as_agent.py /path/to/ctf-workspace
```

### Method 2: Global Installation Across All Projects
Install skills, rules, and subagents globally into `~/.gemini/config/`:
```bash
python scripts/install_as_agent.py --global
```

### Method 3: Direct Usage Within This Workspace
This workspace already has `.agents/` configured. You can start prompting directly using slash commands and text flags:
- **Master Orchestrator**: `/solve-challenge <target-url-or-dir>`
- **Speedrun / Blitz Mode (Fast Solve, Stop-on-Flag)**: `/solve-challenge --mode blitz <target>` or `/ctf-web --fast <target>` or `--blitz <prompt>`
- **Deep Analysis Mode (RCA & Writeup)**: `/solve-challenge --mode deep <target>` or `/ctf-pwn --deep <target>` or `--lab <prompt>`
- **Specific Category Skills**: `/ctf-web`, `/ctf-pwn`, `/ctf-crypto`, `/ctf-reverse`, `/ctf-forensics`, `/ctf-osint`, `/ctf-misc`, `/ctf-ai-ml`, `/ctf-malware`, `/ctf-writeup`

---

## Automated Automation Utilities

Located in [scripts/](scripts/):

- **`parallel_triage.py`**:
  - `python3 scripts/parallel_triage.py <target-binary-or-url>`: Executes high-speed concurrent Tier 1 & 2 diagnostics (pure Python ELF parsing, checksec, strings, headers, robots.txt, sitemap.xml, sensitive leak probes) via ThreadPoolExecutor.
  - `python3 scripts/parallel_triage.py <target> --json`: Emits machine-readable diagnostic synthesis with recommended specialist category skills.
- **`scope_guard.py`**:
  - `python3 scripts/scope_guard.py <target-or-command>`: Machine-enforces authorized testing boundaries (RFC1918 subnets, loopback, CTF platform domains) and blocks destructive commands or root persistence attempts.
  - `python3 scripts/scope_guard.py --target <url> --json`: Generates a formal Security Context Object (SCO) for multi-agent dispatch.
- **`skill_validator.py`**:
  - `python3 scripts/skill_validator.py <path-to-skill>`: Validates external custom skills against YAML frontmatter schemas, shallow orchestration constraints (depth <= 1), mode awareness, policy lexicon, and prohibited commands.
  - `python3 scripts/skill_validator.py --all --json`: Scans all skills across `.agents/skills/` and returns structured JSON reports for CI/CD or agent pipelines.
- **`prompt_policy_sanitizer.py`**:
  - `python3 scripts/prompt_policy_sanitizer.py "<prompt>" --lang [vi|en]`: Scans, scores policy risk, and sanitizes prompts with academic terminology and educational CTF preambles.
  - `python3 scripts/prompt_policy_sanitizer.py --file <path> --check`: Verifies that challenge writeups, prompts, or scripts do not trigger modern LLM backend filters.
- **`workspace_cleaner.py`**:
  - `python3 scripts/workspace_cleaner.py --fast`: Purges scratch files (`test*.py`, `fuzz*.py`, `tmp*`), keeping challenge assets and winning `solve.py`.
  - `python3 scripts/workspace_cleaner.py --deep`: Enforces `writeup.md`, `solve.py`, and `resources/` folder structure.
- **`extract_flags.py`**:
  - `python3 scripts/extract_flags.py "<output>" --banner`: Prints high-visibility flag banner and verifies candidate regex.
  - `python3 scripts/extract_flags.py -f output.log --json`: Emits machine-readable JSON candidate rankings.
- **`ctfd_client.py`**:
  - Python API client for automated challenge retrieval, attachment downloading, and flag submission.
- **`cve_lookup.py`**:
  - Automated CVE advisory and exploit lookup utility via Sploitus and Exploit-DB.

---

## References & Deep Knowledge Base

Detailed references offloaded to [references/](references/) to preserve maximum context window tokens during agent turns:
- [multi-agent-orchestration-and-policy-routing.md](references/multi-agent-orchestration-and-policy-routing.md) — Comprehensive guide on Security Context Objects, Task Envelopes, shallow orchestration, and the 3-Tier Refusal Router.
- [llm-safety-and-policy-compliance.md](references/llm-safety-and-policy-compliance.md) — Comprehensive guide on modern LLM safety filter architecture, trigger dictionary (EN/VI), and safe prompt engineering.
- [ctf-triage-ladder.md](references/ctf-triage-ladder.md) — Hierarchical 4-Tier progression (Tier 1 plaintext to Tier 4 in-meta).
- [version-matrix.md](references/version-matrix.md) — Glibc heap, PHP type juggling, and Python bytecode compatibility matrix.
- [exploit-databases.md](references/exploit-databases.md) — Exploit databases, CVE search, and GitHub PoC repositories.
- [security-events-and-intelligence.md](references/security-events-and-intelligence.md) — CTFtime intelligence and event key extraction techniques.

---

## Constitution & Architectural Governance

The rules governing all CTF-Agent behavior are defined in [AGENTS.md](AGENTS.md):
1. **Hint-First Rule**: Analyze metadata and hints before touching code or tools.
2. **Operational Mode Compliance**: Strictly follow Blitz or Deep Analysis protocols.
3. **Execution Guard**: Never modify original challenge files; wrap Linux binaries through WSL/Docker; enforce 60s command timeouts.
4. **Flag Anti-Hallucination**: 100% verified flag strings directly from runtime output.
5. **LLM Safety & Policy Compliance**: Enforce authorized educational sandbox scope and use academic diagnostic terminology per [ctf-safety-framing-rules.md](rules/ctf-safety-framing-rules.md).
6. **Context Propagation & Task Envelopes**: Propagate machine-readable Security Context Objects and enforce shallow execution depth (max depth: 1).
7. **Refusal Router & Deterministic Tool Fallback**: Enforce 3-tier refusal classification; never enter infinite paraphrasing loops on hard refusals, falling back directly to deterministic CLI tools.

---

### License & Attribution
Distributed under the MIT License. Designed for authorized security research, academic labs, and ethical CTF competitions.
