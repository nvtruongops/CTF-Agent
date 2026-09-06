# CTF-Agent: Autonomous Security Intelligence & Competitive Exploitation Framework

> **A High-Performance AI Agent Architecture for Live CTF Competitions, Lab Vulnerability Audits, and Security Research.**  
> Compatible with **Antigravity IDE**, **Cursor**, **Claude Code**, and **OpenAI Codex/Agent** ecosystems.

---

## Quick Navigation

- [CRITICAL: Environment Backend Selection (WSL vs Docker)](#critical-environment-backend-selection-wsl-vs-docker)
- [Operational Modes: Blitz vs Deep Analysis](#operational-modes-blitz-vs-deep-analysis)
- [LLM Safety Guardrails & Policy Compliance](#llm-safety-guardrails--policy-compliance)
- [Specialized Category Skills](#specialized-category-skills)
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
      [1. Web & JS Ecosystem]        [2. Python Workstation]           [3. Modern UV Toolchain]
        npx ctf-agent init          python scripts/ctf_init.py           uvx ctf-agent init
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

CTF-Agent provides three interchangeable execution engines tailored to different developer workflows:

#### 1. Web & JavaScript Ecosystem (`npx ctf-agent init`)
Zero-clone setup for developers accustomed to npm and modern web toolchains:
```bash
# Initialize current workspace via NPX:
npx ctf-agent init

# Target a specific challenge workspace:
npx ctf-agent init /path/to/ctf-workspace

# Run preflight inspection in dry-run mode:
npx ctf-agent init --dry-run
```

#### 2. Native Python Security Workstation (`python scripts/ctf_init.py`)
Pure standard library execution with zero external third-party dependencies:
```bash
# Interactive setup wizard:
python scripts/ctf_init.py /path/to/ctf-workspace

# Or via install_as_agent wrapper:
python scripts/install_as_agent.py init /path/to/ctf-workspace

# Automated unattended setup (auto-selects highest-scored backend and purpose):
python scripts/ctf_init.py /path/to/ctf-workspace --auto --purpose live-ctf

# Preflight analysis and dry-run inspection (zero filesystem writes):
python scripts/ctf_init.py --dry-run

# Health check verification on an existing workspace:
python scripts/ctf_init.py /path/to/ctf-workspace --check-only
```

#### 3. Modern Python Toolchain (`uvx ctf-agent init`)
Ultra-fast ephemeral execution powered by the Rust-based `uv` package manager:
```bash
# Initialize workspace via UVX directly:
uvx ctf-agent init

# Execute directly from repository source:
uvx --from git+https://github.com/nvtruongops/CTF-Agent ctf-agent init

# Automated speedrun profile:
uvx ctf-agent init --auto --purpose live-ctf
```

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
