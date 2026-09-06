---
name: solve-challenge
description: Coordinates triage and solution workflows for authorized CTF competition challenges and educational security labs by identifying the dominant challenge category and routing execution to the right specialized ctf-* skill. Use when given an authorized CTF challenge bundle, isolated test service, or benchmark file.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access. Orchestrates other ctf-* skills.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch Skill
metadata:
  user-invocable: "true"
  argument-hint: "[--mode blitz|deep] [category] [challenge-file-or-url]"
---

# CTF Challenge Solver

You're a skilled CTF player. Your goal is to solve the challenge and find the flag.

## Environment Setup & Tool Invocation

All CTF tools and Python libraries are centrally managed and installed via the toolchain installer in [scripts/install_ctf_tools.sh](../../scripts/install_ctf_tools.sh).

### Pre-install Full Toolchain

```bash
bash .agents/scripts/install_ctf_tools.sh all
```

Verify installed packages:
```bash
bash .agents/scripts/install_ctf_tools.sh --verify
```

### Execution Across Platforms

- **On Windows Host (via WSL Kali Linux)**:
  - Run Linux tools and virtualenv-installed Python modules directly inside WSL:
    ```bash
    wsl -d kali-linux bash -c "source ~/.ctf-tools/venv/bin/activate && <command>"
    ```
  - Pre-installed virtualenv is at `~/.ctf-tools/venv` (auto-activated in `~/.bashrc`).
  - Windows files are accessible at `/mnt/c/Users/...`.

- **On Native Linux / WSL**:
  - Activate the CTF virtualenv before executing scripts:
    ```bash
    source ~/.ctf-tools/venv/bin/activate
    ```
  - System binaries (`nmap`, `r2`, `gdb`, `tshark`, `hashcat`, `ffuf`, `apktool`, etc.) are directly available in PATH.

## Core References & Intelligence Hubs

- [exploit-databases.md](../../references/exploit-databases.md) - Exploit databases, CVE advisories, Sploitus, Exploit-DB/Searchsploit, GitHub PoCs, and the `.agents/scripts/cve_lookup.py` CLI utility.
- [security-events-and-intelligence.md](../../references/security-events-and-intelligence.md) - Security event intelligence, CTFtime archives, Pwn2Own research, threat intel feeds, and automated key/flag/CTFd token extraction techniques.

## Workflow

### Step 0: CTFd Platform Detection

If the CTF platform URL is known, check if it runs CTFd and switch to API-driven navigation:

```bash
# Detect CTFd (look for /api/v1/ and /themes/core/)
curl -s "$CTF_URL/api/v1/" | head -5
curl -s "$CTF_URL" | grep -oE '/themes/core/'
```

If CTFd is detected, **ask the user for their API token** (generated from CTFd Settings > Access Tokens). The token is not provided by default — the user must create one in the CTFd web UI first. Once provided, set the environment variables and proceed via API:

```bash
export CTF_URL="https://ctf.example.com"
export CTF_TOKEN="ctfd_..."  # Ask user for this
```

Invoke `/ctf-misc` and load its `ctfd-navigation.md` for the full API reference and Python client class. See [security-events-and-intelligence.md](../../references/security-events-and-intelligence.md) for automated event key extraction and flag submission.

### Step 0.5: Operational Mode Determination (Blitz vs Deep Analysis)

Determine the operational profile before beginning exploitation:

1. **Blitz / Speedrun Mode (`--mode blitz`, `--fast`)**:
   - **Trigger**: Active CTF competitions, time pressure, or prompts like "làm nhanh", "tìm cờ nhanh", "blitz", "speedrun".
   - **Primary Objective**: Minimal Time-to-Flag (First Blood).
   - **Behavioral Rule**: Fast triage, tight timeouts (30-60s max per attempt), **Stop-on-Flag (HALT immediately)**, zero doc/writeup overhead, auto-clean temporary scratch files, print flag banner, and exit.

2. **Deep Analysis / Lab Mode (`--mode deep`, `--deep`, `--lab`)**:
   - **Trigger**: Lab challenges (HTB, PortSwigger, pwnable.tw), security audits, research, or prompts like "phân tích sâu", "tạo writeup", "viết docs".
   - **Primary Objective**: Security rigor, exhaustive Root Cause Analysis (RCA), and publication-ready documentation.
   - **Behavioral Rule**: Reverse engineering, memory/math layout documentation, artifact preservation in `resources/`, invoke `/ctf-writeup` to generate standard `writeup.md`, and create self-contained `solve.py`.

### Step 1: Hint & Description Analysis (Hint-First Methodology)

**CRITICAL RULE**: If a challenge title, description, or hint is provided, **analyze it thoroughly BEFORE touching files or running recon tools**.

Challenge authors intentionally embed directional cues to prevent players from going down irrelevant rabbit holes:
1. **Name Puns & Exploit Metaphors**:
   - "Apple" / "Fruit" -> House of Apple (FSOP)
   - "Wiener" / "Fermat" / "Broadcast" -> Specific RSA attacks
   - "Flight" / "RSC" -> React Server Components Flight RCE
   - "Lattice" / "Knapsack" / "Vector" -> LLL / CVP / LWE
   - "Tcache" / "Fast" -> Specific glibc heap bins
2. **Technical Fingerprints & Negative Constraints**:
   - Explicit version mentions: "Runs on Ubuntu 24.04 (glibc 2.39)", "PHP 8.2", "Python 3.12"
   - Scope limiters: "No brute force required", "Zero network traffic needed", "Only port 8080"
3. **Formulate Hypotheses**:
   - Establish 1-2 prioritized exploit paths based on the hint.
   - **Only if NO hint/description exists (or it is purely generic like 'Get the flag')**: Fall back to Step 2 and the standard CTF Triage Ladder.

### Step 2: Recon (File & Service Triage)

1. **Explore files** -- List the challenge directory, run `file *` on everything
2. **Triage binaries** -- `strings`, `xxd | head`, `binwalk`, `checksec` on binaries
3. **Fetch links** -- If the challenge mentions URLs, fetch them FIRST for context
4. **Connect** -- Try remote services (`nc`) to understand what they expect
5. **Read hints** -- Challenge descriptions, filenames, and comments often contain clues
6. **Vulnerability & Exploit Lookup** -- If specific software versions, libraries, or CVEs are discovered, query exploit repositories ([exploit-databases.md](../../references/exploit-databases.md)) using `python .agents/scripts/cve_lookup.py <CVE>` or Sploitus/Searchsploit. Check CTFtime and event intelligence for challenge lineage.

### Step 3: Categorize

Determine the primary category, then invoke the matching skill.

**By file type:**
- `.pcap`, `.pcapng`, `.evtx`, `.raw`, `.dd`, `.E01` -> forensics
- `.elf`, `.exe`, `.so`, `.dll`, binary with no extension -> reverse or pwn (check if remote service provided -- if yes, likely pwn)
- `.py`, `.sage`, `.txt` with numbers -> crypto
- `.apk`, `.wasm`, `.pyc` -> reverse
- Web URL or source code with HTML/JS/PHP/templates -> web
- Images, audio, PDFs with no obvious content -> forensics (steganography)

**By challenge description keywords:**
- "buffer overflow", "ROP", "shellcode", "libc", "heap" -> pwn
- "RSA", "AES", "cipher", "encrypt", "prime", "modulus", "lattice", "LWE", "GCM" -> crypto
- "XSS", "SQL", "injection", "cookie", "JWT", "SSRF" -> web
- "disk image", "memory dump", "packet capture", "registry", "power trace", "side-channel", "spectrogram", "audio tracks", "MKV" -> forensics
- "find", "locate", "identify", "who", "where" -> osint
- "obfuscated", "packed", "C2", "malware", "beacon" -> malware
- "jail", "sandbox", "escape", "encoding", "signal", "game", "Nim", "commitment", "Gray code" -> misc

**By service behavior:**
- Port with interactive prompt, crash on long input -> pwn
- HTTP service -> web
- netcat with math/crypto puzzles -> crypto
- netcat with restricted shell or eval -> misc (jail)

### Step 4: Invoke the Category Skill

Once you identify the category, **invoke the matching skill** to get specialized techniques:

| Category | Invoke | When to Use |
|----------|--------|-------------|
| Web | `/ctf-web` | XSS, SQLi, SSTI, SSRF, JWT, file uploads, prototype pollution |
| Pwn | `/ctf-pwn` | Buffer overflow, format string, heap, ROP, sandbox escape |
| Crypto | `/ctf-crypto` | RSA, AES, ECC, PRNG, ZKP, classical ciphers |
| Reverse | `/ctf-reverse` | Binary analysis, game clients, VMs, obfuscated code |
| Forensics | `/ctf-forensics` | Disk images, memory dumps, event logs, stego, network captures |
| OSINT | `/ctf-osint` | Social media, geolocation, DNS, public records |
| Malware | `/ctf-malware` | Obfuscated scripts, C2 traffic, PE/.NET analysis |
| Misc | `/ctf-misc` | Jails, encodings, RF/SDR, esoteric languages, constraint solving |

You can also invoke `/ctf-<category>` to load the full skill instructions with detailed techniques.

### Step 5: Pivot When Stuck

If your first approach doesn't work:

1. **Re-examine assumptions** -- Is this really the category you think? A "web" challenge might need crypto for JWT forgery. A "forensics" PCAP might contain a pwn exploit to replay.
2. **Try a different category skill** -- Many challenges span multiple categories. Invoke a second skill for the cross-cutting technique.
3. **Look for what you missed** -- Hidden files, alternate ports, response headers, comments in source, metadata in images.
4. **Simplify** -- If an exploit is too complex, check if there's a simpler path (default creds, known CVE, logic bug).
5. **Check edge cases** -- Off-by-one, race conditions, integer overflow, encoding mismatches.

**Common multi-category patterns:**
- Forensics + Crypto: encrypted data in PCAP/disk image, need crypto to decrypt
- Web + Reverse: WASM or obfuscated JS in web challenge
- Web + Crypto: JWT forgery, custom MAC/signature schemes
- Reverse + Pwn: reverse the binary first, then exploit the vulnerability
- Forensics + OSINT: recover data from dump, then trace it via public sources
- Misc + Crypto: jail escape requires building crypto primitives under constraints
- OSINT + Stego: social media posts with unicode homoglyph steganography (Cyrillic lookalikes encode bits)
- Web + Forensics: paywall bypass (curl reveals content hidden by CSS overlays)
- Misc + Crypto + Game Theory: multi-phase interactive challenges with AES decryption → HMAC commitment → combinatorial game solving (GF(256) Nim)
- Crypto + Geometry + Lattice: multi-layer challenges progressing from spatial reconstruction → subspace recovery → LWE solving → AES-GCM decryption
- Forensics + Signal Processing: power traces / side-channel analysis requiring statistical analysis of measurement data
- Forensics + Network + Encoding: timing-based encoding in PCAP (inter-packet intervals encode binary data)

### Step 6: Post-Exploitation & Completion (Mode-Dependent)

#### Branch A: Blitz Mode (`--mode blitz` or `--fast`)
When running in Blitz mode (active CTF competition):
1. **Stop-on-Flag (HALT immediately)**: The moment a flag candidate is verified, stop all further tool invocations, scans, or code modifications.
2. **Display Verified Flag Banner**:
   ```bash
   python3 scripts/extract_flags.py "<output>" --banner
   ```
3. **Automated Workspace Cleanup**: Clean temporary scratch files and debris:
   ```bash
   python3 scripts/workspace_cleaner.py --fast
   ```
4. **Zero Documentation Overhead**:
   - **STRICTLY DO NOT** call `ctf-writeup`.
   - **DO NOT** create `writeup.md` or any report files.
   - Limit chat response to at most 3 concise lines:
     1. Flag Banner.
     2. Exploit vector in 1 sentence.
     3. Solve script location or CTFd submission status.

#### Branch B: Deep Analysis Mode (`--mode deep` or `--deep`)
When running in Deep Analysis / Lab mode (research, audit, or practice):
1. **Organize Directory Structure**:
   ```bash
   python3 scripts/workspace_cleaner.py --deep
   ```
   Ensure the directory strictly contains `writeup.md`, `solve.py`, and `resources/` (with all challenge files, pcaps, and dumps moved inside `resources/`).
2. **Author Full Writeup**: Invoke `/ctf-writeup` to generate a comprehensive 5-section `writeup.md` including Hint Analysis, Target Architecture & RCA, Step-by-Step Exploitation, and Standalone Exploit Script.
3. **Verify Reproducibility**: Confirm `solve.py` executes standalone and prints the flag.

## Flag Formats

Flags vary by CTF. Common formats:
- `flag{...}`, `FLAG{...}`, `CTF{...}`, `TEAM{...}`
- Custom prefixes: check the challenge description or CTF rules for the format (e.g., `ENO{...}`, `HTB{...}`, `picoCTF{...}`)
- Sometimes just a plaintext string with no wrapper

**Validation rule (important):**
- If you find multiple flag-like strings, treat them as candidates and validate before finalizing.
- Prefer the token tied to the intended artifact/workflow (not random metadata noise or obvious decoys).
- Do a corpus-wide uniqueness check and include the source file/path when reporting.

```bash
# Search for common flag patterns in files
grep -rniE '(flag|ctf|eno|htb|pico)\{' .
# Search in binary/memory output
strings output.bin | grep -iE '\{.*\}'
```

## Quick Reference

```bash
# Recon
file *                                    # Identify file types
strings binary | grep -i flag             # Quick string search
xxd binary | head -20                     # Hex dump header
binwalk -e firmware.bin                   # Extract embedded files
checksec --file=binary                    # Check binary protections

# Connect
nc host port                              # Connect to challenge
echo -e "answer1\nanswer2" | nc host port # Scripted input
curl -v http://host:port/                 # HTTP recon

# Python exploit template
python3 -c "
from pwn import *
r = remote('host', port)
r.interactive()
"
```

## Challenge

$ARGUMENTS
