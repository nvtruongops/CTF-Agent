---
name: solve-challenge
description: Coordinates triage and solution workflows for authorized CTF competition challenges and educational security labs by identifying the dominant challenge category and routing execution to the right specialized ctf-* skill. Use when given an authorized CTF challenge bundle, isolated test service, or benchmark file.
license: MIT
---

# CTF Challenge Solver

You're a skilled CTF player. Your goal is to solve the challenge and find the flag.

## Environment & Tool Availability

The `.agents/` collection provides guidance; the parent CTF-Agent repository may also provide its optional MCP runtime. When using that runtime, check readiness with `npm run ctf-agent -- doctor --json` and follow [the CTF MCP tool map](../../references/ctf-mcp-tool-map.md). Otherwise check which tools the host already provides and consult their upstream installation instructions when needed.

- On Windows, use WSL for Linux-only tools. Keep challenge files in their original location and work on copies when a tool may modify them.
- On Linux or WSL, run tools using the active environment configured by the host.
## Core References & Intelligence Hubs

- [exploit-databases.md](../../references/exploit-databases.md) - CVE advisories, vulnerability databases, SearchSploit, and public proof-of-concept repositories.
- [security-events-and-intelligence.md](../../references/security-events-and-intelligence.md) - CTFtime archives, security event research, and public threat intelligence sources.
- [ctf-mcp-tool-map.md](../../references/ctf-mcp-tool-map.md) - CTF MCP setup, category tool routing, scope, and WSL limitations.

## Workflow

### Step 0: Challenge Platform Context

When a competition URL is supplied, use its authorized challenge page and published rules to identify challenge details, hints, attachments, and the submission process. Prefer the competition's normal web interface. Do not request or store platform credentials for routine challenge triage; submit a verified flag only when the user asks or the task clearly includes submission.
### Step 0.5: Operational Mode Determination (Blitz vs Deep Analysis)

Determine the operational profile before beginning exploitation:

1. **Blitz / Speedrun Mode (`--mode blitz`, `--fast`)**:
   - **Trigger**: Active CTF competitions, time pressure, or prompts like "speedrun", "fast", "blitz", "find flag quickly".
   - **Primary Objective**: Minimal Time-to-Flag (First Blood).
   - **Behavioral Rule**: Fast triage, short timeouts, stop after a verified flag, preserve challenge files and scratch artifacts, and keep the response concise.

2. **Deep Analysis / Lab Mode (`--mode deep`, `--deep`, `--lab`)**:
   - **Trigger**: Lab challenges (HTB, PortSwigger, pwnable.tw), security audits, research, or prompts like "deep analysis", "detailed writeup", "write docs", "root cause analysis".
   - **Primary Objective**: Security rigor, exhaustive Root Cause Analysis (RCA), and publication-ready documentation.
   - **Behavioral Rule**: Document the root cause, preserve original artifacts and work on copies, and create a reproducible writeup when requested.

### Step 0.6: Task Envelope & Security Context Binding

Before delegating to category skills or secondary agents, bind the challenge/lab into a **Task Envelope (TE)** and **Security Context Object (SCO)** per [multi-agent-orchestration-and-policy-routing.md](../../references/multi-agent-orchestration-and-policy-routing.md):
1. **Define Security Context**: Binds target endpoint/file and establishes `mode: ctf | lab`. Record `environment.isolated` as `true`, `false`, or `unknown` from evidence; do not assume a WSL user or scope declaration is a sandbox.
2. **Shallow Execution Mandate**: Activate or read the matching category skill (for example, `ctf-web` or `ctf-pwn`) using the host's skill mechanism. Do not spawn recursive subagents.
3. **Refusal Router Protocol**:
    - If an invocation returns a safety refusal, clarify only missing or inaccurate authorization facts without disguising the requested action.
      - Type A (Context correction): at most one retry that states the true challenge and target plainly.
      - Type B (Scope ambiguity): at most one retry after adding verified target and organizer scope.
      - Type C (Hard policy): do not retry, rephrase to evade, or delegate the same action; continue only with a permitted alternative.

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
6. **Vulnerability & Exploit Lookup** -- For a discovered product version or CVE, check the official CVE record, vendor advisory, CISA KEV, FIRST EPSS, and sources such as Sploitus or SearchSploit. Check CTFtime and event intelligence for challenge lineage.

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
- "LLM prompt injection", "LLM jailbreak", "model extraction", "adversarial examples", "neural networks", "LLM security challenge" -> ai-ml (for LLM/model targets, use this specific route before the generic web "injection" cue)
- "buffer overflow", "ROP", "shellcode", "libc", "heap" -> pwn
- "RSA", "AES", "cipher", "encrypt", "prime", "modulus", "lattice", "LWE", "GCM" -> crypto
- "XSS", "SQL", "injection", "cookie", "JWT", "SSRF" -> web
- "disk image", "memory dump", "packet capture", "registry", "power trace", "side-channel", "spectrogram", "audio tracks", "MKV" -> forensics
- "find", "locate", "identify", "who", "where" -> osint
- "obfuscated", "packed", "C2", "malware", "beacon" -> malware
- "game client", "game hacking", "game binary" -> reverse (memory exploitation -> pwn)
- "jail", "sandbox", "escape", "encoding", "signal", "game theory", "Nim", "commitment", "Gray code" -> misc

**By service behavior:**
- Port with interactive prompt, crash on long input -> pwn
- HTTP service -> web
- netcat with math/crypto puzzles -> crypto
- netcat with restricted shell or eval -> misc (jail)

### Step 4: Load the Category Skill

Once you identify the category, load the matching skill using the host's skill mechanism to get specialized techniques:

| Category | Skill | When to Use |
|----------|--------|-------------|
| Web | `ctf-web` | XSS, SQLi, SSTI, SSRF, JWT, file uploads, prototype pollution |
| Pwn | `ctf-pwn` | Buffer overflow, format string, heap, ROP, sandbox escape |
| Crypto | `ctf-crypto` | RSA, AES, ECC, PRNG, ZKP, classical ciphers |
| Reverse | `ctf-reverse` | Binary analysis, game clients, VMs, obfuscated code |
| Forensics | `ctf-forensics` | Disk images, memory dumps, event logs, stego, network captures |
| OSINT | `ctf-osint` | Social media, geolocation, DNS, public records |
| Malware | `ctf-malware` | Obfuscated scripts, C2 traffic, PE/.NET analysis |
| Misc | `ctf-misc` | Jails, encodings, RF/SDR, esoteric languages, constraint solving |
| AI/ML | `ctf-ai-ml` | Model attacks, adversarial examples, prompt security, model extraction |

Related topics route through these existing specialist skills:

| Topic | Default route | Conditional route / limit |
|---|---|---|
| Steganography | `ctf-forensics` | OSINT-led cases may start with `ctf-osint` |
| Hardware / firmware | `ctf-reverse` | Signal or measurement traces use `ctf-forensics` |
| Game hacking | `ctf-reverse` | Memory-exploitation cases use `ctf-pwn` |
| Web3 / smart contracts | `ctf-web` | Cryptographic primitives or protocol math use `ctf-crypto` |
| Mobile reversing | `ctf-reverse` | — |
| PPC / programming puzzles | `ctf-misc` (best-effort fallback) | No dedicated PPC skill exists |

Load the full `ctf-<category>` skill instructions with detailed techniques.

### Step 5: Pivot When Stuck

Use this step after comparing the result of a bounded probe with the hypothesis it was meant to test:

1. Record the observation and whether it confirms, rejects, or leaves the hypothesis unresolved.
2. A failed probe alone is not evidence for escalation or a different category. Two consecutive attempts without new relevant evidence end that strategy.
3. Pivot only when a new observation supports a distinct category or hypothesis. Name that observation and choose one bounded next probe.
4. If no observation supports a pivot, state the blocker, record the unresolved question, or ask for the missing input instead of repeating broader probes.

**Common multi-category patterns:**
- Forensics + Crypto: encrypted data in PCAP/disk image, need crypto to decrypt
- Web + Reverse: WASM or obfuscated JS in web challenge
- Web + Crypto: JWT forgery, custom MAC/signature schemes
- Reverse + Pwn: reverse the binary first, then exploit the vulnerability
- Forensics + OSINT: recover data from dump, then trace it via public sources
- Misc + Crypto: jail escape requires building crypto primitives under constraints
- OSINT + Stego: social media posts with unicode homoglyph steganography (Cyrillic lookalikes encode bits)
- Web + Forensics: paywall inspection (curl reveals content hidden by CSS overlays)
- Misc + Crypto + Game Theory: multi-phase interactive challenges with AES decryption → HMAC commitment → combinatorial game solving (GF(256) Nim)
- Crypto + Geometry + Lattice: multi-layer challenges progressing from spatial reconstruction → subspace recovery → LWE solving → AES-GCM decryption
- Forensics + Signal Processing: power traces / side-channel analysis requiring statistical analysis of measurement data
- Forensics + Network + Encoding: timing-based encoding in PCAP (inter-packet intervals encode binary data)

### Step 6: Post-Exploitation & Completion (Mode-Dependent)

#### Branch A: Blitz Mode (`--mode blitz` or `--fast`)
When running in Blitz mode (active CTF competition):
1. Stop further tool use once a candidate flag is verified.
2. Report the exact flag and the direct output or response that established it.
3. Do not create a writeup. Preserve challenge files and scratch artifacts unless the user asks for cleanup.
4. Keep the response concise: verified flag, method, and submission status when applicable.
5. Skip `ctf-lab-retrospective` unless the user explicitly asks; if asked, run it only after reporting and do not resume challenge probing.
#### Branch B: Deep Analysis Mode (`--mode deep` or `--deep`)
For labs, research, and practice:
1. Preserve original artifacts; use copies for analysis.
2. Load the `ctf-writeup` skill when a reproducible report is requested.
3. Include a standalone `solve.py` only when useful to reproduce the result, and verify it from a fresh run.
4. Report the first verified flag and its direct evidence before doing any retrospective.
5. After reporting, invoke `ctf-lab-retrospective` for every deep/lab solve, including when there is no reusable lesson; in that case say “no proposed update” and write no file.
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
