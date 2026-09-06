# CTF Triage Ladder: Hierarchical Attack Progression Protocol
## Fallback Methodology for Unknown & Generic CTF Challenges

When a challenge has **no specific hint or description** (or only a generic prompt like "Can you get the flag?"), follow this hierarchical triage ladder from Tier 1 to Tier 4. **Never jump straight into Tier 3 or Tier 4 without first completing Tier 1 and Tier 2 checks.**

---

## The 4-Tier Progression Ladder

```
┌────────────────────────────────────────────────────────────────────────┐
│  TIER 1: PLAINTEXT & TRIVIAL LEAKS (MINIMAL RECON)                     │
│  - strings, exiftool, curl /robots.txt, source HTML comments, git log  │
│  - Default credentials, basic logic bypass, plaintext flag in binary   │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   ▼ (Escalate only if Tier 1 yields nothing)
┌────────────────────────────────────────────────────────────────────────┐
│  TIER 2: TEXTBOOK CLASSIC FLAWS (FOUNDATIONAL PATTERNS)                │
│  - Web: ' OR 1=1--, basic php://filter LFI, PHP 7 type juggling        │
│  - Pwn: ret2win, basic x86/x64 ret2libc, format string %p/%n           │
│  - Crypto: factordb factor lookup, Wiener attack, Caesar, single XOR   │
│  - Forensics: zsteg -a, binwalk -e, Wireshark HTTP/FTP credentials     │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   ▼ (Escalate only if Tier 2 yields nothing)
┌────────────────────────────────────────────────────────────────────────┐
│  TIER 3: STANDARD EXPLOIT CHAINS (INTERMEDIATE PLAYBOOKS)              │
│  - Web: SSTI (Jinja2/Twig), JWT forgery, Prototype pollution, SSRF     │
│  - Pwn: ROPgadget chains, ret2csu, SROP, standard tcache poisoning     │
│  - Crypto: Padding oracle CBC, MT19937 untemper, Coppersmith small root│
│  - Forensics: Volatility 3 pslist/filescan, USB HID extraction         │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   ▼ (Escalate only if Tier 3 yields nothing)
┌────────────────────────────────────────────────────────────────────────┐
│  TIER 4: ADVANCED IN-META TECHNIQUES (2024–2026+ DEEP EXPLOITS)        │
│  - Web: RSC Flight RCE, WeasyPrint SSRF, Web3 EIP-1153, Groth16 ZKP    │
│  - Pwn: House of Apple 2 FSOP, Kernel SLUB cross-cache, PTE overlap    │
│  - Crypto: Hidden Number Problem LLL/BKZ, Babai CVP, Lattice HNP       │
│  - AI/ML: LoRA weight merging, Model inversion, Prompt injection       │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Detailed Category Breakdown

### 1. Web Exploitation
- **Tier 1**: Source code comments, `/robots.txt`, `.git/` leak, hidden URL routes, admin default credentials (`admin:admin`, `admin:password`).
- **Tier 2**: Simple SQLi (`' OR 1=1--`), basic LFI (`php://filter/convert.base64-encode/resource=index.php`), path traversal (`../../../../flag`).
- **Tier 3**: Server-Side Template Injection (`{{7*7}}`), JWT signature none/weak secret, prototype pollution, SSRF targeting internal metadata (`169.254.169.254`).
- **Tier 4**: React Server Components (Flight) RCE, WeasyPrint PDF injection, HTTP Request Smuggling (CL.TE / TE.CL / H2), Groth16 ZKP verification bypasses.

### 2. Binary Exploitation (Pwn)
- **Tier 1**: Plaintext flag in binary (`strings binary | grep flag`), buffer overflow without protections (no canary, no PIE).
- **Tier 2**: Classic `ret2win` (calling hidden win function), 32-bit/64-bit `ret2libc`, printf format string leak (`%p %p %p`).
- **Tier 3**: ROP gadget chains (`ROPgadget`), SROP (`sigreturn`), basic tcache poisoning (glibc 2.26-2.30), format string write (`%n`).
- **Tier 4**: House of Apple 2 (`_IO_wfile_overflow` on glibc >= 2.34), Linux kernel SLUB cross-cache overflow, dirty cred, page table entry (PTE) overwriting.

### 3. Cryptography
- **Tier 1**: Classical ciphers (Caesar, ROT13, Vigenere), single-byte XOR, Base64/Base32/Base85 encodings.
- **Tier 2**: Small RSA factors (`factordb`), Wiener attack (small private exponent $d < \frac{1}{3}N^{1/4}$), Fermat factorization (primes close together).
- **Tier 3**: CBC padding oracle attacks, MT19937 PRNG untempering / state recovery, RSA Franklin-Reiter or Coppersmith small roots.
- **Tier 4**: Hidden Number Problem (HNP) with biased nonce via LLL/BKZ lattice reduction, CVP Babai's nearest plane, fault attacks on Ed25519/ECDSA.

### 4. Digital Forensics & Reverse Engineering
- **Tier 1**: Metadata inspection (`exiftool`), embedded file extraction (`binwalk -e`), plaintext strings in dumps.
- **Tier 2**: Steganography LSB extraction (`zsteg -a`), Wireshark HTTP/FTP cleartext traffic filter, unstripped ELF symbol examination in IDA/Ghidra.
- **Tier 3**: Volatility 3 memory analysis (`windows.pslist`, `linux.bash`), USB keystroke extraction from PCAP, bytecode disassembly (`pycdc`, `jadx`).
- **Tier 4**: Custom VM architecture reversing, anti-analysis / anti-debugging bypass, memory injection / process hollowing forensics, complex signal processing (SDR/RF).
