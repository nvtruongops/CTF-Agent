---
name: ctf-writeup
description: Generates a single standardized submission-style CTF writeup for competition handoff and organizer review. Use after solving a CTF challenge to document the solution steps, tools used, and lessons learned in a structured format.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash and Python 3.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "true"
  argument-hint: "[challenge-name]"
---

# CTF Write-up Generator & Lab Directory Standard

Generate a standardized submission-style CTF writeup and enforce clean repository organization for each lab.

## Lab Directory Structure Standard

Each lab directory must follow this clean and minimal structure:

```
Category/XX-ChallengeName/
├── writeup.md      # Main writeup report (only markdown report file)
├── solve.py        # Automated solve script (if applicable)
└── resources/      # Subfolder for all challenge attachments, source code, data, logs, images
```

**Cleanliness Rules:**
- **DO NOT** create `flag.txt` (the flag is already stored in `writeup.md` frontmatter and body).
- **DO NOT** create redundant markdown duplicates (e.g., `ChallengeName.md`, `REPORT.md`). Only keep `writeup.md`.
- Move all downloaded challenge files, source code folders, dumps, test scripts, and media into the `resources/` subfolder.

---

## Writeup Format Standard

### Frontmatter YAML
The YAML frontmatter contains the following fields:

```yaml
---
title: "<Challenge Name>"
ctf: "<CTF Event / Platform Name>"
category: <web|pwn|crypto|reverse|forensics|osint|malware|misc>
diff: <easy|medium|hard|insane>
flag: "<flag_value>"
hint: "<hint_content_or_official_description>"
---
```

### Writeup Body Structure

```markdown
# <Challenge Name>

## 1. Challenge & Hint Analysis (Hint-First Methodology)
- **Challenge Description & Hints**: Exact quote of the official prompt, title, and hints provided by the organizers.
- **Semantic Interpretation**: Decoded technical intent, targeted primitive, and explicit elimination of irrelevant attack vectors (anti-rabbit hole scoping).

## 2. Target Architecture & Vulnerability Analysis
- **Architecture & Context**: Summary of the target stack, service architecture, or binary environment.
- **Root Cause Analysis (RCA)**: Deep technical breakdown of the underlying flaw (e.g., memory corruption, cryptographic flaw, logic flaw, injection).

## 3. Step-by-Step Exploitation Walkthrough
- **Step 1**: Initial reconnaissance and confirmation of the vulnerable primitive.
- **Step 2**: Developing the exploit chain or mitigation bypass.
- **Step 3**: Triggering final execution / decryption and exfiltrating the flag.

## 4. Standalone Exploit Script (solve.py)
```python
<one complete, standalone, runnable solving script from challenge data to flag>
```

## 5. Verification & Flag
```text
<exact_flag_here>
```
```

---

## Best Practices Checklist

Before finalizing the lab:
- [ ] **Frontmatter complete** — contains `title`, `ctf`, `category`, `diff`, `flag`, and `hint`.
- [ ] **Hint Analysis included** — dedicated section explaining the technical significance of the hint.
- [ ] **No extra files at root** — only `writeup.md`, `solve.py`, and `resources/` folder.
- [ ] **Redundant files removed** — no `flag.txt` and no duplicate `.md` files.
- [ ] **All challenge data organized** — source code, logs, and downloads placed inside `resources/`.
- [ ] **Reproducible solve script** — `solve.py` is self-contained and runnable.
- [ ] **Real flag verified** — exact flag verified and documented.
