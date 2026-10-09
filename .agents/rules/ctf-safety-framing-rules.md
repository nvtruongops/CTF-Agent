# CTF Educational Safety & Scope Rules

> These rules apply to authorized Capture The Flag (CTF) competitions, academic security research, and isolated security labs. They provide operating guidance; the agent host enforces permissions and isolation.

---

### 1. Authorized Environment & Non-Offensive Scope

1. **Strictly Sandboxed Targets**:
   - All target services, binaries, network captures, and source files must be local sandbox assets (Docker, localhost, `127.0.0.1`, WSL, `/tmp/`) or explicitly designated CTF competition endpoints provided by verified organizers (e.g. `ctf.example.com`, CTFd platforms, PicoCTF, HackTheBox labs).
   - **Never** target, probe, or scan unauthorized third-party systems or production infrastructure.
2. **Defensive & Educational Intent**:
   - The primary objective of all code, analysis, and execution is educational vulnerability verification, root cause analysis (RCA), and retrieval of synthetic validation tokens (`flag{...}`).
   - Prohibit the creation of weaponized, persistent, or autonomous real-world malicious tools.

---

### 2. Clear Educational Context

Describe the authorized challenge or lab, its owner or organizer, the target assets, and the verification objective plainly. Use accurate technical terms. Do not disguise the requested action or misrepresent its scope.

---

### 3. Safe Scripting & Code Generation Patterns

When generating `solve.py`, exploit scripts, or interactive tests:
1. **Sanitized Variable & Function Names**:
   - Do NOT use names like `evil_payload`, `malicious_input`, `attack_target`, `exploit()`.
   - DO use descriptive, diagnostic names: `poc_payload`, `test_vector`, `target_endpoint`, `verify_vulnerability()`, `solve()`.
2. **Clear Educational Header**:
   - Prepend all standalone verification scripts with an educational preamble:
     ```python
     #!/usr/bin/env python3
     """
     CTF Challenge Proof-of-Concept & Verification Script
     Environment: Isolated Educational CTF Lab Sandbox
     Objective: Vulnerability Verification & Flag Retrieval
     """
     ```
3. **Clean Teardown**:
   - Ensure network connections to challenge instances terminate cleanly after flag capture.

---

### 4. Host Capabilities and Refusals

- Use only tools and permissions the current agent host actually provides. Tool names and skill discovery paths differ between Codex, Antigravity, Claude Code, and other hosts.
- Do not assume this package installs tools, grants network access, creates a sandbox, or enforces scope.
- If a needed capability is unavailable, describe the limitation and continue with an available, in-scope method when possible.
- If the host refuses an action, follow its rules. Clarify authorization or scope when that is the issue; do not disguise the action, retry with wording changes to evade a restriction, or delegate the same blocked action elsewhere.
- Use the host's native skill and agent mechanisms. If delegation is unavailable, continue sequentially in the current session.

---

### 5. Security Context Object (SCO) & Task Envelope (TE) Standard

To prevent subagent context zero-knowledge and semantic policy refusals, all invocations must inherit a structured **Security Context Object** and **Task Envelope**:

#### 5.1. Security Context Object (SCO) Schema
```yaml
security_context:
  mode: "ctf | lab | audit"
  authorization: "confirmed"
  target:
    type: "educational_lab | ctf_challenge"
    scope:
      - "<target_domain_or_ip>"
      - "localhost"
      - "127.0.0.1"
  environment:
    isolated: true
    sandbox: "docker | wsl | local"
  objective:
    - "vulnerability_verification"
    - "retrieve_flag"
  prohibited:
    - "production_targets"
    - "persistence"
    - "lateral_movement"
    - "denial_of_service"
```

#### 5.2. Task Envelope (TE) Schema
```yaml
task_envelope:
  task_id: "<unique_challenge_or_lab_id>"
  category: "web | pwn | crypto | reverse | forensics | misc | ai-ml | osint"
  mode: "blitz | deep"
  target_assets:
    - "<path_to_challenge_files>"
    - "<endpoint_url>"
  primary_objective: "retrieve_flag"
  constraints:
    timeout_seconds: 60
    max_retries_per_vector: 1
```

---

### 6. Lab Execution and Delegation

For each challenge or lab, establish the authorized target, objective, and constraints before interacting with it. Load the matching category skill through the host's documented mechanism. Keep delegation shallow: one specialist handoff is enough; if the host does not support agents, perform the work in the current session. Do not send challenge artifacts to another service or agent unless the user and the host permit it.

---
