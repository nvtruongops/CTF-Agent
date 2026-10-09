# CTF Flag Validation & Anti-Hallucination Rules
## Trigger: always_on

Every candidate flag string discovered during CTF competitions or security labs must undergo strict verification before being reported or submitted:

### 1. Three-Step Flag Verification Protocol
1. **Regex & Format Compliance**:
   - The flag must strictly match the regex format specified in the challenge description or event rules (e.g., `^FLAG\{[ -~]+\}$`, `FlagY\{[A-Za-z0-9_\-!@#\$%^&*()]+\}`, `picoCTF\{.*\}`).
   - If the flag has no standard prefix, verify against explicit plaintext markers in the challenge prompt.
2. **Provenance & Execution Verification**:
   - The flag must originate directly from verifiable command output (e.g., HTTP response, shell command execution, memory dump extraction, or script execution output).
   - Never extrapolate, guess, or synthesize truncated flag endings.
3. **Reproducibility Check**:
   - The automated `solve.py` script must run independently and output the verified flag string from scratch.
   - If integrated with a CTFd platform, submit through the competition page when requested and report its response accurately.

### 2. Workspace Cleanliness & Mode-Aware Reporting Standard
- Do NOT create standalone `flag.txt` files in the repository root.
- **In Blitz Mode (`--blitz`, `@ctf-speedrun`)**:
- Print the verified flag directly in the high-visibility banner.
  - Do NOT generate `writeup.md`.
- Preserve challenge and scratch files unless the user asks for cleanup.
- **In Deep Analysis Mode (`--deep`, `@ctf-analyzer`)**:
  - Document the validated flag in the YAML frontmatter and designated flag section of `writeup.md` following the `ctf-writeup` skill standard.
  - Enforce clean workspace structure: `writeup.md`, `solve.py`, and `resources/`.
