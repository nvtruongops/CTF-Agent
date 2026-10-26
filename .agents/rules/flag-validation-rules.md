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
   - If a `solve.py` is requested or included, run it independently and confirm it outputs the verified flag string.
   - If integrated with a CTFd platform, submit through the competition page when requested and report its response accurately.

### 2. Flag-First Reporting
- Report the verified flag and its direct evidence before documentation.
- After reporting, invoke `ctf-solve-report` to write `writeup.md` in the supplied challenge folder; it asks before overwriting an existing report and does not move or delete challenge files.
- Do not invoke `ctf-lab-retrospective` unless the user explicitly requests it.
