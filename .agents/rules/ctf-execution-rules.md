# CTF Execution & Environment Isolation Rules
## Trigger: always_on

Apply these rules to authorized CTF challenges and educational labs.

## Host Environment

- On Windows, use WSL for Linux binaries and Linux-only tools.
- The agent host supplies tools, dependencies, permissions, and isolation. Do not assume this repository installs or configures them.
- Preserve organizer-provided binaries, captures, and source archives. Analyze copies when a tool may modify an artifact.

## Timeouts and Resource Use

Use hard timeouts for symbolic execution, SMT solving, lattice reduction, and brute-force work. Start with a short limit such as 60 seconds; reassess the approach if it stalls.

## Operational Modes

- **All CTF/lab modes**: Prioritize the first verified flag; stop challenge probing once verified and report direct evidence immediately. Then invoke `ctf-solve-report` to write the actual solve steps in the user-supplied challenge folder. Preserve challenge files in place.
- Run `ctf-lab-retrospective` only when the user explicitly invokes it or clearly requests it, and only after reporting the flag.
