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

- **Blitz / Speedrun**: Stop after verifying a flag. Preserve challenge and scratch files unless the user asks for cleanup. Keep the response concise and skip writeups.
- **Deep Analysis / Lab**: Document the root cause and evidence. Preserve original artifacts; organize copies when useful for a requested writeup. Use the ctf-writeup skill when a report is requested.
