# CTF Execution & Environment Isolation Rules
## Trigger: always_on

All execution actions related to solving CTF challenges and lab environments must comply with the following standards:

### 1. Environment & Shell Isolation
- **On Windows**:
  - Do NOT directly execute native Linux ELF binaries (`./binary`), `gdb`, `r2`, or `volatility3` in native Windows PowerShell/CMD.
  - Delegate execution to WSL Kali Linux:
    ```powershell
    wsl -d kali-linux bash -c "source ~/.ctf-tools/venv/bin/activate && <command>"
    ```
  - Note that Windows paths (e.g., `C:\Users\...`) map directly to `/mnt/c/Users/...` inside WSL.
- **On Linux / Docker**:
  - Activate the dedicated virtualenv before running Python exploit scripts:
    ```bash
    source ~/.ctf-tools/venv/bin/activate
    ```
  - Alternatively, use the isolated container:
    ```bash
    docker compose run --rm ctf-agent <command>
    ```

### 2. Execution Timeouts & Resource Management
- Heavy analytical tools (symbolic execution via `angr`, SMT solving via `z3`, lattice reduction via `fpylll`/`flint`, or crypto brute-forcing):
  - MUST enforce a hard execution timeout (e.g., maximum 60 seconds for initial test runs):
    ```bash
    timeout 60s python3 solve.py
    ```
  - If a command times out without producing a constraint solution or model, reassess algorithm complexity immediately and evaluate a pivot.

### 3. Original Challenge Asset Integrity
- Never modify or overwrite the original challenge binary, firmware, capture file, or source archive provided by organizers.
- Work exclusively on copies saved in `/tmp/` or the challenge's dedicated `resources/` directory.

### 4. Operational Mode Execution Discipline
- **Blitz / Speedrun Mode (`--blitz`, `@ctf-speedrun`)**:
  - Halt execution immediately upon verified flag capture (`STOP_ON_FLAG`).
  - Purge scratch files before termination: `python3 scripts/workspace_cleaner.py --fast`.
  - Zero documentation overhead: do NOT author `writeup.md` or redundant report files.
- **Deep Analysis / Lab Mode (`--deep`, `@ctf-analyzer`)**:
  - Perform root cause analysis (RCA) and decompile/disassemble attack primitives.
  - Enforce directory structure: `python3 scripts/workspace_cleaner.py --deep`.
  - Generate standardized 5-section `writeup.md` via `ctf-writeup`.
