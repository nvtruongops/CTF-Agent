# CTF-Agent

CTF-Agent combines host-neutral CTF skills under `.agents/` with one project-local MCP server for authorized CTF competitions and educational labs. Reverse Engineering and Game Hacking use local Kali tools managed by the CTF-Agent setup.

## Requirements

- Node.js 24.11 or later on Windows.
- WSL2 with Kali Linux for the bundled tool adapters. The setup command can install Kali when it is missing.
- Kali mirror access for APT packages and PyPI access to install the pinned Frida wheel in a dedicated virtual environment.
- OpenCode or another MCP-compatible host. The included `opencode.jsonc` config is for OpenCode.

The server uses a non-sudo WSL account named `ctfagent`. WSL and a separate Linux account are not a sandbox: network access and host integration may still be available. Use only organizer-authorized targets and review the tool scope before active scans.

## Install and check

From this repository root:

```powershell
npm install
npm run ctf-agent -- doctor --json
npm run ctf-agent -- setup --plan --profile full
```

Review the exact Kali and package plan before applying it:

```powershell
npm run ctf-agent -- setup --apply --profile full
```

Kali installation may require an elevated terminal. Setup does not elevate itself, change the global WSL default distribution, or install the entire Kali metapackage. If WSL needs a reboot or first-run step, the command reports the next action; rerun `doctor` afterward.

## Start a challenge

1. Place challenge assets in an input directory.
2. Declare a challenge workspace and exact organizer-provided network targets:

```powershell
npm run ctf-agent -- scope init `
  --challenge web-01 `
  --workspace .ctf-workspaces/web-01 `
  --source-root .\challenge-inputs `
  --target challenge.example:8080
```

3. Open this repository in OpenCode. The project config starts the single `ctf-agent` MCP server.
4. Use `ctf_tool_status` to see CTF tool readiness. Import individual files with `ctf_workspace_import`; the server copies them into the WSL workspace and verifies their hashes.

Tools are grouped by CTF category. Examples include Nmap/SQLmap/FFUF for scoped web challenges, Z3, local decoders, and offline encoding/XOR candidate ranking for crypto, GDB/pwntools for local PWN challenges, TShark PCAP field extraction and stream following plus Binwalk/ExifTool for forensics, Steghide for stego, and sigrok-cli for saved hardware recordings. Workspace artifact paths are opened through WSL no-follow checks; PWN binaries are staged to a private copy before execution. Reverse Engineering provides scoped ELF metadata/symbol/string inspection, objdump disassembly, and fixed GDB inspection. Game Hacking provides one-shot Frida instrumentation of a Linux executable in the challenge workspace. Kali's ptrace policy prevents reliable attachment to unrelated existing processes, so this MVP uses spawn-only instrumentation. Missing dependencies appear in the readiness report.

`ctf_stego_steghide_extract` writes up to 64 MiB to an explicit, non-existing workspace path and never executes the extracted data. The passphrase is not returned or logged, but is briefly visible in process arguments to privileged or same-user observers.

Optional CTFd tools read the configured stock CTFd API v1 instance. Set `CTF_MCP_CTFD_URL` and, if needed, `CTF_MCP_CTFD_TOKEN` in the environment used to launch OpenCode; the project config forwards those variables without storing their values. The integration performs only GET requests: it never submits flags or unlocks hints. Tokens are used for challenge listing and your own progress only; challenge details and attachment downloads are anonymous, so private or module-gated content fails closed. Attachments are limited to 64 MiB, written only to a new active-workspace path, and never executed. `ctf_ctfd_auth_status` checks credentials explicitly; local `ctf_tool_status` does not contact CTFd.

See [the CTF MCP tool map](.agents/references/ctf-mcp-tool-map.md) and [the skills package guide](.agents/README.md) for category routing and host setup.

## Development checks

Set up the repository-local Python test environment once:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

Run the test suites from the repository root:

```powershell
npm test
.\.venv\Scripts\python.exe -m pytest .agents/tests
```
