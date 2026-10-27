# CTF-Agent

CTF-Agent combines host-neutral CTF skills under `.agents/` with one project-local MCP server for authorized CTF competitions and educational labs. Reverse Engineering and Game Hacking use local Kali tools managed by the CTF-Agent setup.

## Requirements

- Windows PowerShell and WSL2 with the `kali-linux` distribution. Windows Node/Python are **not** needed for clone setup or MCP use.
- Node.js >=24.11, npm, Python3 and venv **inside Kali**; the bootstrap installs these through APT when missing.
- Kali mirror, public npm dependency and PyPI access. Frida uses a dedicated user-owned virtual environment, not system pip.
- OpenCode or another MCP-compatible host. The setup command registers the MCP server in the selected host's user-level configuration.

The server uses a non-sudo WSL account named `ctfagent`. WSL and a separate Linux account are not a sandbox: network access and host integration may still be available. Use only organizer-authorized targets and review the tool scope before active scans.

## Clone, install and check

Clone-first setup installs a curated local `ctf-agent@0.1.0` tarball into Kali. It does **not** download `ctf-agent` from npm or require npm login; public npm dependencies are still downloaded. The published npm installation channel is deferred.

```powershell
git clone https://github.com/nvtruongops/CTF-Agent.git
cd CTF-Agent
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\setup.ps1 -Client opencode
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\setup.ps1 -Apply -Client opencode
```

The first command previews without writing. `-Apply` provisions Kali, installs the local runtime, verifies the selected tools, then backs up and merges the chosen Windows agent's configuration and CTF guidance. `-Client` accepts `opencode`, `claude-code`, `codex`, `antigravity` (comma-separated when calling `./setup.ps1` from PowerShell). Reload the agent after setup.

`-Profile full` is the baseline, not every optional tool. Topic profiles include `web`, `reverse`, `crypto`, `pwn`, `forensics`, `exploitation`, `game_hacking`, `misc`, `osint`, `steganography`, `hardware`, and `competition`. Missing optional tools remain visible in doctor output. Setup keeps unchanged runtime/configuration files and creates numbered `.bak` backups when Windows files change.

If Kali/WSL2 is missing, setup reports `pending_wsl2` and stops before configuration writes. Install/initialize Kali first (an elevated terminal and reboot may be necessary):

```powershell
wsl --install --distribution kali-linux --no-launch
wsl --list --verbose
# For an existing WSL1 Kali only, explicitly convert it:
wsl --set-version kali-linux 2
```

Setup does not self-elevate, reset distributions, change WSL defaults or change global PowerShell execution policy. `-ExecutionPolicy Bypass` applies only to the invoked process. Malformed configs, unrelated `ctf-agent` entries, redirected Windows destinations and stale merge plans are rejected. On failure, fix the reported prerequisite/mirror/permission issue and rerun; do not delete existing scopes or distro data.

The stable Windows launcher is `$env:LOCALAPPDATA\CTF-Agent\ctf-agent.ps1`; it starts `/usr/bin/node` as non-sudo `ctfagent` in Kali, using `/home/ctfagent/.local/share/ctf-agent/runtime/node_modules/ctf-agent/ctf_mcp/cli.js`. No Windows Node/npm or npm-cache path is used. Active project paths and optional CTFd environment variables are forwarded process-locally; credentials are not stored in configuration.

After setup, run checks from any local challenge project:

```powershell
$ctf = Join-Path $env:LOCALAPPDATA 'CTF-Agent\ctf-agent.ps1'
& $ctf doctor --json
& $ctf setup --plan --profile full
```

Reapply `setup.ps1 -Apply` from the checkout to update the installed runtime. Existing `.ctf-agent/scope.json` files are not rewritten; old absolute Windows source roots are translated and validated at use time. Use local drive paths, not UNC/network locations.

## Start a challenge

1. Place challenge assets in an input directory.
2. Declare a challenge workspace and exact organizer-provided network targets:

```powershell
& $ctf scope init `
  --challenge web-01 `
  --workspace .ctf-workspaces/web-01 `
  --source-root ./challenge-inputs `
  --target challenge.example:8080
```

3. Open that challenge project in your selected agent with CTF-Agent registered in user-level config. Each project's local scope is separate; the repository does not ship a project-local OpenCode config.
4. Use `ctf_tool_status` to see CTF tool readiness. Import individual files with `ctf_workspace_import`; the server copies them into the WSL workspace and verifies their hashes.

Tools are grouped by CTF category. Examples include Nmap/SQLmap/FFUF for scoped web challenges, Z3, local decoders, and offline encoding/XOR candidate ranking for crypto, GDB/pwntools for local PWN challenges, TShark PCAP field extraction and stream following plus Binwalk/ExifTool for forensics, Steghide for stego, and sigrok-cli for saved hardware recordings. Workspace artifact paths are opened through WSL no-follow checks; PWN binaries are staged to a private copy before execution. Reverse Engineering provides scoped ELF metadata/symbol/string inspection, objdump disassembly, and fixed GDB inspection. Game Hacking provides one-shot Frida instrumentation of a Linux executable in the challenge workspace. Kali's ptrace policy prevents reliable attachment to unrelated existing processes, so this MVP uses spawn-only instrumentation. Missing dependencies appear in the readiness report.

`ctf_stego_steghide_extract` writes up to 64 MiB to an explicit, non-existing workspace path and never executes the extracted data. The passphrase is not returned or logged, but is briefly visible in process arguments to privileged or same-user observers.

Optional CTFd tools read the configured stock CTFd API v1 instance. Set `CTF_MCP_CTFD_URL` and, if needed, `CTF_MCP_CTFD_TOKEN` in the environment used to launch OpenCode; the project config forwards those variables without storing their values. The integration performs only GET requests: it never submits flags or unlocks hints. Tokens are used for challenge listing and your own progress only; challenge details and attachment downloads are anonymous, so private or module-gated content fails closed. Attachments are limited to 64 MiB, written only to a new active-workspace path, and never executed. `ctf_ctfd_auth_status` checks credentials explicitly; local `ctf_tool_status` does not contact CTFd.

See [the CTF MCP tool map](.agents/references/ctf-mcp-tool-map.md) and [the skills package guide](.agents/README.md) for category routing and host setup.

## npm release

The package explicitly sets `publishConfig.access` to `public`, keeps a curated `files` allowlist, and declares its CTF tooling as dual-use with a root [`DISCLOSURE`](DISCLOSURE). This follows REA's packaging discipline, not its product configuration. CTF skills, Kali profiles, the non-sudo `ctfagent` account, scoped tools and explicit setup confirmation remain intact. Policy declaration is not npm approval.

For development/release checks, install native Node dependencies in Kali and run:

```bash
npm ci
npm run prepublishOnly
npm run verify:package
npm pack --dry-run --json
```

`prepublishOnly` runs the full Node test suite and source package audit; `prepack` repeats the audit before packing. `verify:package` creates a real tarball, installs it with production dependencies in a fresh temporary project, checks its CLI shim, initializes all four IDE clients in a temporary home, compares bundled guidance, initializes a challenge scope, and checks MCP tools and out-of-scope rejection. It does not install Kali, scan targets or change real IDE configuration.

### Stage in CI, approve with 2FA

[npm's dual-use policy](https://docs.npmjs.com/policies/dual-use) prohibits direct CI publishing with OIDC or a bypass-2FA token. `.github/workflows/publish.yml` gates staging on Linux runtime/package/Python tests and Windows bootstrap/unit tests, then runs **`npm stage publish` only**. Hosted CI does not claim live Kali WSL verification. It uses npm 11.21.1 and OIDC, with no `NPM_TOKEN` secret. A GitHub release or manual workflow dispatch stages a candidate; neither makes it publicly installable. No publication is needed for clone setup.

Before running that workflow, the package owner must configure [npm trusted publishing](https://docs.npmjs.com/trusted-publishers) for `ctf-agent`:

- GitHub owner: `nvtruongops`; repository: `CTF-Agent`; workflow filename: `publish.yml`.
- Permit `npm stage publish`, not direct `npm publish`; require 2FA for promotion. No GitHub environment name is configured by this workflow.
- Keep the intended release at `0.1.0`; do not automatically bump it because it is not public yet. Inspect any existing `0.1.0` staged candidate while logged in: these source edits do not update its tarball. If it contains the old files, the maintainer must review and reject that candidate with 2FA before restaging the corrected archive, subject to npm's version rules. Never automatically reject candidates or approve an outdated tarball.

After reviewing the workflow output and tarball, the maintainer performs the authenticated steps locally (these are manual instructions, not automatic scripts):

```powershell
npm login
npm stage list ctf-agent --json
npm stage view <stage-id> --json
npm stage approve <stage-id>
npm view ctf-agent@0.1.0 version dist.integrity --registry=https://registry.npmjs.org
```

Approval requires the maintainer's 2FA. npm may still validate/review the package; a successful staging run is not publication. The future npm entry flow must reuse the WSL runtime and be verified separately before announcing availability. Clone setup already works without that release. No credentials are stored in the repository. Account configuration, 2FA and npm review cannot be supplied by repository metadata alone.

## Development checks

Set up the repository-local Python test environment once:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
```

Run the test suites from the repository root:

```bash
npm test
.venv/bin/python -m pytest .agents/tests
# On the provisioned Kali host as ctfagent:
CTF_AGENT_RUN_WSL_INTEGRATION=1 npm test
```

Windows launcher regression tests run with `npm test` under Windows Node (development only). After clone setup, `npm run verify:wsl` on Windows exercises the installed launcher with a temporary Unicode/spaces project, MCP catalog, file SHA-256, pwntools, Z3, ExifTool and out-of-scope rejection. It never scans a public target.
