# CTF-Agent

CTF-Agent combines host-neutral CTF skills under `.agents/` with one project-local MCP server for authorized CTF competitions and educational labs. Reverse Engineering and Game Hacking use local Kali tools managed by the CTF-Agent setup.

## Requirements

- Node.js 24.11 or later on Windows.
- WSL2 with Kali Linux for the bundled tool adapters. The setup command can install Kali when it is missing.
- Kali mirror access for APT packages and PyPI access to install the pinned Frida wheel in a dedicated virtual environment.
- OpenCode or another MCP-compatible host. The setup command registers the MCP server in the selected host's user-level configuration.

The server uses a non-sudo WSL account named `ctfagent`. WSL and a separate Linux account are not a sandbox: network access and host integration may still be available. Use only organizer-authorized targets and review the tool scope before active scans.

## Install and check

The npm package is `ctf-agent`. This checkout prepares `0.1.0`; it is not publicly installable yet. On 2026-10-27, the public registry exposed only the `0.0.0-stage` placeholder, not a working MCP. After the maintainer approves a release and npm makes that version public, install and initialize it from any challenge project:

```powershell
npm install ctf-agent@0.1.0
npx ctf-agent setup --client opencode --dry-run
npx ctf-agent setup --client opencode --yes
npx ctf-agent doctor --json
npx ctf-agent setup --plan --profile full
```

Until that release is public, inspect the same setup from a local checkout:

```powershell
npm install
npm run ctf-agent -- setup --client opencode --dry-run
npm run ctf-agent -- doctor --json
npm run ctf-agent -- setup --plan --profile full
```

The IDE setup previews configuration and skill destinations, then asks before writing. Pass `--yes` only when the preview is approved; `--dry-run` never writes. Add repeatable `--client` values for `claude-code`, `codex`, or `antigravity`, or use `--all-detected` to select clients with existing configuration directories. `--skills=false` skips skill installation. Existing config files are backed up as `.bak` (with a numbered suffix if needed); malformed configs, unsafe paths, name collisions, or files changed after preview are rejected. Restart the selected IDE after setup.

The installer registers the MCP server in user-level configuration and installs CTF skills/references/rules under the client's global skills directory. MCP commands inherit the IDE's active workspace; setup never stores an npm-cache path as the project root. The optional CTFd environment variables remain environment references, not stored secret values.

Review the exact Kali and package plan before applying it (this remains separate from IDE setup):

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

3. Open this repository in OpenCode with the CTF-Agent MCP registered in your user-level config. The repository does not ship a project-local OpenCode config.
4. Use `ctf_tool_status` to see CTF tool readiness. Import individual files with `ctf_workspace_import`; the server copies them into the WSL workspace and verifies their hashes.

Tools are grouped by CTF category. Examples include Nmap/SQLmap/FFUF for scoped web challenges, Z3, local decoders, and offline encoding/XOR candidate ranking for crypto, GDB/pwntools for local PWN challenges, TShark PCAP field extraction and stream following plus Binwalk/ExifTool for forensics, Steghide for stego, and sigrok-cli for saved hardware recordings. Workspace artifact paths are opened through WSL no-follow checks; PWN binaries are staged to a private copy before execution. Reverse Engineering provides scoped ELF metadata/symbol/string inspection, objdump disassembly, and fixed GDB inspection. Game Hacking provides one-shot Frida instrumentation of a Linux executable in the challenge workspace. Kali's ptrace policy prevents reliable attachment to unrelated existing processes, so this MVP uses spawn-only instrumentation. Missing dependencies appear in the readiness report.

`ctf_stego_steghide_extract` writes up to 64 MiB to an explicit, non-existing workspace path and never executes the extracted data. The passphrase is not returned or logged, but is briefly visible in process arguments to privileged or same-user observers.

Optional CTFd tools read the configured stock CTFd API v1 instance. Set `CTF_MCP_CTFD_URL` and, if needed, `CTF_MCP_CTFD_TOKEN` in the environment used to launch OpenCode; the project config forwards those variables without storing their values. The integration performs only GET requests: it never submits flags or unlocks hints. Tokens are used for challenge listing and your own progress only; challenge details and attachment downloads are anonymous, so private or module-gated content fails closed. Attachments are limited to 64 MiB, written only to a new active-workspace path, and never executed. `ctf_ctfd_auth_status` checks credentials explicitly; local `ctf_tool_status` does not contact CTFd.

See [the CTF MCP tool map](.agents/references/ctf-mcp-tool-map.md) and [the skills package guide](.agents/README.md) for category routing and host setup.

## npm release

The package explicitly sets `publishConfig.access` to `public`, keeps a curated `files` allowlist, and declares its CTF tooling as dual-use with a root [`DISCLOSURE`](DISCLOSURE). This follows REA's packaging discipline, not its product configuration. CTF skills, Kali profiles, the non-sudo `ctfagent` account, scoped tools and explicit setup confirmation remain intact. Policy declaration is not npm approval.

Verify from **Windows PowerShell**, not a Linux/WSL Node process:

```powershell
npm ci
npm run prepublishOnly
npm run verify:package
npm pack --dry-run --json
```

`prepublishOnly` runs the full Node test suite and source package audit; `prepack` repeats the audit before packing. `verify:package` creates a real tarball, installs it with production dependencies in a fresh temporary project, checks its CLI shim, initializes all four IDE clients in a temporary home, compares bundled guidance, initializes a challenge scope, and checks MCP tools and out-of-scope rejection. It does not install Kali, scan targets or change real IDE configuration.

### Stage in CI, approve with 2FA

[npm's dual-use policy](https://docs.npmjs.com/policies/dual-use) prohibits direct CI publishing with OIDC or a bypass-2FA token. `.github/workflows/publish.yml` therefore verifies on Windows and runs **`npm stage publish` only**. It uses npm 11.21.1 and OIDC, with no `NPM_TOKEN` secret. A GitHub release or manual workflow dispatch stages a candidate; neither makes it publicly installable.

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

Approval requires the maintainer's 2FA. npm may still validate/review the package; a successful staging run is not publication. After the public version lookup succeeds, test `npm install ctf-agent@0.1.0` in a clean project before announcing availability. The IDE installer pins MCP launches to the installed package version, so its `npx` launcher also requires that version to be public. No credentials are stored in the repository. Account configuration, 2FA and npm review cannot be supplied by repository metadata alone.

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
