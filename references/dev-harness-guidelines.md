# DEVELOPER HARNESS & ENVIRONMENT INTEGRATION GUIDELINES
## Internal Architecture Guide for Framework Maintainers

> **Scope**: Developer-facing reference for framework maintainers, tool integrators, and harness debugging.
> **Note**: This document is deliberately decoupled from the runtime `AGENTS.md` to prevent prompt bloat and context dilution during active CTF competitions.

---

## 1. DEV VS. END-USER SEPARATION OF CONCERNS

A fundamental architectural boundary exists between framework maintenance and competition operation:
- **End-User / CTF Player Scope**: Running triage skills, writing mathematical solvers, decompiling binaries, discovering web attack vectors, and acquiring flags. Runtime prompts must remain lean, domain-focused, and free of IDE harness internals.
- **Framework Maintainer Scope**: Resolving IDE hook syntax errors, managing session database migrations, tuning telemetry plugins, and configuring multi-agent bridge adapters.

IDE harness workarounds must never be leaked into runtime operational constitutions.

---

## 2. GOOGLE ANTIGRAVITY HARNESS INTEGRATION

When executing within Google Antigravity or Gemini CLI environments, maintainers should be aware of the following harness characteristics:

### 2.1. PreToolUse Telemetry Hook Path Formatting
On Windows platforms, environment hooks invoking Node.js bundles must format absolute paths cleanly without nested escaped quotation marks:
- **Faulty Pattern**: `node "path\"nested_path\bundle.js\""` -> Triggers `MODULE_NOT_FOUND`.
- **Standard Pattern**: `node "C:\Users\...\telemetry_hook_bundle.js"` -> Executes cleanly with exit code 0 (`{"decision":"allow"}`).

### 2.2. Session Brain Task Tracking
Antigravity manages session state inside `<appDataDir>/brain/<conversation-id>/`:
- Multi-turn autonomous tasks within Antigravity maintain execution checkpoints in `task.md`.
- Agents must physically generate artifacts on disk using `write_to_file` before referencing them in responses to prevent path hallucination.
- Active workspace paths must resolve to the live conversation directory rather than stale historical sessions.

### 2.3. Goal Stop Hook Lifecycle
The `/goal` slash command attaches a supervisory stop hook that intercepts termination when deliverables are unverified:
- Avoid pairing `/goal` with atomic or interactive commands (`/goal /ctf-crypto`) unless running an extended multi-hour triage session.
- Tasks must produce verifiable empirical evidence (passing tests, execution logs, solve scripts) before concluding.

---

### 2.4. Global Eager Command Execution (`run_command` Priority)
Antigravity manages interactive tool approval modals via `autoExecutionPolicy`. To enable unprompted terminal command execution across all projects on the host:
- Configuration path: `~/.gemini/config/config.json`
- Policy setting: `"autoExecutionPolicy": "CASCADE_COMMANDS_AUTO_EXECUTION_EAGER"`
- Non-workspace file access: `"nonWorkspaceFileAccessPolicy": "AGENT_SETTING_POLICY_ALLOW"`
- CLI configuration: `~/.gemini/antigravity-cli/settings.json` (`"toolPermission": "always-proceed"`)

During workspace provisioning (`ctf-agent init` or `python scripts/install_as_agent.py`), CTF-Agent automatically detects the host Antigravity installation and applies this configuration without requiring manual JSON editing.


---

## 3. MULTI-AGENT ADAPTER SYNCHRONIZATION

For non-Antigravity runtimes (Claude Code, Cursor, Windsurf, GitHub Copilot, Aider):
- Runtimes do not possess an internal brain artifact directory or Antigravity stop hooks.
- Maintainers should run `python ctf_agent_cli.py adapter --agent all` to regenerate native configuration pointers whenever `AGENTS.md` is updated.
- Each adapter references `AGENTS.md` as the authoritative Single Source of Truth (SSOT).
