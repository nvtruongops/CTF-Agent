# CTF Skills

This folder is a drop-in collection of Markdown skills and optional agent personas for authorized CTF competitions, educational labs, and security research. Copy the entire `.agents/` folder into the root of a lab repository.

## Agent host setup

| Host | Setup |
| --- | --- |
| Codex | Copy `.agents/` to the repository root. Codex discovers repo skills in `.agents/skills/`. |
| Google Antigravity | Copy `.agents/` to the repository root. Antigravity discovers skills in `.agents/skills/`. |
| Claude Code | Copy `.agents/` to the repository root, then start Claude Code there with `claude --add-dir .agents`. Claude loads the bridge entries in `.agents/.claude/skills/`; each bridge points to the canonical skill under `.agents/skills/`. |
| Other Agent Skills hosts | Configure the host to search `.agents/skills/` if supported. Otherwise preserve the package's directory layout when loading a skill so links to `references/` and `rules/` still resolve. |

These skills use the Agent Skills `SKILL.md` format. Host support for tool names, permission metadata, automatic discovery paths, and persona files differs. The canonical skills do not grant tool permissions; the host/runtime supply tools, while host permissions and actual isolation remain authoritative. The optional persona documents under `agents/` are plain Markdown; register or load them using the host's documented mechanism.

When this folder is used from the parent CTF-Agent repository, the root also contains an optional CTF MCP runtime. See the [root README](../README.md) for setup and the [CTF MCP tool map](references/ctf-mcp-tool-map.md). Copying `.agents/` alone does not install that runtime.

## Contents

- `skills/` — category and workflow skills. `skills/ctf-solve-challenge/` prioritizes the first verified flag, then invokes `skills/ctf-solve-report/` to write actual solve steps in the supplied challenge folder. `skills/ctf-lab-retrospective/` reviews the current session for reusable improvements to canonical skills when explicitly invoked after a reported result.
- `.claude/skills/` — small Claude Code discovery entries that point to the canonical skills; edit the files under `skills/` for workflow changes.
- `skill-tree/` — manual learning proposals and explicitly approved patterns for the optional parent-repository CTF MCP runtime; normal solving and post-solve review do not consult it.
- `agents/` — optional controller, speedrun, and analyzer personas.
- `references/` — shared technical references linked by skills and personas.
- `rules/` — shared scope, execution, and flag-verification guidance.
- `tests/` — checks for Markdown links, skill and persona structure, and host discovery entries.

The `.agents/` folder itself contains guidance only. The parent CTF-Agent repository provides the optional MCP runtime separately; neither the guidance nor that runtime is a security sandbox. External tool availability and host permissions remain explicit prerequisites.

## Optional learning workflow

Agent-side post-solve review is opt-in: `ctf-lab-retrospective` runs only when the user explicitly invokes it or clearly requests a retrospective, and only after reporting a verified result. It compares the current session with only the relevant canonical topic skill and linked references. It presents no update or an exact proposed diff and waits for explicit approval before any canonical skill edit; it does not create per-lab records. The optional parent-repository CTF MCP keeps `ctf-agent learn --propose`, `ctf-agent learn --list`, `ctf-agent learn --show`, and `ctf-agent learn --promote` for explicit manual operations only. That CLI is not the post-solve review path and is not consulted during normal challenge routing.

## Scope

Use the material only for explicitly authorized CTF challenges, competitions, and isolated educational labs. These documents describe operating guidance; they do not technically restrict network or command execution. Follow the host's permission controls and the linked scope rules.

Treat a flag as verified only when it is freshly observed in direct challenge output or a platform response and matches the expected format. Preserve original challenge files; work on copies.

## Validation

From the downloaded `CTF-Agent` repository root, run:

    python -m pytest .agents/tests

## Contributing

Add or revise a canonical skill under `skills/<skill-name>/`, with a `SKILL.md` entrypoint and relative links to supporting material. Keep the corresponding Claude Code entry in `.claude/skills/<skill-name>/SKILL.md` synchronized. Add shared guidance to `references/` or `rules/` only when a skill or persona links to it. Skills must remain usable without the optional MCP runtime; when referencing it, link to the root setup guide and state its prerequisites.
