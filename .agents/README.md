# CTF Skills

This folder is a drop-in collection of Markdown skills and optional agent personas for authorized CTF competitions, educational labs, and security research. Copy the entire `.agents/` folder into the root of a lab repository.

## Agent host setup

| Host | Setup |
| --- | --- |
| Codex | Copy `.agents/` to the repository root. Codex discovers repo skills in `.agents/skills/`. |
| Google Antigravity | Copy `.agents/` to the repository root. Antigravity discovers skills in `.agents/skills/`. |
| Claude Code | Copy `.agents/` to the repository root, then start Claude Code there with `claude --add-dir .agents`. Claude loads the bridge entries in `.agents/.claude/skills/`; each bridge points to the canonical skill under `.agents/skills/`. |
| Other Agent Skills hosts | Configure the host to search `.agents/skills/` if supported. Otherwise preserve the package's directory layout when loading a skill so links to `references/` and `rules/` still resolve. |

These skills use the Agent Skills `SKILL.md` format. Host support for tool names, permission metadata, automatic discovery paths, and persona files differs. The canonical skills do not grant tool permissions; the host supplies tools, permissions, network limits, and isolation. The optional persona documents under `agents/` are plain Markdown; register or load them using the host's documented mechanism.

## Contents

- `skills/` — category and orchestration skills. Each starts at `SKILL.md` and may link to supporting notes in the same directory.
- `.claude/skills/` — small Claude Code discovery entries that point to the canonical skills; edit the files under `skills/` for workflow changes.
- `agents/` — optional controller, speedrun, and analyzer personas.
- `references/` — shared technical references linked by skills and personas.
- `rules/` — shared scope, execution, and flag-verification guidance.
- `tests/` — checks for Markdown links, skill and persona structure, and host discovery entries.

The package contains guidance only. It does not include an installer, command-line runtime, CTFd client, container image, or execution sandbox. A referenced tool must be installed and allowed by the host environment.

## Scope

Use the material only for explicitly authorized CTF challenges, competitions, and isolated educational labs. These documents describe operating guidance; they do not technically restrict network or command execution. Follow the host's permission controls and the linked scope rules.

Treat a flag as verified only when it is freshly observed in direct challenge output or a platform response and matches the expected format. Preserve original challenge files; work on copies.

## Validation

From the downloaded `CTF-Agent` repository root, run:

    python -m pytest .agents/tests

## Contributing

Add or revise a canonical skill under `skills/<skill-name>/`, with a `SKILL.md` entrypoint and relative links to supporting material. Keep the corresponding Claude Code entry in `.claude/skills/<skill-name>/SKILL.md` synchronized. Add shared guidance to `references/` or `rules/` only when a skill or persona links to it. Do not assume scripts, package entrypoints, or bundled system tools exist.
