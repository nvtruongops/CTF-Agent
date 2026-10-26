# CTF Skills Repository Guide

## Purpose

This `.agents/` subtree contains Markdown skills, optional agent personas, shared references, and operating rules for authorized CTF competitions and educational labs. The parent CTF-Agent repository also has an optional MCP runtime outside this subtree; the skills remain usable without it.

## Scope and execution

- Work only on challenges, competitions, and labs the user is authorized to assess.
- Read challenge descriptions and hints before choosing an analysis path.
- Preserve original challenge binaries, captures, and archives. Make working copies before changing or executing them.
- Do not treat these documents or the optional MCP runtime as a technical sandbox. The host/runtime supply tools; host permissions and actual isolation remain authoritative.
- Do not claim a flag is correct unless it was freshly observed in direct challenge output or a platform response and matches the expected flag format.

## Operating modes

- Blitz or fast mode prioritizes the first verified flag. Stop further probing after a verified flag and keep the response concise.
- Deep or lab mode prioritizes root cause, reproducible reasoning, and a clear write-up when requested.
- Follow the progressive triage order in [ctf-triage-ladder.md](references/ctf-triage-ladder.md), then confirm environment versions with [version-matrix.md](references/version-matrix.md).

## Shared rules

Apply [ctf-execution-rules.md](rules/ctf-execution-rules.md), [ctf-safety-framing-rules.md](rules/ctf-safety-framing-rules.md), and [flag-validation-rules.md](rules/flag-validation-rules.md). For multi-agent work, follow [multi-agent-orchestration-and-policy-routing.md](references/multi-agent-orchestration-and-policy-routing.md). Treat scope checks and prompt wording guidance as operating procedures, not as runtime enforcement.

## Maintaining this repository

- Keep skill entrypoints in `skills/<skill-name>/SKILL.md` and preserve local relative links.
- Keep `references/` and `rules/` material only while skills, personas, or this guide link to it.
- Keep runtime instructions optional. When a skill uses the parent repository's CTF MCP, link to its setup guide and readiness command; do not imply that the skill itself installs tools or enforces isolation.
- Validate local Markdown links and skill/persona frontmatter when changing content.
