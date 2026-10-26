# CTF MCP Tool Map

CTF-Agent exposes one project-local MCP server. Reverse Engineering and Game Hacking use standalone local tools; no REA process or MCP server is required.

## Readiness and setup

From the `CTF-Agent` repository root:

```powershell
npm install
npm run ctf-agent -- doctor --json
npm run ctf-agent -- setup --plan --profile full
```

Review the exact Kali and apt package plan before applying it:

```powershell
npm run ctf-agent -- setup --apply --profile full
```

The setup uses Kali WSL2 and the non-sudo Linux account `ctfagent`, with Python 3 as a base runtime for workspace-safe file operations. It leaves Docker Desktop and the global WSL default distribution unchanged. WSL and a Linux user are not a security sandbox; host network and drive access may still be available.

## Declare a challenge scope

Create a per-repository scope before active network tools are called:

```powershell
npm run ctf-agent -- scope init `
  --challenge web-01 `
  --workspace .ctf-workspaces/web-01 `
  --source-root .\challenge-inputs `
  --target challenge.example:8080
```

Targets are exact host/port pairs; wildcards and CIDR ranges are not accepted. Local artifacts must be imported from an explicitly declared source root. The import creates a WSL copy, safely creates its workspace destination without following symlinks, verifies its SHA-256, and leaves the supplied original unchanged.

## Category routing

| CTF category | Manifest category | Tool IDs | First operations |
| --- | --- | --- | --- |
| Web | `web` | `ctf_nmap_scan`, `ctf_sqlmap_test`, `ctf_ffuf_discover` | Scope-bounded discovery and web testing. |
| Reverse Engineering | `reverse` | `ctf_reverse_inspect`, `ctf_reverse_disassemble`, `ctf_reverse_gdb_info` | Inspect scoped Linux/ELF artifacts. |
| Crypto | `crypto` | `ctf_smt_solve`, `ctf_crypto_candidates`, `ctf_crypto_john` | Bounded SMT-LIB, offline encoding/XOR analysis, and optional local hash auditing. |
| PWN | `pwn` | `ctf_pwn_checksec`, `ctf_pwn_cyclic`, `ctf_pwn_run`, `ctf_pwn_ropgadget` | Inspect protections, generate cyclic patterns, run timed local challenge binaries, and scan one binary for gadgets. |
| Forensics | `forensics` | `ctf_forensics_pcap`, `ctf_forensics_firmware`, `ctf_forensics_metadata`, `ctf_forensics_pcap_follow_stream`, `ctf_forensics_yara_scan` | Read selected PCAP fields, follow a bounded stream, scan firmware signatures or one artifact with local YARA rules, and inspect metadata. |
| Exploitation | `exploitation` | `ctf_scoped_http_request`, `ctf_scoped_tcp_exchange`, `ctf_hydra_audit` | Send scoped HTTP/TCP requests; optional Hydra attempts are explicit, authorized, and limited to one in-scope SSH/FTP target. |
| Game Hacking | `game_hacking` | `ctf_game_frida_spawn` | Stage a private copy of a scoped Linux workspace executable and run one bounded Frida script. |
| Miscellaneous | `misc` | `ctf_decode` | Decode bounded Base64, hex, URL, ROT13, and one-byte XOR values. |
| OSINT | `osint` | `ctf_dns_lookup`, `ctf_whois_lookup` | Run scoped DNS and WHOIS lookups. |
| Steganography | `steganography` | `ctf_stego_steghide`, `ctf_stego_steghide_extract`, `ctf_stego_metadata`, `ctf_stegseek_crack` | Inspect/extract with Steghide or optionally crack one workspace carrier with Stegseek; outputs are bounded, never overwrite, and are never executed. |
| Hardware Hacking | `hardware` | `ctf_hardware_decode_signal` | Decode supplied signal recordings; no live acquisition. |
| Competition platform | `competition` | `ctf_ctfd_list_challenges`, `ctf_ctfd_get_challenge`, `ctf_ctfd_download_attachment`, `ctf_ctfd_auth_status`, `ctf_ctfd_progress` | Read CTFd challenges and own progress; download public attachments only. Strict GET-only behavior: no flag submissions or hint unlocks; tokens are never sent for details/files, which fail closed for private content. |

The manifest category is the canonical setup grouping; tools may also be useful in cross-category workflows.

## Utility tools

- `ctf_mcp_health` reports server identity and liveness without checking dependencies.
- `ctf_tool_status` reports local dependency readiness. `doctor` checks installed tools and WSL readiness; it does not prove the live agent has connected.
- `ctf_workspace_import` imports a bounded, hash-verified file from a declared source root into the active workspace.

Frida is installed as `frida==17.24.3` in a `ctfagent` virtual environment.

## Execution limits

- MCP adapters use fixed executable mappings and argument arrays, never an arbitrary shell command.
- Workspace file readers, FFUF wordlists, SQLmap output directories, imported destinations, and PWN binary staging use descriptor-relative no-follow traversal; PWN/Frida code execution still runs with `ctfagent` permissions and is not sandboxed.
- Active network tools require an exact target in the current scope; HTTP redirects are not followed by the bounded request tool.
- CTFd tools use only the configured origin and fixed GET routes. The API token is restricted to listing and own-account reads; challenge details and files are anonymous-only.
- Tool timeouts and output budgets are enforced at the Windows process and WSL tool layers.
- Truncated output is incomplete evidence; do not infer absence from a truncated result. Narrow the query or use a bounded follow-up when supported.
- Frida scripts are limited to 64 KiB, run for at most 120 seconds, and return at most 1 MiB. Spawn accepts only workspace executables, opens them without following symlinks, and executes a private staged copy that is removed on completion; the workspace source remains unchanged. Existing-process attachment is not supported because Kali WSL's ptrace policy restricts it for the non-sudo account.
- PWN and Frida operations execute challenge code/processes as the `ctfagent` account. This is account separation, not containment; use a separately isolated VM/firewall when hard isolation is required.
- If the host refuses an operation, follow its policy. Do not rephrase, hide, or route the same rejected operation through another MCP server.
- Tool results are returned to the model. When the selected model provider is remote, challenge data included in those results is sent to that provider under its data policy.
