#!/usr/bin/env python3
"""
CTFd Native Model Context Protocol (MCP) Server
Exposes CTFd platform capabilities directly to AI agents via standard JSON-RPC 2.0 (stdio).
Tools:
  - ctfd_list_challenges: Lists available challenges, categories, points, solve counts.
  - ctfd_get_challenge: Retrieves challenge details, connection info, attachments, and hints.
  - ctfd_download_files: Downloads challenge files into local workspace.
  - ctfd_submit_flag: Validates flag regex, prevents duplicate submissions, and submits to CTFd.
  - ctfd_status: Returns current platform connection status and solved statistics.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure safe UTF-8 stdio on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Add parent directory to path to enable importing sibling scripts
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

try:
    from ctfd_client import CTFdClient
    from flag_guard import FlagGuard
except ImportError:
    from scripts.ctfd_client import CTFdClient
    from scripts.flag_guard import FlagGuard


class CTFdMCPServer:
    """Standard JSON-RPC 2.0 MCP server over stdio for CTFd interaction."""

    def __init__(self, base_url: Optional[str] = None, api_token: Optional[str] = None, cache_path: Optional[Path] = None):
        self.base_url = (base_url or os.environ.get("CTFD_URL", "")).rstrip("/")
        self.api_token = api_token or os.environ.get("CTFD_TOKEN", "")
        self.flag_guard = FlagGuard(cache_path=cache_path)
        self.client: Optional[CTFdClient] = None

        if self.base_url and self.api_token:
            self.client = CTFdClient(self.base_url, self.api_token)

    def _ensure_client(self) -> CTFdClient:
        if not self.client:
            self.base_url = (self.base_url or os.environ.get("CTFD_URL", "")).rstrip("/")
            self.api_token = self.api_token or os.environ.get("CTFD_TOKEN", "")
            if not self.base_url or not self.api_token:
                raise ValueError("CTFd credentials missing. Please configure CTFD_URL and CTFD_TOKEN environment variables or flags.")
            self.client = CTFdClient(self.base_url, self.api_token)
        return self.client

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "ctfd_list_challenges",
                "description": "Lists all challenges from the CTFd platform with category, points, and solve state.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "category": {
                            "type": "string",
                            "description": "Optional category filter (e.g., 'pwn', 'web', 'crypto', 'rev').",
                        }
                    },
                },
            },
            {
                "name": "ctfd_get_challenge",
                "description": "Fetches detailed information for a challenge including description, connection info, attachments, and hints.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "challenge_id": {
                            "type": "integer",
                            "description": "The unique numerical CTFd challenge ID.",
                        }
                    },
                    "required": ["challenge_id"],
                },
            },
            {
                "name": "ctfd_download_files",
                "description": "Downloads attached challenge files from CTFd into a target directory.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "challenge_id": {
                            "type": "integer",
                            "description": "The unique numerical CTFd challenge ID.",
                        },
                        "output_dir": {
                            "type": "string",
                            "description": "Target folder path to download files into (defaults to current directory).",
                        },
                    },
                    "required": ["challenge_id"],
                },
            },
            {
                "name": "ctfd_submit_flag",
                "description": "Validates format, checks deduplication cache, and submits a flag candidate to CTFd.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "challenge_id": {
                            "type": "integer",
                            "description": "The numerical CTFd challenge ID.",
                        },
                        "flag": {
                            "type": "string",
                            "description": "The flag candidate string (e.g., 'flag{...}').",
                        },
                    },
                    "required": ["challenge_id", "flag"],
                },
            },
            {
                "name": "ctfd_status",
                "description": "Returns current connection status, configured URL, and local solved challenge count.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
            },
        ]

    def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if name == "ctfd_status":
                solved = self.flag_guard.get_solved_challenges()
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps({
                                "connected": bool(self.base_url and self.api_token),
                                "base_url": self.base_url or "Not configured",
                                "solved_challenges_count": len(solved),
                                "solved_challenges": solved,
                            }, indent=2),
                        }
                    ]
                }

            client = self._ensure_client()

            if name == "ctfd_list_challenges":
                category = arguments.get("category")
                challs = client.get_challenges()
                if category:
                    challs = [c for c in challs if c.get("category", "").lower() == category.lower()]
                
                # Annotate with local solved cache
                for c in challs:
                    cid = str(c.get("id"))
                    c["is_solved_locally"] = self.flag_guard.is_solved(cid)

                return {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(challs, indent=2),
                        }
                    ]
                }

            elif name == "ctfd_get_challenge":
                cid = arguments["challenge_id"]
                details = client.get_challenge_details(cid)
                if not details:
                    return {
                        "content": [{"type": "text", "text": f"Error: Challenge ID {cid} not found on CTFd."}],
                        "isError": True,
                    }
                files = client.get_challenge_files(cid)
                hints = client.get_challenge_hints(cid)
                details["files"] = files
                details["hints"] = hints
                details["is_solved_locally"] = self.flag_guard.is_solved(cid)
                return {
                    "content": [{"type": "text", "text": json.dumps(details, indent=2)}]
                }

            elif name == "ctfd_download_files":
                cid = arguments["challenge_id"]
                out_dir = Path(arguments.get("output_dir", "."))
                out_dir.mkdir(parents=True, exist_ok=True)
                
                file_urls = client.get_challenge_files(cid)
                if not file_urls:
                    return {
                        "content": [{"type": "text", "text": f"No files attached to challenge {cid}."}]
                    }

                downloaded = []
                headers = client.headers
                for rel_url in file_urls:
                    full_url = f"{self.base_url}/{rel_url.lstrip('/')}" if not rel_url.startswith("http") else rel_url
                    filename = rel_url.split("?")[0].split("/")[-1]
                    target_file = out_dir / filename
                    req = urllib.request.Request(full_url, headers=headers)
                    with urllib.request.urlopen(req, timeout=15) as resp:
                        target_file.write_bytes(resp.read())
                    downloaded.append(str(target_file.resolve()))

                return {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Downloaded {len(downloaded)} files:\n" + "\n".join(f"- {f}" for f in downloaded),
                        }
                    ]
                }

            elif name == "ctfd_submit_flag":
                cid = arguments["challenge_id"]
                flag = arguments["flag"].strip()

                # Step 1: Validate regex format
                valid, fmt_msg = self.flag_guard.validate_format(flag)
                if not valid:
                    return {
                        "content": [{"type": "text", "text": f"Submission rejected by FlagGuard: {fmt_msg}"}],
                        "isError": True,
                    }

                # Step 2: Check deduplication cache
                dup, dup_msg = self.flag_guard.is_duplicate(cid, flag)
                if dup:
                    return {
                        "content": [{"type": "text", "text": f"Submission skipped (deduplicated): {dup_msg}"}]
                    }

                # Step 3: Submit to platform
                resp = client.submit_flag(cid, flag)
                status = resp.get("status", "error")
                message = resp.get("message", "")

                # Step 4: Record in cache
                self.flag_guard.record_attempt(cid, flag, status, message)

                return {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Flag Submission Result:\n- Challenge ID: {cid}\n- Status: {status.upper()}\n- Message: {message}",
                        }
                    ],
                    "isError": status not in ("correct", "already_solved"),
                }

            else:
                return {
                    "content": [{"type": "text", "text": f"Unknown tool: {name}"}],
                    "isError": True,
                }

        except Exception as e:
            return {
                "content": [{"type": "text", "text": f"Error executing tool '{name}': {str(e)}"}],
                "isError": True,
            }

    def run_stdio(self) -> None:
        """Main stdio loop processing JSON-RPC 2.0 MCP requests."""
        while True:
            line = sys.stdin.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue

            try:
                msg = json.loads(line)
            except Exception:
                continue

            msg_id = msg.get("id")
            method = msg.get("method")
            params = msg.get("params", {})

            if method == "initialize":
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": {
                            "name": "ctfd-mcp-server",
                            "version": "1.4.0",
                        },
                    },
                }
                self._send_response(resp)

            elif method == "notifications/initialized":
                # Client acknowledged initialization
                pass

            elif method == "tools/list":
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"tools": self.get_tool_definitions()},
                }
                self._send_response(resp)

            elif method == "tools/call":
                name = params.get("name", "")
                args = params.get("arguments", {})
                result = self.handle_tool_call(name, args)
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": result,
                }
                self._send_response(resp)

            elif method == "ping":
                resp = {"jsonrpc": "2.0", "id": msg_id, "result": {}}
                self._send_response(resp)

            else:
                if msg_id is not None:
                    resp = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {"code": -32601, "message": f"Method not found: {method}"},
                    }
                    self._send_response(resp)

    def _send_response(self, resp: Dict[str, Any]) -> None:
        sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
        sys.stdout.flush()


def main():
    parser = argparse.ArgumentParser(description="CTFd MCP Server (JSON-RPC 2.0 stdio)")
    parser.add_argument("--url", help="CTFd Base URL (e.g., https://ctf.example.com)")
    parser.add_argument("--token", help="CTFd API Token")
    parser.add_argument("--cache", help="Path to local flag deduplication cache")
    args = parser.parse_args()

    cache_path = Path(args.cache) if args.cache else None
    server = CTFdMCPServer(base_url=args.url, api_token=args.token, cache_path=cache_path)
    server.run_stdio()


if __name__ == "__main__":
    main()
