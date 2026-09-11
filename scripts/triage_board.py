#!/usr/bin/env python3
"""
CTF-Agent Triage Board & Run State Tracker
Coordinates multi-challenge CTF workflows, tracks progress across 4 Tiers,
and maintains structured execution logs (triage_board.json and runs.jsonl).
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure safe UTF-8 stdio on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

DEFAULT_BOARD_FILE = Path("triage_board.json")
DEFAULT_RUNS_FILE = Path("runs.jsonl")


class TriageBoard:
    """Orchestrates competition triage state, prioritization, and run history."""

    def __init__(self, board_path: Optional[Path] = None, runs_path: Optional[Path] = None):
        self.board_path = board_path or DEFAULT_BOARD_FILE
        self.runs_path = runs_path or DEFAULT_RUNS_FILE
        self.data: Dict[str, Any] = self._load_board()

    def _load_board(self) -> Dict[str, Any]:
        if self.board_path.exists():
            try:
                return json.loads(self.board_path.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {
            "competition": "CTF Workspace",
            "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "challenges": [],
        }

    def save(self) -> None:
        self.data["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        try:
            self.board_path.write_text(json.dumps(self.data, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception as e:
            sys.stderr.write(f"[TriageBoard] Warning: Failed to save board: {e}\n")

    def init_from_challenges(self, challenges: List[Dict[str, Any]], competition_name: str = "CTF Competition") -> None:
        """Initializes the triage board from a list of challenge objects."""
        self.data["competition"] = competition_name
        self.data["challenges"] = []

        for c in challenges:
            cid = c.get("id")
            name = c.get("name") or c.get("title") or f"chall_{cid}"
            cat = (c.get("category") or "misc").lower()
            points = c.get("points") or c.get("value") or 100

            # Heuristic tier assignment: lower points -> lower tier
            tier = 1 if points <= 100 else (2 if points <= 250 else (3 if points <= 400 else 4))
            priority = "high" if tier <= 2 else ("medium" if tier == 3 else "low")

            self.data["challenges"].append({
                "id": cid,
                "name": name,
                "category": cat,
                "points": points,
                "tier": tier,
                "priority": priority,
                "status": "unsolved",  # unsolved | in_progress | blocked | solved
                "attempts": 0,
                "assigned_agent": None,
                "flag": None,
                "notes": "",
            })
        self.save()

    def get_challenge(self, challenge_id: Any) -> Optional[Dict[str, Any]]:
        cid_str = str(challenge_id)
        for c in self.data.get("challenges", []):
            if str(c.get("id")) == cid_str:
                return c
        return None

    def update_challenge(
        self,
        challenge_id: Any,
        status: Optional[str] = None,
        assigned_agent: Optional[str] = None,
        flag: Optional[str] = None,
        notes: Optional[str] = None,
        tier: Optional[int] = None,
        priority: Optional[str] = None,
    ) -> bool:
        c = self.get_challenge(challenge_id)
        if not c:
            return False

        if status:
            c["status"] = status
        if assigned_agent is not None:
            c["assigned_agent"] = assigned_agent
        if flag:
            c["flag"] = flag
            c["status"] = "solved"
        if notes is not None:
            c["notes"] = notes
        if tier is not None:
            c["tier"] = tier
        if priority is not None:
            c["priority"] = priority

        self.save()
        return True

    def record_run(
        self,
        challenge_id: Any,
        strategy: str,
        status: str,  # success | failed | timeout | error
        duration_seconds: float = 0.0,
        agent_or_model: str = "agent",
        flag: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> None:
        """Appends a run entry to runs.jsonl and updates challenge attempt count."""
        cid = str(challenge_id)
        c = self.get_challenge(cid)
        if c:
            c["attempts"] = c.get("attempts", 0) + 1
            if status == "success" and flag:
                c["status"] = "solved"
                c["flag"] = flag
            self.save()

        run_record = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "challenge_id": challenge_id,
            "agent_or_model": agent_or_model,
            "strategy": strategy,
            "status": status,
            "duration_seconds": round(duration_seconds, 2),
            "flag": flag,
            "error": error_message,
        }

        try:
            with open(self.runs_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(run_record, ensure_ascii=False) + "\n")
        except Exception as e:
            sys.stderr.write(f"[TriageBoard] Warning: Failed to record run: {e}\n")

    def summary(self) -> Dict[str, Any]:
        challs = self.data.get("challenges", [])
        total = len(challs)
        solved = sum(1 for c in challs if c.get("status") == "solved")
        in_progress = sum(1 for c in challs if c.get("status") == "in_progress")
        blocked = sum(1 for c in challs if c.get("status") == "blocked")
        unsolved = total - solved

        return {
            "competition": self.data.get("competition", "CTF"),
            "total": total,
            "solved": solved,
            "in_progress": in_progress,
            "blocked": blocked,
            "unsolved": unsolved,
            "rate_percent": round((solved / total * 100), 1) if total > 0 else 0.0,
        }

    def print_board(self) -> None:
        s = self.summary()
        print("\n=================================================================")
        print(f"CTF-AGENT TRIAGE BOARD: {s['competition']}")
        print("=================================================================")
        print(f"Total: {s['total']} | Solved: {s['solved']} ({s['rate_percent']}%) | In Progress: {s['in_progress']} | Blocked: {s['blocked']}")
        print("-----------------------------------------------------------------")
        print(f"{'ID':<6} {'Name':<22} {'Category':<10} {'Tier':<5} {'Pri':<6} {'Status':<12} {'Flag'}")
        print("-" * 75)

        for c in self.data.get("challenges", []):
            cid = str(c.get("id"))[:5]
            name = str(c.get("name"))[:20]
            cat = str(c.get("category"))[:9]
            tier = f"T{c.get('tier', 2)}"
            pri = str(c.get("priority"))[:5]
            st = str(c.get("status"))[:11]
            flag = str(c.get("flag") or "")[:15]
            print(f"{cid:<6} {name:<22} {cat:<10} {tier:<5} {pri:<6} {st:<12} {flag}")

        print("=================================================================\n")


def main():
    parser = argparse.ArgumentParser(description="CTF-Agent Triage Board & Run State Tracker")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Command: status
    subparsers.add_parser("status", help="Print current triage board summary")

    # Command: update
    update_parser = subparsers.add_parser("update", help="Update challenge status")
    update_parser.add_argument("challenge_id", help="Challenge ID")
    update_parser.add_argument("--status", choices=["unsolved", "in_progress", "blocked", "solved"], help="New status")
    update_parser.add_argument("--flag", help="Solved flag string")
    update_parser.add_argument("--agent", help="Assigned agent or model")
    update_parser.add_argument("--notes", help="Diagnostic notes")

    # Command: record-run
    run_parser = subparsers.add_parser("record-run", help="Log an exploit/solver run")
    run_parser.add_argument("challenge_id", help="Challenge ID")
    run_parser.add_argument("--strategy", required=True, help="Strategy or exploit technique used")
    run_parser.add_argument("--status", choices=["success", "failed", "timeout", "error"], required=True, help="Run outcome")
    run_parser.add_argument("--duration", type=float, default=0.0, help="Duration in seconds")
    run_parser.add_argument("--flag", help="Extracted flag")
    run_parser.add_argument("--error", help="Error message if failed")

    args = parser.parse_args()
    board = TriageBoard()

    if args.command == "status" or not args.command:
        board.print_board()
    elif args.command == "update":
        ok = board.update_challenge(args.challenge_id, status=args.status, assigned_agent=args.agent, flag=args.flag, notes=args.notes)
        if ok:
            print(f"[+] Challenge {args.challenge_id} updated.")
        else:
            print(f"[-] Challenge {args.challenge_id} not found.")
    elif args.command == "record-run":
        board.record_run(
            args.challenge_id,
            strategy=args.strategy,
            status=args.status,
            duration_seconds=args.duration,
            flag=args.flag,
            error_message=args.error,
        )
        print(f"[+] Run recorded for challenge {args.challenge_id}.")


if __name__ == "__main__":
    main()
