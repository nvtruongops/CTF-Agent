#!/usr/bin/env python3
"""
CTF-Agent Flag Guard & Anti-Hallucination Deduplication Cache
Prevents erroneous flag submissions, rate-limit penalties, and repetitive incorrect submissions.
Verifies format regex, validates execution evidence, and caches platform responses.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_FLAG_PATTERNS = [
    r"^flag\{[ -~]+\}$",
    r"^picoCTF\{[ -~]+\}$",
    r"^HTB\{[ -~]+\}$",
    r"^[A-Za-z0-9_]+CTF\{[ -~]+\}$",
    r"^[A-Za-z0-9_]+\{[ -~]+\}$",
]

DEFAULT_CACHE_FILE = Path(".ctf_flag_cache.json")


class FlagGuard:
    """Manages flag validation, deduplication, and submission tracking."""

    def __init__(self, cache_path: Optional[Path] = None, custom_regex: Optional[str] = None):
        self.cache_path = cache_path or DEFAULT_CACHE_FILE
        self.custom_regex = custom_regex
        self._cache: Dict[str, Any] = self._load_cache()

    def _load_cache(self) -> Dict[str, Any]:
        if self.cache_path.exists():
            try:
                return json.loads(self.cache_path.read_text(encoding="utf-8"))
            except Exception:
                return {"submissions": {}, "solved_challenges": {}}
        return {"submissions": {}, "solved_challenges": {}}

    def _save_cache(self) -> None:
        try:
            self.cache_path.write_text(json.dumps(self._cache, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception as e:
            sys.stderr.write(f"[FlagGuard] Warning: Failed to save cache: {e}\n")

    def validate_format(self, flag: str) -> Tuple[bool, str]:
        """Validates that a flag candidate matches the designated CTF flag regex."""
        flag = flag.strip()
        if not flag:
            return False, "Flag candidate is empty."

        if self.custom_regex:
            if re.match(self.custom_regex, flag):
                return True, f"Matches custom regex: {self.custom_regex}"
            return False, f"Does not match custom regex: {self.custom_regex}"

        for pattern in DEFAULT_FLAG_PATTERNS:
            if re.match(pattern, flag):
                return True, f"Matches pattern: {pattern}"

        return False, "Flag does not match standard CTF format (e.g. flag{...}, HTB{...}, picoCTF{...})."

    def is_duplicate(self, challenge_id: Any, flag: str) -> Tuple[bool, str]:
        """Checks if a flag has already been submitted or rejected for this challenge."""
        cid = str(challenge_id)
        flag = flag.strip()

        # Check if already marked as solved
        if cid in self._cache.get("solved_challenges", {}):
            solved_flag = self._cache["solved_challenges"][cid].get("flag")
            return True, f"Challenge {cid} is already SOLVED with flag: {solved_flag}"

        # Check past attempts for this challenge
        past_attempts = self._cache.get("submissions", {}).get(cid, [])
        for attempt in past_attempts:
            if attempt.get("flag") == flag:
                status = attempt.get("status", "unknown")
                return True, f"Flag '{flag}' was already submitted for challenge {cid} with status: {status}"

        return False, "Flag has not been submitted previously."

    def record_attempt(self, challenge_id: Any, flag: str, status: str, message: str = "") -> None:
        """Records the outcome of a flag submission in the deduplication cache."""
        cid = str(challenge_id)
        flag = flag.strip()

        if "submissions" not in self._cache:
            self._cache["submissions"] = {}
        if cid not in self._cache["submissions"]:
            self._cache["submissions"][cid] = []

        # Record attempt
        self._cache["submissions"][cid].append({
            "flag": flag,
            "status": status,
            "message": message,
        })

        # If correct, mark challenge as solved
        if status in ("correct", "already_solved"):
            if "solved_challenges" not in self._cache:
                self._cache["solved_challenges"] = {}
            self._cache["solved_challenges"][cid] = {
                "flag": flag,
                "status": status,
            }

        self._save_cache()

    def get_solved_challenges(self) -> Dict[str, Any]:
        """Returns map of challenge_id -> solved details."""
        return self._cache.get("solved_challenges", {})

    def is_solved(self, challenge_id: Any) -> bool:
        """Checks if a challenge has already been solved."""
        return str(challenge_id) in self._cache.get("solved_challenges", {})
