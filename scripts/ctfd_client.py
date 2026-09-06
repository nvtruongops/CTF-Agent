#!/usr/bin/env python3
"""
CTFd Platform Automation Client (v2.0)
Handles authentication, pagination, challenge files, hints, and flag submission.
"""

import os
import sys
import json
import time
import urllib.request
import urllib.error
from typing import Optional, Dict, Any, List

class CTFdClient:
    def __init__(self, base_url: str, api_token: str):
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": f"Token {api_token}",
            "Content-Type": "application/json",
            "User-Agent": "CTF-Agent-PlatformClient/2.0"
        }

    def _request(self, method: str, endpoint: str, data: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        url = f"{self.base_url}/api/v1/{endpoint.lstrip('/')}"
        payload = json.dumps(data).encode("utf-8") if data else None
        req = urllib.request.Request(url, data=payload, headers=self.headers, method=method)

        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    time.sleep(2 ** attempt)
                    continue
                return None
            except Exception:
                return None
        return None

    def get_challenges(self) -> List[Dict[str, Any]]:
        """Retrieve all challenges across all paginated pages."""
        all_challenges = []
        page = 1
        while True:
            res = self._request("GET", f"challenges?page={page}")
            if not res or not res.get("success") or not res.get("data"):
                break
            all_challenges.extend(res["data"])
            pagination = res.get("meta", {}).get("pagination", {})
            if page >= pagination.get("pages", 1):
                break
            page += 1
        return all_challenges

    def get_challenge_details(self, challenge_id: int) -> Optional[Dict[str, Any]]:
        res = self._request("GET", f"challenges/{challenge_id}")
        return res.get("data") if res else None

    def get_challenge_files(self, challenge_id: int) -> List[str]:
        """Fetch distinct attachment URLs for a challenge."""
        res = self._request("GET", f"challenges/{challenge_id}/files")
        if res and res.get("success"):
            return [f.get("location") for f in res.get("data", [])]
        return []

    def get_challenge_hints(self, challenge_id: int) -> List[Dict[str, Any]]:
        res = self._request("GET", f"challenges/{challenge_id}/hints")
        return res.get("data", []) if res else []

    def submit_flag(self, challenge_id: int, flag: str) -> Dict[str, Any]:
        data = {"challenge_id": challenge_id, "submission": flag}
        res = self._request("POST", "challenges/attempt", data=data)
        if res and res.get("success"):
            status = res.get("data", {}).get("status", "incorrect")
            return {"status": status, "message": res.get("data", {}).get("message", "")}
        return {"status": "error", "message": "Failed to communicate with CTFd"}

if __name__ == "__main__":
    print("CTFdClient module initialized. Import in solve scripts or CTF automation tools.")
