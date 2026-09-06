#!/usr/bin/env python3
"""
Unit and Integration Tests for Parallel Triage Scheduler
Validates concurrent binary inspection, pure Python ELF parsing, web diagnostics, and JSON output.
"""

import sys
import json
import tempfile
import threading
import subprocess
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from parallel_triage import ParallelTriageScheduler, PurePythonElfTriage


@pytest.fixture
def mock_elf_binary():
    """Constructs a minimal test ELF 64-bit binary with canary and win function strings."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        # Header: \x7fELF (64-bit, little endian, ET_EXEC = 2)
        header = bytearray(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)
        header += (2).to_bytes(2, "little")  # e_type = ET_EXEC (No PIE)
        header += (62).to_bytes(2, "little") # e_machine = x86_64
        header += b"\x00" * 44               # padding to 64 bytes
        # Payload containing test symbols and strings
        payload = b"GNU_STACK\x00__stack_chk_fail\x00win\x00system\x00flag{test_parallel_flag}\x00"
        f.write(header + payload)
        path = Path(f.name)

    yield path

    if path.exists():
        path.unlink()


def test_pure_python_elf_parser(mock_elf_binary):
    """Verifies that PurePythonElfTriage detects bitness, PIE, NX, and canary flags."""
    res = PurePythonElfTriage.parse_elf(mock_elf_binary)

    assert res["is_elf"] is True
    assert res["bitness"] == 64
    assert "No PIE" in res["pie"]
    assert "Canary found" in res["canary"]
    assert "NX enabled" in res["nx"]


def test_binary_parallel_triage_synthesizes_recommendations(mock_elf_binary):
    """Verifies that ParallelTriageScheduler runs all 4 diagnostic vectors and synthesizes actionable CTF advice."""
    res = ParallelTriageScheduler.triage_binary(mock_elf_binary)

    assert res["type"] == "binary"
    diag = res["diagnostics"]
    assert "file" in diag
    assert "checksec" in diag
    assert "strings" in diag
    assert "symbols" in diag

    # Should detect test plaintext flag in strings
    assert any("flag{test_parallel_flag}" in s for s in diag["strings"])

    # Recommendations should include ret2win / fixed addresses
    recs = res["recommendations"]
    assert any("ret2win" in r.lower() or "win" in r.lower() for r in recs)


class MockWebHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin_secret_area\n")
        elif self.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"FLAG=flag{leak_env_success}\n")
        else:
            self.send_response(200)
            self.send_header("Server", "Werkzeug/3.0.1 Python/3.12")
            self.send_header("X-Powered-By", "Flask")
            self.end_headers()
            self.wfile.write(b"<html><body>CTF Challenge Home</body></html>")

    def log_message(self, format, *args):
        pass  # Suppress console log spam during test


@pytest.fixture
def mock_web_server():
    """Spins up a lightweight ephemeral HTTP server on localhost."""
    server = HTTPServer(("127.0.0.1", 0), MockWebHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield f"http://127.0.0.1:{port}"

    server.shutdown()


def test_web_parallel_triage(mock_web_server):
    """Verifies that ParallelTriageScheduler runs concurrent web probes and catches leaks & server tech."""
    res = ParallelTriageScheduler.triage_web(mock_web_server)

    assert res["type"] == "web"
    diag = res["diagnostics"]
    assert "headers" in diag
    assert "robots_txt" in diag
    assert "leaks" in diag

    # Check robots.txt detection
    assert diag["robots_txt"]["present"] is True
    assert any("/admin_secret_area" in d for d in diag["robots_txt"]["disallows"])

    # Check leak probe
    assert "/.env" in diag["leaks"]

    # Recommendations should detect Werkzeug/Flask SSTI hint and sensitive leak
    recs = " ".join(res["recommendations"])
    assert "Flask" in recs or "SSTI" in recs
    assert "Leak" in recs or "Sensitive" in recs


def test_cli_parallel_triage_json(mock_elf_binary):
    """Verifies that 'python scripts/parallel_triage.py --json' emits valid structured JSON."""
    cmd = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "parallel_triage.py"),
        str(mock_elf_binary),
        "--json",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)

    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert data["type"] == "binary"
    assert "diagnostics" in data
    assert "recommendations" in data
