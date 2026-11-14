"""Shared secret scanner policy and output boundary."""
from __future__ import annotations
import json
from pathlib import Path

def trufflehog_flags(*, offline: bool = False, verify_secrets: bool = False) -> list[str]:
    if offline and verify_secrets:
        raise ValueError("--offline cannot be combined with --verify-secrets")
    # Detection is local by default; verification may exercise real credentials.
    flags = ["--no-update", "--json", "--results=verified,unknown,unverified", "--fail"]
    if not verify_secrets:
        flags.append("--no-verification")
    return flags

def safe_trufflehog_output(code: int, stdout: str, stderr: str) -> tuple[int, str, str]:
    # Never relay raw stdout/stderr: either can include credentials, context or
    # an attacker-controlled field. Counts preserve the actionable signal.
    results = 0
    malformed = False
    for line in stdout.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except (ValueError, TypeError):
            malformed = True
            continue
        if not isinstance(item, dict):
            malformed = True
        else:
            results += 1
    if malformed and code == 0:
        code = 2
    # Some versions/integrations fail to return --fail despite emitted results.
    if results and code == 0:
        code = 1
    summary = f"TruffleHog: {results} finding(s); exit {code}; raw output withheld"
    return code, summary, ""

def bundled_launcher() -> Path:
    return Path(__file__).resolve().parents[2] / "scripts" / "repo_safety.py"
