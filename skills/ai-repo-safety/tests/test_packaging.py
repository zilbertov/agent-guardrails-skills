from __future__ import annotations

from importlib.resources import files
from pathlib import Path
import sys
import pytest

# These assets are read at runtime by `init`, `setup`, `incident`,
# `threat-model`, and `install-hooks` via importlib.resources. If any
# of them is missing from the installed package, those commands
# raise FileNotFoundError. Asserting their presence here is the
# source-tree counterpart of the installed-wheel smoke test
# (`scripts/smoke-wheel.sh`).
REQUIRED_ASSETS: tuple[str, ...] = (
    "docs/agent-hooks.md",
    "docs/git-integrity.md",
    "templates/universal/AGENTS.md",
    "templates/universal/SECURITY.md",
    "templates/universal/env.example",
    "templates/universal/gitignore.block",
    "templates/universal/dockerignore",
    "templates/universal/pre-commit-config.yaml",
    "templates/gitlab/.gitlab-ci.yml",
    "templates/gitlab/merge_request_templates/default.md",
    "templates/gitlab/issue_templates/security.md",
    "templates/python/bandit.yaml",
    "templates/python/pyproject.ai-repo-safety.toml",
    "templates/python/settings.py",
    "templates/python/test_security_basics.py",
    "rules/opengrep/python-dangerous-code.yml",
    "rules/opengrep/github-actions-security.yml",
    "scripts/forbid_sensitive_files.py",
    "scripts/agent_hook_runner.py",
    "scripts/prepush.py",
    "scripts/scan_mcp_config.py",
)


def test_required_assets_are_available_from_package_resources() -> None:
    root = files("ai_repo_safety") / "assets"
    missing: list[str] = []
    for rel in REQUIRED_ASSETS:
        if not (root / rel).is_file():
            missing.append(rel)
    assert not missing, f"missing required package assets: {missing}"


def test_bundled_launcher_runs_this_fork(tmp_path):
    import subprocess, sys
    launcher = Path(__file__).resolve().parents[1] / "scripts/repo_safety.py"
    (tmp_path / "ai_repo_safety.py").write_text("raise RuntimeError('project shadow import')")
    proc = subprocess.run([sys.executable, str(launcher), "--version"], cwd=tmp_path, capture_output=True, text=True, timeout=15)
    assert proc.returncode == 0
    assert "zilbertov" in proc.stdout
