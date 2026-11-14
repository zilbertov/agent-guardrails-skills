from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

from .util import current_platform, is_windows, project_root, run_cmd, which

# Pinned TruffleHog release for Windows install-tools. Bump after checking
# https://github.com/trufflesecurity/trufflehog/releases
TRUFFLEHOG_RELEASE = "3.97.1"


@dataclass
class ToolSpec:
    name: str
    command: str
    required: bool
    purpose: str
    install_hint: str
    version_args: tuple[str, ...] = ("--version",)
    category: str = "core"
    privacy_note: str = ""


TOOL_SPECS: list[ToolSpec] = [
    ToolSpec("Git", "git", True, "source control and hooks", "Install Git from official docs or OS package manager."),
    ToolSpec("Python", "python", True, "runtime; Python 3.12+ required", "Install Python 3.12+ or use `uv python install 3.12`."),
    ToolSpec("uv", "uv", False, "Python package/project manager", "Install uv from Astral official docs."),
    ToolSpec("pre-commit", "pre-commit", False, "local commit hooks", "Install with `uv tool install pre-commit`."),
    ToolSpec("Gitleaks", "gitleaks", False, "fast secret scanning", "Install from Gitleaks official releases or package manager."),
    ToolSpec("TruffleHog", "trufflehog", False, "deep secret scanning and verification", "Install from TruffleHog official docs/releases."),
    ToolSpec("detect-secrets", "detect-secrets", False, "baseline-oriented secret scanner", "Install with `uv tool install detect-secrets`."),
    ToolSpec("Opengrep", "opengrep", False, "open-source SAST pattern engine", "Install from Opengrep official docs/releases; use current stable compatible version."),
    ToolSpec("Bandit", "bandit", False, "Python SAST", "Install with `uv tool install bandit`."),
    ToolSpec("Ruff", "ruff", False, "Python lint/security rules", "Install with `uv tool install ruff`."),
    ToolSpec("pip-audit", "pip-audit", False, "Python dependency vulnerability scanner", "Install with `uv tool install pip-audit`."),
    ToolSpec("OSV-Scanner", "osv-scanner", False, "open-source vulnerability scanner", "Install from OSV-Scanner official releases or package manager."),
    ToolSpec("GitHub CLI", "gh", False, "GitHub read guard backend", "Install GitHub CLI from official docs or package manager."),
    ToolSpec("git-filter-repo", "git-filter-repo", False, "clean leaked secrets from Git history", "Install with `uv tool install git-filter-repo` or OS package manager."),
    ToolSpec("GitLab CLI", "glab", False, "GitLab read guard backend", "Install GitLab CLI from official docs or package manager.", category="gitlab"),
    ToolSpec("gosec", "gosec", False, "Go static security analyzer", "Install from securego/gosec official releases or an exact reviewed securego/gosec release after checking the current release.", category="go"),
    ToolSpec("govulncheck", "govulncheck", False, "Go vulnerability analyzer", "Install from Go official tooling with an exact reviewed golang.org/x/vuln release after checking Go docs.", category="go"),
    ToolSpec("cargo-audit", "cargo-audit", False, "Rust dependency vulnerability scanner", "Install from RustSec/cargo-audit official releases using an exact reviewed version.", category="rust"),
    ToolSpec("cargo-deny", "cargo-deny", False, "Rust dependency/license/advisory policy gate", "Install from EmbarkStudios/cargo-deny official releases using an exact reviewed version.", category="rust"),
    ToolSpec("ESLint", "eslint", False, "JavaScript/TypeScript lint and security-adjacent rules", "Use the project's package manager and official ESLint docs.", category="typescript"),
    ToolSpec("npm", "npm", False, "JavaScript package audit backend", "Install Node.js/npm from official Node.js distributions.", category="typescript"),
    ToolSpec("Snyk Agent Scan", "snyk-agent-scan", False, "AI agent, MCP, and skill scanner", "Install from Snyk Agent Scan official releases/docs.", category="agent-skill", privacy_note="may send agent metadata to Snyk cloud; require explicit opt-in before running"),
    ToolSpec("Cisco Skill Scanner", "skill-scanner", False, "AI skill prompt-injection and exfiltration scanner", "Install from cisco-ai-defense/skill-scanner official repository.", category="agent-skill"),
    ToolSpec("NVIDIA SkillSpector", "skillspector", False, "AI agent skill scanner with structured reports", "Install from NVIDIA/SkillSpector official repository.", category="agent-skill"),
]

PYTHON_TOOL_COMMANDS = {name: f"Install reviewed {name} and transitive dependencies from an owner-maintained hash-locked requirements file." for name in ("pre-commit", "detect-secrets", "bandit", "ruff", "pip-audit", "git-filter-repo")}
WINDOWS_INSTALL = {}
UNIX_INSTALL = {}


def install_one_liner(spec: ToolSpec) -> str:
    py_cmd = PYTHON_TOOL_COMMANDS.get(spec.command)
    if py_cmd:
        return py_cmd
    table = WINDOWS_INSTALL if is_windows() else UNIX_INSTALL
    return table.get(spec.command, spec.install_hint)


def check_python_312() -> tuple[bool, str]:
    version = sys.version_info
    ok = version >= (3, 12)
    return ok, f"{version.major}.{version.minor}.{version.micro}"


def check_tool(spec: ToolSpec) -> tuple[bool, str]:
    if spec.command == "python" and is_windows() and not which("python") and which("py"):
        code, out, err = run_cmd(["py", "-3", "--version"], timeout=20)
        if code == 0:
            version = (out or err or "py -3").strip().splitlines()[0]
            return True, version
    path = which(spec.command)
    if not path:
        return False, "missing"
    code, out, err = run_cmd([spec.command, *spec.version_args], timeout=20)
    if code != 0:
        return False, (err or out or f"exit:{code}").strip()
    version = (out or err or path).strip().splitlines()[0] if (out or err) else path
    if len(version) > 100:
        version = version[:100] + "..."
    return True, version


def doctor(*, agent_plan: bool = False, json_out: bool = False, target: str | Path | None = None) -> int:
    root = project_root(target or ".")
    rows: list[tuple[str, str, str]] = [("Tool", "Status", "Details")]
    missing_required: list[ToolSpec] = []
    missing_optional: list[ToolSpec] = []
    tool_rows: list[dict] = []

    py_ok, py_ver = check_python_312()
    if not py_ok:
        rows.append(("Python version", "FAIL", f"{py_ver}; Python 3.12+ required"))
    else:
        rows.append(("Python version", "OK", py_ver))

    for spec in TOOL_SPECS:
        ok, details = check_tool(spec)
        status = "OK" if ok else ("FAIL" if spec.required else "MISSING")
        install = install_one_liner(spec)
        display = details if ok else install
        if spec.privacy_note:
            display = f"{display}; {spec.privacy_note}"
        rows.append((spec.name, status, display))
        tool_rows.append(
            {
                "name": spec.name,
                "command": spec.command,
                "status": status,
                "details": details if ok else display,
                "install": install,
                "required": spec.required,
            }
        )
        if not ok and spec.required:
            missing_required.append(spec)
        elif not ok:
            missing_optional.append(spec)

    uv_lock = (root / "uv.lock").exists()
    osv_ok = bool(which("osv-scanner"))
    tag_gate_ok = (not uv_lock) or osv_ok
    if uv_lock and not osv_ok:
        rows.append(
            (
                "OSV-Scanner (tag gate)",
                "FAIL",
                f"{install_one_liner(next(s for s in TOOL_SPECS if s.command == 'osv-scanner'))}; uv.lock present so tag gate requires osv-scanner",
            )
        )
        missing_required.append(next(s for s in TOOL_SPECS if s.command == "osv-scanner"))

    missing_payload = [
        {"name": spec.name, "install": install_one_liner(spec)}
        for spec in missing_required + missing_optional
    ]
    # Dedupe osv-scanner if added twice.
    seen: set[str] = set()
    unique_missing: list[dict] = []
    for item in missing_payload:
        if item["name"] in seen:
            continue
        seen.add(item["name"])
        unique_missing.append(item)

    payload = {
        "platform": current_platform(),
        "python_executable": sys.executable,
        "python": {"ok": py_ok, "version": py_ver},
        "target": str(root),
        "tools": tool_rows,
        "missing": unique_missing,
        "tag_gate": {"uv_lock": uv_lock, "osv_scanner": osv_ok, "ok": tag_gate_ok},
        "invoke": [[sys.executable, str(Path(__file__).resolve().parents[2] / "scripts/repo_safety.py")]],
    }

    if json_out:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        if not py_ok or missing_required:
            return 2
        return 0

    print("AI Repo Safety Doctor")
    print(f"Platform: {current_platform()}")
    print(f"Python executable: {sys.executable}")
    print()

    from .util import print_table
    print_table(rows)
    print()

    if missing_required or agent_plan:
        print("Agent install plan (one command per missing tool):")
        for item in unique_missing:
            print(f"- {item['name']}: `{item['install']}`")
        print()
        print("Canonical invoke: use this reviewed bundle's scripts/repo_safety.py; no registry fallback.")
        print("Install tools separately from reviewed, pinned releases, then re-run the bundled doctor.")

    if not py_ok or missing_required:
        return 2
    return 0



def install_missing_tools(*, dry_run: bool = False, yes: bool = False) -> int:
    """Report prerequisites without fetching a changing package or installer."""
    missing = [spec for spec in TOOL_SPECS if not which(spec.command)]
    for spec in missing:
        print(f"[repo-safety] missing {spec.command}: install a reviewed pinned version separately; verify signed checksums for native releases or use a transitive hash lock for Python tools.")
    print("[repo-safety] prerequisite plan only; no downloads or installation performed, including with legacy --yes.")
    return 2 if missing and not dry_run else 0
