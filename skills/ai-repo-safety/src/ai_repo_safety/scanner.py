from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from typing import Mapping

from .util import project_root, run_cmd, which, git_has_commits


def run_available(
    command: list[str],
    *,
    cwd: Path,
    required: bool = False,
    timeout: int = 300,
    env: Mapping[str, str] | None = None,
) -> tuple[int, str, str]:
    if not which(command[0]):
        level = "ERROR" if required else "WARN"
        print(
            f"[repo-safety] {level}: missing tool `{command[0]}`; run `ai-repo-safety doctor --agent-plan`"
        )
        return 127, "", f"missing:{command[0]}"
    print(f"[repo-safety] running: {' '.join(command)}")
    code, out, err = run_cmd(command, cwd=cwd, timeout=timeout, env=env)
    if command[0] == "trufflehog":
        from .secret_scan import safe_trufflehog_output
        code, out, err = safe_trufflehog_output(code, out, err)
    if out:
        print(out.rstrip())
    if err:
        print(err.rstrip())
    if code != 0:
        print(f"[repo-safety] command failed: {' '.join(command)}")
    return code, out, err


def run_optional_tool(
    tool: str,
    command: list[str],
    *,
    cwd: Path,
    timeout: int = 300,
) -> tuple[int, str, str]:
    if not which(tool):
        print(
            f"[repo-safety] WARN: missing tool `{tool}`; run `ai-repo-safety doctor --agent-plan`"
        )
        return 127, "", f"missing:{tool}"
    return run_available(command, cwd=cwd, required=False, timeout=timeout)


def _python_executable() -> list[str]:
    """Return the python executable to invoke for the local security
    helper scripts that ship under .repo-safety/scripts/. We use
    sys.executable so the same Python that runs the CLI runs the
    helpers; on systems where `python` is missing, the helpers
    still work as long as the user is in the venv that installed
    ai-repo-safety."""
    return [sys.executable]


def _helper_script(root: Path, name: str) -> str | None:
    for rel in (f".repo-safety/scripts/{name}", f"scripts/security/{name}"):
        if (root / rel).exists():
            return rel
    return None


def _resolve_trufflehog_since_commit(root: Path) -> str | None:
    """Pick a safe 'since' revision for TruffleHog.

    Returns None if no commit on the local branch can be used as a
    stable lower bound. TruffleHog accepts a commit SHA, and a
    missing or invalid SHA makes the tool error out.
    """
    candidates: list[list[str]] = [
        ["git", "merge-base", "HEAD", "@{upstream}"],
        ["git", "merge-base", "HEAD", "origin/main"],
        ["git", "merge-base", "HEAD", "origin/dev"],
    ]
    for cmd in candidates:
        code, out, _ = run_cmd(cmd, cwd=root, timeout=20)
        if code == 0 and out.strip():
            return out.strip()
    code, out, _ = run_cmd(
        ["git", "rev-list", "--max-count=20", "HEAD"], cwd=root, timeout=20
    )
    if code == 0:
        commits = [line.strip() for line in out.splitlines() if line.strip()]
        if len(commits) >= 2:
            return commits[-1]
    return None


def _trufflehog_exclude_args(root: Path) -> list[str]:
    exclude_file = root / ".repo-safety" / "trufflehog-exclude.txt"
    if exclude_file.exists():
        return ["--exclude-paths", str(exclude_file)]
    return []


def _looks_like_go_repo(root: Path) -> bool:
    return (root / "go.mod").exists()


def _looks_like_rust_repo(root: Path) -> bool:
    return (root / "Cargo.toml").exists()


def _looks_like_js_repo(root: Path) -> bool:
    return any((root / name).exists() for name in ("package.json", "pnpm-lock.yaml", "yarn.lock", "package-lock.json"))


def _scan_engine(
    target: str | Path,
    *,
    strict: bool = False,
    offline: bool = False,
    agent_skills: bool = False,
    allow_cloud_agent_scan: bool = False,
    verify_secrets: bool = False,
    report=None,
) -> int:
    from .secret_scan import trufflehog_flags
    secret_flags = trufflehog_flags(offline=offline, verify_secrets=verify_secrets)
    root = project_root(target)
    failures = 0
    network_required_skipped: list[str] = []

    # Run only bundled checks, never similarly named scripts in the target repo.
    from .fast_scan import scan_directory
    from .results import Finding, ToolRun
    for f in scan_directory(root):
        report.findings.append(Finding(id=f"{f.get('type')}@{f.get('file')}:{f.get('line',0)}", severity="high", category=f.get("type", "secret_content"), message=str(f.get("message", "Sensitive content detected")), file=f.get("file"), line=f.get("line"), tool="fast_scan"))
    failures += bool(report.findings)
    # Import only the audited bundled asset, not target/.repo-safety scripts.
    import runpy
    bundled = Path(__file__).parent / "assets/scripts/scan_mcp_config.py"
    mcp_scan = runpy.run_path(str(bundled))["scan_file"]
    for name in (".mcp.json", "claude_desktop_config.json"):
        path=root/name
        if path.is_file():
            problems=mcp_scan(path)
            if problems:
                report.findings.append(Finding(id=f"mcp-policy@{name}",severity="medium",category="policy_violation",message="MCP configuration requires review (details withheld)",file=name,tool="mcp_scan"))
                failures += 1

    def run_available(command, *, cwd, required=False, timeout=300, env=None):
        # Suppress external output: scanners may echo matching secrets or source.
        import contextlib, io
        with contextlib.redirect_stdout(io.StringIO()):
            code, out, err = globals()["run_available"](command,cwd=cwd,required=required,timeout=timeout,env=env)
        report.tools.append(ToolRun(name=command[0],command=command,status="skipped" if code==127 else "passed" if code==0 else "failed",exit_code=code,required=required,reason="missing" if code==127 else None))
        return code, "", ""

    def run_optional_tool(tool, command, *, cwd, timeout=300):
        if not which(tool):
            report.tools.append(ToolRun(name=tool,command=command,status="skipped",reason="missing"))
            return 127,"",""
        return run_available(command,cwd=cwd,timeout=timeout)

    commands: list[list[str]] = [
        ["gitleaks", "detect", "--source", ".", "--redact", "--exit-code", "1"],
    ]
    if git_has_commits(root):
        since = _resolve_trufflehog_since_commit(root) if not offline else None
        if since:
            commands.append(
                [
                    "trufflehog",
                    "git",
                    "file://.",
                    "--since-commit",
                    since,
                    *_trufflehog_exclude_args(root),
                    *secret_flags,
                ]
            )
        else:
            commands.append(
                [
                    "trufflehog",
                    "filesystem",
                    ".",
                    *_trufflehog_exclude_args(root),
                    *secret_flags,
                ]
            )
    else:
        commands.append(
            [
                "trufflehog",
                "filesystem",
                ".",
                *_trufflehog_exclude_args(root),
                *secret_flags,
            ]
        )

    for command in commands:
        code, _, _ = run_available(command, cwd=root, required=strict)
        if code != 0 and code != 127:
            failures += 1
        elif strict and code == 127:
            failures += 1

    opengrep_rules = root / ".repo-safety" / "opengrep"
    if opengrep_rules.exists():
        command = [
            "opengrep",
            "--error",
            "--config",
            str(opengrep_rules),
            "--exclude",
            ".repo-safety/opengrep/",
            "--exclude",
            "src/ai_repo_safety/assets/rules/opengrep/",
            ".",
        ]
        code, _, _ = run_available(command, cwd=root, required=strict)
        if code not in (0, 127) or (strict and code == 127):
            failures += 1

    if (
        (root / "pyproject.toml").exists()
        or (root / "requirements.txt").exists()
        or any(root.glob("**/*.py"))
    ):
        for command in [
            ["bandit", "-q", "-r", "src", "-x", "tests"],
            ["ruff", "check", "."],
        ]:
            code, _, _ = run_available(command, cwd=root, required=False)
            if code not in (0, 127):
                failures += 1

        if offline:
            print("[repo-safety] skipping lockfile audit (offline mode): network_required")
            network_required_skipped.append("lockfile-audit")
        else:
            from .lockfile_audit import audit_lockfile

            code, detail = audit_lockfile(root, required=False, offline=False)
            if detail:
                print(detail)
            if code == 127:
                network_required_skipped.append("lockfile-audit")
            elif code != 0:
                failures += 1

    if _looks_like_go_repo(root):
        go_commands = [["gosec", "./..."]]
        if offline:
            print("[repo-safety] skipping govulncheck (offline mode): network_required")
            network_required_skipped.append("govulncheck")
        else:
            go_commands.append(["govulncheck", "./..."])
        for command in go_commands:
            code, _, _ = run_available(command, cwd=root, required=False)
            if code not in (0, 127):
                failures += 1

    if _looks_like_rust_repo(root) and offline:
        print("[repo-safety] skipping Rust advisory tools (offline mode)")
        network_required_skipped.append("rust-advisories")
    if _looks_like_rust_repo(root) and not offline:
        for tool, command in [
            ("cargo-audit", ["cargo", "audit"]),
            ("cargo-deny", ["cargo", "deny", "check"]),
        ]:
            code, _, _ = run_optional_tool(tool, command, cwd=root)
            if code not in (0, 127):
                failures += 1

    if _looks_like_js_repo(root):
        js_commands = [["eslint", "."]]
        if offline:
            print("[repo-safety] skipping npm audit (offline mode): network_required")
            network_required_skipped.append("npm-audit")
        else:
            js_commands.append(["npm", "audit", "--audit-level=moderate"])
        for command in js_commands:
            code, _, _ = run_available(command, cwd=root, required=False)
            if code not in (0, 127):
                failures += 1

    if agent_skills and offline:
        print("[repo-safety] skipping optional agent scanners (offline mode)")
        network_required_skipped.append("agent-scanners")
    if agent_skills and not offline:
        for command in [["skillspector", "scan", ".", "--no-llm"], ["skill-scanner", "scan", "."]]:
            code, _, _ = run_available(command, cwd=root, required=False)
            if code not in (0, 127):
                failures += 1
        if allow_cloud_agent_scan:
            code, _, _ = run_available(["snyk-agent-scan", "scan"], cwd=root, required=False)
            if code not in (0, 127):
                failures += 1
        elif which("snyk-agent-scan"):
            print("[repo-safety] skipping snyk-agent-scan: pass --allow-cloud-agent-scan to allow cloud-backed metadata analysis")

    for name in network_required_skipped:
        report.tools.append(ToolRun(name=name,command=[],status="skipped",reason="network_required"))
    if failures:
        print(f"[repo-safety] scan failed with {failures} failing check(s)")
        return 1
    if network_required_skipped and strict:
        print(
            f"[repo-safety] scan partial: skipped {network_required_skipped} under --strict"
        )
        return 3
    print("[repo-safety] scan completed")
    return 0


def collect_report(target, *, strict=False, offline=False, agent_skills=False, allow_cloud_agent_scan=False, verify_secrets=False):
    import contextlib, io
    from .results import ScanReport
    report=ScanReport(status="passed",target=str(project_root(target)))
    with contextlib.redirect_stdout(io.StringIO()):
        code=_scan_engine(target,strict=strict,offline=offline,agent_skills=agent_skills,allow_cloud_agent_scan=allow_cloud_agent_scan,verify_secrets=verify_secrets,report=report)
    report.status="failed" if code==1 or report.findings else "partial" if code==3 or any(t.status=="skipped" for t in report.tools) else "passed"
    return report


def scan(target, **options):
    report=collect_report(target,**options)
    for tool in report.tools:
        print(f"[repo-safety] {tool.name}: {tool.status}" + (f" ({tool.reason})" if tool.reason else ""))
    for f in report.findings:
        print(f"[repo-safety] {f.file}:{f.line or 0}: {f.category}")
    print(f"[repo-safety] scan {report.status}")
    return report.exit_code(strict=options.get("strict",False))


def prepush(target: str | Path, *, offline: bool = False, json_out: bool = False) -> int:
    from .gate import run_gate

    return run_gate(target, when="push", offline=offline, json_out=json_out)
