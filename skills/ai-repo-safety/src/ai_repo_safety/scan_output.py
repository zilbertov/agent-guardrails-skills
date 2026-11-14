"""Structured JSON and SARIF output for `ai-repo-safety scan`.

The default text path is unchanged: it prints human-readable
status lines and returns the integer exit code. The structured
paths wrap the same scanners and emit a machine-readable
representation of the result for CI ingestion.
"""

from __future__ import annotations

import json
import subprocess  # nosec
import sys
from pathlib import Path

def _collect_report(target, **options):
    from .scanner import collect_report
    return collect_report(target, **options)


def emit_scan(
    target: str | Path,
    *,
    strict: bool = False,
    offline: bool = False,
    sarif: bool = False,
    verify_secrets: bool = False,
    agent_skills: bool = False,
    allow_cloud_agent_scan: bool = False,
) -> int:
    report = _collect_report(target, strict=strict, offline=offline, verify_secrets=verify_secrets, agent_skills=agent_skills, allow_cloud_agent_scan=allow_cloud_agent_scan)
    if sarif:
        sarif_doc = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "ai-repo-safety",
                            "version": "0.1.9+zilbertov.1",
                            "informationUri": "https://github.com/letya999/ai-repo-safety-skill",
                            "rules": [],
                        }
                    },
                    "invocations": [{"executionSuccessful": report.exit_code(strict=strict)==0,"properties": {"status": report.status,"tools": report.to_dict()["tools"]}}],
                    "results": [
                        {
                            "ruleId": f.id,
                            "level": "error"
                            if f.severity in {"high", "critical"}
                            else "warning",
                            "message": {"text": f.message},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": f.file or "."},
                                        "region": {"startLine": f.line or 1}
                                        if f.line
                                        else {},
                                    }
                                }
                            ]
                            if f.file
                            else [],
                        }
                        for f in report.findings
                    ],
                }
            ],
        }
        sys.stdout.write(json.dumps(sarif_doc, indent=2, ensure_ascii=False) + "\n")
    else:
        sys.stdout.write(
            json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n"
        )
    return report.exit_code(strict=strict)


__all__ = ["emit_scan"]
