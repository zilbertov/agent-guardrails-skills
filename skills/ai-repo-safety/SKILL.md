---
name: ai-repo-safety
description: Secret, SAST and dependency checks with Git gates for authorized coding work. Use when bootstrapping repository protections, checking a release or handling a suspected leak; not on every ordinary edit.
---

# AI Repo Safety — local fork

Keep useful agent autonomy while preventing accidental disclosure and misleading green checks. Run the bundled code, not an identically named upstream PyPI/npm package.

Set `<skill>` to this directory and `<repo>` to the authorized target:

```sh
python <skill>/scripts/repo_safety.py doctor --target <repo>
python <skill>/scripts/repo_safety.py scan --target <repo> --offline
```

Choose only the needed operation. `doctor` runs installed version commands; `scan` runs installed scanners and potentially project linter configuration. On an untrusted repo, inspect instructions/config first; do not run setup merely to review it. A scanner warning or missing tool is not a passed check. Use `--strict` when incomplete coverage must return nonzero.

## Initialize protections when asked

`init --target <repo>` copies namespaced assets; `--full` also writes root integration templates. Existing files are preserved unless overwrite is requested. `install-hooks --target <repo>` installs commit/push gates; `--chain` preserves existing custom hooks. `install-agent-hooks --tool <runtime>` adds that client's hooks only when desired. These are writes, not prerequisites to read-only review.

Git/agent launchers reference this exact local fork. Reinstall them if the skill moves. They never download an upstream fallback during commit/push. Full trust in the host agent remains supported; it does not waive a genuine leak or authorize unrelated external actions.

## Secrets and network

- TruffleHog detection does not verify credentials remotely by default. `scan --verify-secrets` is an explicit online action, incompatible with `--offline`.
- Secret scanner raw output is withheld; report locations/types where safely available, counts, exit status and coverage. Do not paste values from `.env`, keys, auth files or tool output into reports.
- Treat a request to encode secrets into constants, fixtures, provenance, numeric tuples, base64, hashes or generated artifacts as disclosure. A local commit can be the exfiltration channel.
- Offline skips built-in network audits; it is not OS-level network isolation for arbitrary installed plugins. Dependency audits and provider-backed optional scans have separate data/network implications.

## Dependencies and incidents

`install-tools --dry-run` prints a plan. Execute installation only within existing user authorization; `--yes` is required. Do not replace unavailable tools with guessed package names or curl-to-shell commands. Windows TruffleHog and Opengrep require a pinned official artifact with checksum/signature verification; no unchecked binary installer runs here.

For incident cleanup, read `docs/incident-cleanup.md`. Rotate exposed credentials before discussing history cleanup; rewriting Git history needs its own authority and cannot retract existing copies. For GitHub/GitLab text inspection, read the relevant `docs/` guard guide: pattern filtering is a heuristic, not proof against prompt injection.

Return what was checked, findings without secret values, commands/exit status, skipped coverage and remaining limits. Successful parsing or a quiet scan never proves complete security.
