# Before → after

## AI Repo Safety

- Offline previously still ran credential verification. Detection is now local by default; online verification requires `scan --verify-secrets`, rejected with offline mode. Rust advisory and optional agent scanners are skipped offline.
- TruffleHog could print raw credentials into terminal/model logs. Output is reduced to counts and exit status; raw stdout/stderr are withheld, even for malformed output. Unverified detections still block.
- Opengrep findings could exit successfully; scans now use `--error`. JSON/SARIF aggregation also propagates failed/error tool runs instead of returning success. Text/JSON/SARIF now share one collector, including bundled fast checks, Opengrep, applicable JS/Go/Rust checks and selected agent scanners. SARIF records scanner status even when external findings are not parsed. Target-provided helper scripts are never executed by the scan collector.
- Installer offered nonexistent `@opengrep/cli`, and Windows direct download had no digest check. Those paths no longer run. Official pinned/verified release instructions are returned as manual prerequisites; Python tools and supported native package managers remain available behind `--yes`.
- Hooks could fall back to an upstream PyPI package. Generated Git/agent/prepush launchers now bind to the bundled fork. A project-local Python module cannot shadow that import. Moving the skill causes a clear fail-closed error.
- Git hooks previously assumed `.git` is a directory. Resolved Git hooks paths now work in linked worktrees and with `core.hooksPath`.
- Distribution-specific npm tests were replaced with bundled-launcher behavior tests; upstream release checks explicitly reject this non-npm bundle. No npm release pipeline is shipped.

## Workflow Herdr

- Unconditional Devin dangerous defaults became CLI-policy inheritance; per-project full trust remains explicitly supported for both Codex and Devin.
- Project YAML or project/mappings cannot declare itself trusted or override launch argv before an owner grant. Owner-scoped grants are stored separately, keyed by the exact real project root, not inherited by sibling/child repositories.
- Blind/repeated Enter at a trust dialog became a separate owner opt-in, a visible selected-Yes check, at most one submission and a positive composer check. Unknown UI is not accepted.
- Same-name agents in another workspace are rejected rather than silently reused.
- Change/task names cannot contain path traversal or absolute paths. Expanded layout writes and role brief reads are constrained to the project/bundled roots, including resolved symlink parents; cross-root paths are rejected even with full trust. Missing workspace identity blocks reuse.
- Preserved Herdr runtime, graph transitions, worktree separation, plan/receipt gates, finite waits and model preflight. Added an explicit work contract explaining objective, scope and acceptance evidence.

No change downgrades a user's existing Codex full-trust configuration or turns it into repeated per-command approval requests. Full trust and task authorization remain distinct.

## Repo Intake Guard

- Added an original skill for unfamiliar repositories and changed agent instructions/media.
- Reviews instruction authority and secret-source → encoded-output → commit chains; includes the trusted-startup limitation.
- Bundled read-only helper flags linked media, suspicious secret-transformation instructions and selected Python byte/base64 literals. Staged mode reads exact indexed blobs with literal path handling.
- Four synthetic tests cover encoded canaries, benign palettes, symlink handling, staged-vs-working-tree differences and Git pathspec metacharacters.
