# Agent Guardrails Skills

Three skills for coding agents: two focused forks and an original repository intake guard. Preserve intentional full trust while checking repository instructions, secrets and development workflows.

| Skill | Use it for | Start here |
| --- | --- | --- |
| AI Repo Safety | Secret checks, SAST, dependency audit and fail-closed Git gates in a trusted working repository | [SKILL.md](skills/ai-repo-safety/SKILL.md) |
| Workflow Herdr | Contract → plan → implementation → evidence across Herdr seats/worktrees | [SKILL.md](skills/workflow-herdr/SKILL.md) |
| Repo Intake Guard | Review unfamiliar repo instructions and linked media; catch GhostCommit-style encoded secret traps before setup or publication | [SKILL.md](skills/repo-intake-guard/SKILL.md) |

## Install instructions, not dependencies

Copy the **complete selected skill directory** into your agent's supported project/user skill directory. Keep `src`, `scripts`, `assets`, and references together. Nothing installs on clone or import. Avoid keeping upstream and this fork enabled under the same skill name.

For clients using Vercel's Skills CLI, these are discoverable as separate skills:

```sh
npx skills add zilbertov/agent-guardrails-skills --skill ai-repo-safety
npx skills add zilbertov/agent-guardrails-skills --skill workflow-herdr
npx skills add zilbertov/agent-guardrails-skills --skill repo-intake-guard
```

These commands execute an external installer; manual copy avoids that dependency. For repeatable installs use a reviewed commit URL instead of a moving branch. Python 3.12+ is needed for bundled commands. Herdr and the selected coding CLIs are separate prerequisites.

## Repo Intake Guard

Use it before adopting instructions or running setup in an unfamiliar repository, and when agent instructions or their linked media change. Load the guard from a trusted skill store before the repository instructions. It reviews instruction chains, flags linked media for inspection, and checks Python integer tuples/base64 for some encoded environment-like content. `--staged` reads exact Git-index blobs.

```sh
python skills/repo-intake-guard/scripts/inspect_repo.py /absolute/unfamiliar-repo
python skills/repo-intake-guard/scripts/inspect_repo.py /absolute/project --staged
```

The helper is read-only and uses Python standard library modules. It does not execute project code, print decoded secrets, OCR images or prove that a repository is safe. Inspect linked images separately. This skill is a review aid, not a sandbox or an enforcement layer.

## Repo Safety quick start

```sh
python skills/ai-repo-safety/scripts/repo_safety.py doctor --target /absolute/project
python skills/ai-repo-safety/scripts/repo_safety.py scan --target /absolute/project --offline
python skills/ai-repo-safety/scripts/repo_safety.py install-hooks --target /absolute/project
```

`doctor` invokes installed tools' version commands. `scan` runs installed scanners and may execute project linter configuration. Use it in an authorized, trusted repo. Normal scan/gates do not validate discovered credentials over provider APIs; `scan --verify-secrets` explicitly opts in. It is incompatible with `--offline`.

Offline skips network-dependent built-in audit paths and disables TruffleHog verification. It is not an OS network sandbox: arbitrary installed scanners/plugins can have their own behavior. Git push itself still uses the network. Scanner absence is reported; use `--strict` when missing configured checks must fail. Hooks use this exact local fork and fail closed when it is moved/missing. Reinstall hooks after moving/removing a skill. Existing custom hooks are preserved unless chaining/overwrite is requested.

This source bundle does not publish or invoke the upstream npm/PyPI package. The retained upstream `verify-release` helper audits upstream npm/PyPI packaging; it intentionally rejects this GitHub-only bundle and is not the way to release this repository.

## Intentional full trust in Workflow Herdr

Default launch arguments inherit your installed CLI policy. If your Codex is already full trust, this fork does not secretly downgrade it. For an explicit profile on one exact project root:

```sh
python skills/workflow-herdr/scripts/trust_policy.py --project /absolute/project --full-trust
```

This records the owner decision outside the project and adds full-trust flags to Codex/Devin launches. It grants broad process permissions, **not** permission to publish, deploy, delete data or read/encode secrets for unrelated work. `--auto-confirm-workspace` is separate: add it only when automatic acceptance of that project's trust dialog is intended. It sends Enter once only when Yes is visibly selected and requires the composer afterwards. Ambiguous UI stops for manual action.

To revoke, run the same command with `--revoke`. The default registry is `~/.config/agent-guardrails/workflow-trust.json`; `WORKFLOW_HERDR_TRUST_FILE` selects an owner-controlled alternative. It stores paths/booleans, no credentials. No profile is created by installing the skill. Models remain inventory-checked examples: configure models actually available in your installed CLIs.

## Changes and verification

See [CHANGES.md](CHANGES.md) for before/after and [SECURITY.md](SECURITY.md) for boundaries. Run offline unit/integration fixtures:

```sh
cd skills/ai-repo-safety
PYTHONPATH=src python -m pytest -q tests
cd ../workflow-herdr
python -m unittest discover -s scripts -p 'test_*.py' -v
cd ../repo-intake-guard
python -m unittest discover -s tests -v
```

For Windows set `PYTHONPATH` using your shell's environment syntax. No test requires authenticating a model, running a live Herdr session or installing a scanner. A wheel-artifact test skips when no wheel is built. Real provider egress, live Herdr UI variants and real Windows execution need separate integration checks; fake-runtime tests do not prove those.

## Provenance and license

Derived from Artem Letyushev's MIT-licensed [ai-repo-safety-skill](https://github.com/letya999/ai-repo-safety-skill) at `5530bd29a9a89acfb88b9b9b7703d972a33917e4` and [workflow-herdr](https://github.com/letya999/workflow-herdr) at `7cd03cf2e45d9446a79d6ccd1b839f94c12af1d4`. Both original LICENSE files are preserved. This is an independent modified distribution, not an upstream release. No production credentials, private project context or user configuration is included.

Repo Intake Guard is an original MIT-licensed skill by zilbertov, informed by the [ASSET GhostCommit disclosure](https://asset-group.github.io/disclosures/ghostcommit/). It does not include the attack payload or the user’s video.
