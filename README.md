# Agent Guardrails Skills

Two security skills for coding agents: a focused repository-safety fork and an original repository intake guard.

| Skill | Use it for | Start here |
| --- | --- | --- |
| AI Repo Safety | Secret checks, SAST, dependency audit and fail-closed Git gates in a trusted working repository | [SKILL.md](skills/ai-repo-safety/SKILL.md) |
| Repo Intake Guard | Review unfamiliar repo instructions and linked media; catch GhostCommit-style encoded secret traps before setup or publication | [SKILL.md](skills/repo-intake-guard/SKILL.md) |

## Install instructions, not dependencies

Copy the **complete selected skill directory** into your agent's supported project/user skill directory. Keep `src`, `scripts`, `assets`, and references together. Nothing installs on clone or import. Avoid keeping upstream and this fork enabled under the same skill name.

Use a locally copied, reviewed full Git commit. Do not fetch `main`, `latest`, an unversioned installer or an upstream PyPI package on each invocation. Review updates separately; a checksum proves fixed bytes, not that those bytes are benign. Python 3.12+ is needed for bundled safety commands.

## Reviewed snapshot installation

This snapshot contains the supply-chain correction. Clone without checking out moving branch content, then select the full reviewed commit:

```sh
git clone --no-checkout https://github.com/zilbertov/agent-guardrails-skills.git agent-guardrails-skills
git -C agent-guardrails-skills checkout --detach 060f5cba18884dbc90d44d7ddd5a684ffc08e34e
```

Copy only the selected complete `skills/ai-repo-safety` or `skills/repo-intake-guard` folder into your trusted skill store. Ordinary invocation uses this local copy; there is no auto-update. Do not put clone, pull, npx or uvx into a per-task hook. A new revision needs a new review. Exact commits prevent a later branch update from changing installed bytes; they do not prove the reviewed code or its installed external tools are harmless.

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

## Workflow Herdr moved

Workflow Herdr now lives in its own public repository: [zilbertov/workflow-herdr](https://github.com/zilbertov/workflow-herdr). Install a reviewed full commit from that repository separately. It is no longer bundled here.

## Changes and verification

See [CHANGES.md](CHANGES.md) for before/after and [SECURITY.md](SECURITY.md) for boundaries. Run offline unit/integration fixtures:

```sh
cd skills/ai-repo-safety
PYTHONPATH=src python -m pytest -q tests
cd ../repo-intake-guard
python -m unittest discover -s tests -v
```

For Windows set `PYTHONPATH` using your shell's environment syntax. No test requires authenticating a model, running a live Herdr session or installing a scanner. A wheel-artifact test skips when no wheel is built. Real provider egress and real Windows execution need separate integration checks; fake-runtime tests do not prove those.

## Provenance and license

AI Repo Safety is derived from Artem Letyushev's MIT-licensed [ai-repo-safety-skill](https://github.com/letya999/ai-repo-safety-skill) at `5530bd29a9a89acfb88b9b9b7703d972a33917e4`. Its original LICENSE is preserved. This is an independent modified distribution, not an upstream release. No production credentials, private project context or user configuration is included.

Repo Intake Guard is an original MIT-licensed skill by zilbertov, informed by the [ASSET GhostCommit disclosure](https://asset-group.github.io/disclosures/ghostcommit/). It does not include the attack payload or the user’s video.

## Tool supply-chain boundary

Routine scan never invokes uvx or installs a missing pip-audit. Missing tools are reported; strict mode is nonzero when coverage is missing. Dependency auditing retains `--disable-pip` and does not retry by resolving/building target dependencies. `install-missing` is now a prerequisite plan only, including legacy `--yes`.

For Python tools, install an owner-reviewed transitive hash lock into a dedicated tool environment, using installed pip with `--require-hashes --only-binary=:all:`. Native tools need reviewed release artifacts with verified hashes/signatures. CI templates require that tool lock; GitLab requires an owner-reviewed digest-pinned image and a vendored copy of this fork. External advisory databases may still be contacted by online audits; offline mode skips them. This is different from downloading new executable code.
