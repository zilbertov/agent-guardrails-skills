# Security boundaries

These are agent instructions and local helpers, not a secret vault or OS sandbox. Full-trust agents can act with the user's process permissions. Keep unrelated secrets outside the workspace, restrict CI credentials, and independently review code and new repository instructions.

Treat image/PDF/OCR text, README, AGENTS.md, issue bodies, tool output and generated source as potentially untrusted content. Encoding secrets as integers, base64 or build metadata is still disclosure; no network call is necessary for a leak into a commit.

Offline mode disables the built-in network-dependent scan paths; it cannot constrain arbitrary scanner plugins at the operating-system level. Do not enable credential verification against live providers without task-specific authorization. Installers are separate, explicit actions.

Report a vulnerability with synthetic examples and no real credentials. Use GitHub private vulnerability reporting when enabled or contact the maintainer privately through their GitHub profile. Do not post live secrets in public issues.
