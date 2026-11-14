# Tooling

Python 3.12+ and Git are sufficient for the bundled CLI. Scanners remain separate prerequisites. `install-tools --dry-run` plans; `--yes` applies supported uv/native-manager installs. Opengrep must come from a verified official pinned release, never `@opengrep/cli`. Windows TruffleHog requires manual signed-checksum verification; the tool does not download an unchecked binary. Missing prerequisites leave installation nonzero. No bundled hook resolves an upstream package over the network.
