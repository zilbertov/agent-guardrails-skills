# Why this check exists

Primary disclosure: [ASSET GhostCommit](https://asset-group.github.io/disclosures/ghostcommit/) (June 2026).

The demonstrated chain points agent instructions to a local image, disguises a request for private environment data as build provenance, and has the agent embed encoded bytes into ordinary source. Later publication leaks the data without a dedicated network-exfiltration step. A repo-supplied verifier reinforces the pretext. Reported controlled experiments are evidence for those model/harness configurations only, not universal attack rates or a claim about current models.

The guard checks authority, source-to-output flow, linked media and the staged artifact. Numeric/base64 detection is deliberately narrow: ordinary image palettes should not be reported as secret exfiltration without a sensitive-data signal. It cannot prove intent or decode every obfuscation; manual analysis of linked images remains essential.
