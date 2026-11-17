# LabSecurity documentation

[Español](README.md) · [English home](../README.en.md)

This page organizes documentation by need and makes translation status visible. Spanish is the repository's default entrance; the technical reference stays in English while the following documentation work units progress.

## Choose a path

| Need | Start here | Current language |
| --- | --- | --- |
| Understand the lab and install it | [Main README](../README.en.md) | Spanish and English |
| Install and use the skill from an agent | [README prompts](../README.en.md#try-it-in-minutes) and [agent integration](AGENT-INTEGRATION.md) | Spanish and English; the integration guide is English |
| Run commands and read the JSON | [CLI reference](CLI.md) | English; Spanish pending |
| Apply the pre-PR gate | [Gate](GATE.md) | English; Spanish pending |
| Triage findings and generate tasks | [Triage](TRIAGE.md) | English; Spanish pending |
| Learn the rules, sources, and licenses | [Rules](RULES.md) and [third-party notices](../THIRD_PARTY_NOTICES.md) | English; Spanish pending |
| Pick an operating system and data folder | [Platforms](PLATFORMS.md) | English; Spanish pending |
| Back up and restore the databases | [Backups](BACKUP.md) | English; Spanish pending |
| Review pinned versions and images | [Versions](VERSIONS.md) | English; Spanish pending |
| Understand SonarQube taint analysis | [SonarQube and taint](SONAR-TAINT.md) | English; Spanish pending |
| Understand decisions and boundaries | [Architecture](architecture.md) | English; Spanish pending |
| Contribute and review changes | [Contributing](../CONTRIBUTING.md) and [governance](governance.md) | English; Spanish pending |
| Report a vulnerability | [Security policy](../SECURITY.md) | English; Spanish pending |
| Read the standards research | [Research notes](research/standards-catalog.md) | English and Spanish |

## Documentation contract

- Capabilities are documented only when executable evidence exists: a test or a real verification.
- Each platform's status separates what was tested from what was designed; macOS and WSL2 are not presented as tested.
- Commands must run from the stated path.
- Versions come from `compose.yaml`, the Dockerfiles, and [Versions](VERSIONS.md); prose does not invent status.
- Spanish and English documents retain the same structure and verifiable claims.

## Program status

| Work unit | Status |
| --- | --- |
| Spanish-first product entrance with an English pair | Available |
| CLI, gate, triage, rules, platforms, and backup reference | Available, in English |
| Repository architecture and governance | Available, in English |
| Automated relative-link validation in CI | Available |
| Spanish translation of the technical reference | Pending |
| Verified runs on macOS and WSL2 | Pending |
