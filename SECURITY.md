# Security Policy

Security reports for LabSecurity must use GitHub private vulnerability reporting. Do not disclose vulnerabilities, credentials, personal data, or working exploits in public issues or pull requests.

## Supported versions

| Version | Supported |
| --- | --- |
| Latest commit on `main` | Yes |
| Earlier commits and forks | No |

LabSecurity runs on the user's machine and publishes no hosted service, package, or image. It binds every port to `127.0.0.1` and is not meant to be reachable from a network.

## Reporting

Open the repository `Security` tab and select `Report a vulnerability`. Include the affected file or command, impact, minimal reproduction, and a safe contact method. Do not include real credentials or someone else's data. If private reporting is unavailable, contact the maintainer through an existing private GitHub channel rather than opening a public issue.

## Scope

- Code in this repository: the `labsec` CLI, scripts, compose file, Dockerfiles, rules, and the agent skill.
- Behavior that could expose the lab beyond the local machine, leak credentials or findings, modify a scanned repository, write outside the documented data folders, or let an agent accept a risk.

Vulnerabilities in the upstream tools (SonarQube, DefectDojo, ZAP, and the rest) belong to their own projects.

## Security model

- Every published port binds to `127.0.0.1` only, and ZAP scans loopback addresses only.
- Credentials are generated locally by `scripts/init.sh` into a private config folder (mode 600) and are never printed.
- Reports and raw tool output describe vulnerabilities: they are stored outside the repositories with restrictive permissions. Do not commit or share them. Backups contain the same data.
- Downloaded images, binaries, and rule packs are pinned by digest, commit, or checksum.

## Handling

The maintainer will acknowledge the report, validate its impact, coordinate remediation, and publish an advisory when appropriate. Compromised secrets are revoked and removed from history; a source deletion alone is not considered remediation.
