# Automation

| Workflow | Trigger | Contract |
| --- | --- | --- |
| `ci.yml` | Pull requests and `main`/`develop` pushes | Runs the unit tests, the rule contracts and Opengrep fixtures, the relative-link check of the documentation, ShellCheck, the Gitleaks history scan, the PR policy tests, and `git diff --check` |
| `pr-policy.yml` | Pull request metadata changes | Enforces branch naming, approved issue linkage, one `type:*` label, and the 1000-line budget |

CI never starts the lab: SonarQube, DefectDojo, and the scanners need several GB of RAM and a local Docker daemon, so the end-to-end tests (`uv run pytest -m integration tests/integration`) run on a developer machine before a pull request.

External actions are pinned to commit SHAs. Dependabot updates those pins through reviewable pull requests. Workflows use read-only permissions.

Repository protection requires CI and policy checks on both `main` and `develop`. Promotion PRs from `develop` to `main` may exceed 1000 aggregate lines only because each included work unit was already reviewed under that limit.
