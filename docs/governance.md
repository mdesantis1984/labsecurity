# Repository governance

LabSecurity is public for transparent consumption and review. Repository write and merge authority is limited to the maintainers listed in `.github/CODEOWNERS`; external contributors work through forks and pull requests.

## Protected branches

| Branch | Purpose | Accepted changes |
| --- | --- | --- |
| `develop` | Integration | Approved, verified work-unit PRs |
| `main` | Production | Promotion from `develop` or bounded emergency fixes |

Both branches are meant to require pull requests, passing status checks, resolved conversations, and protection from force pushes or deletion. Direct pushes are prohibited.

## Review authority

`CODEOWNERS` assigns the entire repository to the maintainer, and no other account receives write access. GitHub does not allow a PR author to approve their own PR. While the project has a single maintainer, branch protection requires green checks but does not require a numeric approval that would deadlock maintainer-authored changes.

For an external contribution, only a maintainer can merge it or provide a review with repository authority. If another maintainer is added later, enable one required CODEOWNER approval and retain stale-review dismissal.

## Automated dependency PRs

Dependabot is the only issue-link exception. The PR author must be `dependabot[bot]`, target `develop`, use `type:chore`, and pass every required check. A change above 1000 lines also needs an administrator-applied `size:exception` label and a concrete rationale showing why no valid split exists. Python, npm, Docker, and GitHub Actions updates are separate ecosystems to keep lockfile and digest churn reviewable; related GitHub Actions may remain grouped. Dependabot has no merge authority; the maintainer reviews and merges or rejects every update, and a new image version is accepted only after the lab's tests pass against it and [VERSIONS.md](VERSIONS.md) is updated.

## Delivery evidence

Issue Forms classify documentation, public API, migration, compatibility, and release-note impact before implementation. Human and promotion PRs repeat those classifications in the `Delivery Impact` section and name concrete evidence. The policy check rejects placeholders or missing dimensions; Dependabot remains exempt because GitHub generates its PR body.

## Rule contributions

A rule enters `rules/opengrep/` only with its standard reference, positive and negative fixtures, tests, and an entry in [RULES.md](RULES.md). The rule request form collects those items before implementation; the review checks that the cited page was read, not recalled.

## Promotion rule

A promotion PR from `develop` to `main` contains only commits already reviewed as bounded work units. It may exceed the 1000-line aggregate budget, but it must not introduce new implementation changes. Promotions use merge commits to preserve ancestry between the long-lived branches; work-unit PRs into `develop` use squash merges.

## Repository settings

These are the settings the maintainer applies when the repository is created and verifies after publication.

- Visibility: public.
- Merge strategy: squash for work-unit PRs and merge commits for `develop` promotions; no direct pushes or rebase merges.
- Issues: enabled and required before PR creation.
- Wiki: disabled; versioned documentation lives in this repository.
- Dependabot alerts, security updates, and private vulnerability reporting: enabled.
- Actions: read-only token permissions by default.
