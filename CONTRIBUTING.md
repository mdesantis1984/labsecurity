# Contributing

Changes to LabSecurity use an issue-first, reviewable workflow. Read this guide, the relevant documentation under [`docs/`](docs/README.md), and the approved issue before editing the repository.

## Workflow

1. Create or select an issue that describes one observable outcome.
2. Wait for the maintainer to apply `status:approved`.
3. Create a branch named `type/description` from `develop`.
4. Implement one cohesive work unit with its tests and documentation.
5. Run the focused verification locally and `git diff --check` before pushing.
6. Commit using Conventional Commits.
7. Open a PR linking the approved issue and apply exactly one `type:*` label.
8. Merge only after required checks and maintainer approval.

Use chained PRs when one cohesive change exceeds 1000 changed lines and can be divided into independently reviewable outcomes. Never combine unrelated concerns to fill the budget. Merge each child into `develop` in dependency order before promotion.

## Branch model

- `develop` is the protected integration branch and target for normal work-unit PRs.
- `main` is the protected production branch and accepts reviewed promotions from `develop` or bounded emergency fixes.
- A `develop` to `main` promotion may aggregate work units that were already reviewed individually; do not add new implementation changes to that PR.
- Squash work-unit PRs into `develop`, but merge promotion PRs into `main` with a merge commit so future promotions retain a clean common ancestor.
- Emergency fixes branch from `main`, use `fix/description`, and must be applied back to `develop` after release.
- Only the maintainers listed in [`.github/CODEOWNERS`](.github/CODEOWNERS) have repository write and merge authority. External contributors work through forks and PRs.

## Verification

Every change requires:

```bash
uv run pytest
git diff --check
```

Rule changes additionally require `uv run pytest tests/rules`, which runs the contract checks and, when the `labsecurity/opengrep` image is built, the native `opengrep test`. Shell changes require `shellcheck -x -P SCRIPTDIR` over `bin/` and `scripts/`, and documentation changes require `python3 scripts/check-doc-links.py`. Changes to the pipeline, compose file, or images also need the end-to-end run against a live lab (about 4 minutes):

```bash
uv run pytest -m integration tests/integration
```

## Ground rules

- **No third-party code, binaries, or rule packs in the repository.** Anything third-party is downloaded at build time, pinned by version and digest or checksum, and listed in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) and [`docs/VERSIONS.md`](docs/VERSIONS.md).
- **No absolute host paths, usernames, hostnames, or private-project names** in tracked files. Use repository-relative paths, `$HOME`, and environment variables.
- **No real or realistic secrets**, not even in tests: build fake values at test time.
- Everything published binds to `127.0.0.1`. LabSecurity never sets `risk_accepted` and never modifies a scanned repository.
- Shell scripts must run on macOS's bash 3.2 (no associative arrays, `${var,,}`, `mapfile`, or `readarray`) and pass `shellcheck`.
- Write tests first for behavior changes. Files and documentation are in English; the README pair and `docs/README*.md` are bilingual.

## Adding a rule

Rules live in `rules/opengrep/*.yaml` (gated: they can block a PR) or `rules/optin/` (opt-in). A rule is accepted only with:

1. **A standard reference.** `metadata.cwe` (`"CWE-NNN: Name"`), `metadata.owasp` (OWASP Top 10 2025 category and name), and `metadata.standard` plus `references` pointing at the official page that says the pattern is insecure (OWASP ASVS or Cheat Sheet, CIS benchmark, vendor documentation). Read the live page and quote what it says in the pull request; do not cite from memory.
2. **Fixtures with `ruleid:` and `ok:` annotations** in `tests/rules/` (a positive and a negative case, including the near-miss that the rule must not flag).
3. **Tests.** `uv run pytest tests/rules` checks the contract (id, metadata, annotations) and runs `opengrep test`.
4. **An entry in [`docs/RULES.md`](docs/RULES.md)** with id, severity, and what it catches.

Prefer high precision: a gated rule that cries wolf trains people to ignore the gate. Open a rule request issue before writing a large rule.

## Commits

Use `type(scope): outcome`, for example `feat(rules): flag wildcard CORS origins` or `ci(workflows): pin the scanner image digest`.

## License of contributions

LabSecurity is distributed under the Apache License 2.0. Unless you state otherwise, a contribution you submit is licensed under the same terms (section 5 of the license). A DCO-style sign-off (`git commit -s`, which adds a `Signed-off-by` line) is welcome but optional.

## Review checklist

- [ ] The PR links an approved issue.
- [ ] The PR has exactly one `type:*` label.
- [ ] The branch and commit names follow repository conventions.
- [ ] The change stays within the 1000-line review budget.
- [ ] Verification evidence and runtime limitations are explicit, including any operating system or CPU architecture not tested.
- [ ] No secrets, third-party code, host paths, or generated outputs are included.
