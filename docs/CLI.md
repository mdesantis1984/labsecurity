# CLI reference

```text
bin/scan <project-path> [--json] [--branch NAME]
bin/scan --doctor [--json]
bin/scan --bootstrap
bin/labsec <subcommand> ...      # same program (symlink): gate, findings, report, mark-fp, unmark-fp, mark, tasks, verify-closed
```

## Subcommands

```text
bin/labsec gate <project> [--branch X] [--json]                      pre-PR gate        labsec.gate/v1     (docs/GATE.md)
bin/labsec findings <project> [--new|--open|--blocking] [--severity critical,high]
                              [--limit N] [--untriaged] [--run latest] [--json]          labsec.findings/v1 (docs/TRIAGE.md)
bin/labsec report <project> [--run latest] [--pr-body] [--out DIR] [--no-save] [--json]  labsec.report/v1
bin/labsec mark-fp <dd-id> --reason "<file:line> - why" [--json]                         labsec.mark/v1
bin/labsec unmark-fp <dd-id> [--json]                                                    labsec.mark/v1
bin/labsec mark <dd-id> (--true-positive [--note T] | --to-confirm) [--json]             labsec.mark/v1
bin/labsec tasks <project> [--out F | --feature-doc F] [--dry-run] [--json]              labsec.tasks/v1
bin/labsec tasks <project> --close <dd-id> --commit <sha> --out F                        labsec.tasks/v1
bin/labsec verify-closed <project> <dd-id...> [--json]                                   labsec.verify/v1
```

Query and triage commands read the DefectDojo API only. Failures with `--json` print `{"schema": "labsec.error/v1", "error": "...", "exit_code": N}`.
Exit codes: `gate` as below (0 PASS, 1 cannot start, 2 findings, 3 lab/tool failure); `findings`, `report`, `mark*`, `tasks`: 0 ok,
1 usage or invalid input, 3 lab or DefectDojo failure; `verify-closed` and `tasks --close`: 2 when a finding is not mitigated.
Nothing in LabSecurity sets `risk_accepted`: accepting a risk is a human decision.

## Exit codes

| Code | `scan` | `--doctor` | `--bootstrap` |
| --- | --- | --- | --- |
| 0 | completed, no blocking findings | all checks OK | done |
| 1 | usage error or invalid `.appsec.yml` | - | - |
| 2 | completed with blocking findings | - | - |
| 3 | lab or tool failure (treat as BLOCKED) | a check failed | failed |

A finding is **blocking** when it is open (active, not a duplicate) anywhere in the project's DefectDojo product, has
severity Critical or High, and is neither a false positive nor risk-accepted. The gate looks at everything still open, not
only at what the current run introduced, so a second run over unchanged code keeps exiting with 2.

## `labsec.summary/v1` (`scan --json`)

```json
{
  "schema": "labsec.summary/v1",
  "project": "my-project",
  "branch": "main",
  "run_id": "20261117T153324Z",
  "engagement_url": "http://127.0.0.1:19080/engagement/11",
  "tools": [
    {"name": "opengrep", "status": "ok", "findings": 2},
    {"name": "zap", "status": "skipped", "findings": 0, "reason": "no zap target declared in .appsec.yml"}
  ],
  "counts": {
    "new": 12,
    "open": 12,
    "closed": 0,
    "blocking": {"critical": 0, "high": 8, "medium": 0, "low": 0, "info": 0}
  },
  "blocking_findings": [
    {"id": 110, "severity": "High", "title": "...", "file": "web/src/app/app.component.ts", "line": 8, "cwe": 79, "tool": "opengrep"}
  ],
  "errors": []
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `schema` | string | always `labsec.summary/v1`; breaking changes bump the version |
| `project`, `branch` | string | project slug and branch label |
| `run_id` | string | UTC timestamp `YYYYMMDDTHHMMSSZ`; names the run folder |
| `engagement_url` | string or null | null when nothing was imported |
| `tools[].name` | string | `opengrep`, `gitleaks`, `trivy`, `sonarqube`, `dotnet-analyzers`, `zap` |
| `tools[].status` | string | `ok`, `failed` or `skipped` |
| `tools[].findings` | integer | findings in the imported report |
| `tools[].reason` | string, optional | present for `failed` and `skipped` |
| `counts.new` | integer | active, non-duplicate findings first seen in this run's engagement |
| `counts.open` | integer | open findings in the whole product |
| `counts.closed` | integer | findings closed (mitigated) by this run because they are gone |
| `counts.blocking` | object | open blocking findings by severity |
| `blocking_findings[]` | array | `id`, `severity`, `title`, `file`, `line` (nullable), `cwe` (nullable), `tool` |
| `errors` | array of strings | lab or tool failures; any entry or a `failed` tool makes the exit code 3 |

No credential value ever appears in the output: Gitleaks runs with `--redact`, and tokens are passed to the tools by
environment variable only.

## `labsec.doctor/v1` (`scan --doctor --json`)

```json
{"schema": "labsec.doctor/v1", "ok": true, "checks": [{"name": "sonarqube:status", "status": "ok", "detail": "/api/system/status is UP"}]}
```

`status` is `ok`, `warn` (for example a scanner image that will be built on first use) or `fail`. The checks cover container
state and health, `dd-initializer` exit code 0, SonarQube status UP, DefectDojo API access with the stored token, SonarQube
token validity, config-file modes (700/600) and that published ports are bound to 127.0.0.1 only.

## Environment and data locations

One data root per user; the defaults per OS, the folder layout and `LABSEC_HOME` are in [PLATFORMS.md](PLATFORMS.md).
`LABSEC_HOME` moves everything (config, data, cache, state) under one folder; `LABSEC_CONFIG_DIR`, `LABSEC_DATA_DIR`,
`LABSEC_CACHE_DIR` and `LABSEC_STATE_DIR` relocate one part each and win over `LABSEC_HOME`.

`labsec report` prints the report as before **and** saves `report.json`, `report.md` and `pr-body.md` (mode 600) under
`<data root>/reports/<repo>-<hash>/<UTC timestamp>/`, printing `labsec: report saved to <dir>` on stderr (`--json` adds
`saved_to`). `--out DIR` saves there instead and is refused (exit 1) inside the scanned repository or LabSecurity's own
repository; `--no-save` prints only.

## `.appsec.yml` (optional, in the scanned repository)

```yaml
name: my-project                 # display name; the slug (directory name) stays the key
exclude: ["**/generated/**", "!.agents/**"]   # extra globs on top of the defaults; "!<default>" scans a default again
rules: [security/rules]          # extra Opengrep rule files or folders, relative to the project
zap:                             # only loopback targets (127.0.0.1, localhost, ::1) are allowed
  target_url: http://127.0.0.1:5000
  test_user: qa-user             # never write a password here
```

Without the file the defaults apply (see "What gets scanned"): every static tool, no ZAP. Unknown keys, password-like keys, non-loopback ZAP targets
and rule paths outside the project are rejected (exit 1). Add this file to a repository only with the approval of its
maintainers.

## What gets scanned

Every tool analyzes a disposable work copy, never the project. The copy holds exactly the files git would consider part of
the project:

- **In a git repository**: tracked files plus untracked files that are not ignored (`git ls-files -co --exclude-standard`).
  What the repository's own `.gitignore` hides is never copied: linked worktrees under `.worktrees/`, local SDKs such as
  `.toolchain/`, package caches, build output. Untracked nested repositories and submodule checkouts are skipped too.
- **Outside git**: every file except the built-in directories (`.git`, `node_modules`, `bin`, `obj`, `dist`, `.angular`).
- **Gitleaks** is unchanged: it scans the history of the branch (`git` mode) or, outside git, the work copy.

On top of that, files are left out in three layers; each one is counted under its own reason in the run summary:

| Reason | What it covers |
| --- | --- |
| `gitignore` | paths ignored by the repository's `.gitignore` (an ignored directory counts once) |
| `nested-repo` | untracked nested git repositories and submodule checkouts (each counts once) |
| `builtin-dir` | `.git`, `node_modules`, `bin`, `obj`, `dist`, `.angular` |
| `default-exclude` | `.agents/**` (vendored agent skills), `**/*.min.js`, `**/*.min.mjs`, `**/node_modules/**` |
| `appsec-exclude` | the globs of `.appsec.yml` `exclude:` |
| `long-line` | source files with a line longer than 5000 bytes (minified or vendored bundles, for example a bundled `.mjs`) |

`exclude:` extends the defaults. To scan a default again, list it with a leading `!` (`exclude: ["!.agents/**"]`); a `!`
entry that is not one of the defaults is rejected (exit 1). Tests and fixtures stay in scope for every tool: they are not
a default exclude, and Gitleaks does not allowlist them as a whole. A deliberately fake value in a fixture is allowlisted
by file or by regex in LabSecurity's own `config/gitleaks.toml`, which a scanned project cannot change. The long-line
check only looks at source files (the extensions LabSecurity detects); data files such as lockfiles are never skipped.

Trivy also skips any `.cache` and `.toolchain` directory (`--skip-dirs`), so the `*.deps.json` files of a NuGet cache or a
local SDK never produce dependency findings even when such a directory is tracked.

The summary (`--json`: key `scope`; text: the `scope:` line) says how many files were scanned, how many were excluded per
reason and which files the long-line check skipped (at most 20 listed):

```json
"scope": {"files": 1204, "excluded": {"default-exclude": 31, "gitignore": 9, "long-line": 1}, "long_line_files": ["public/bundle.mjs"]}
```

Counts are files, except for directories that are pruned without being opened (ignored directories, nested repositories and,
outside git, the built-in directories), which count once.

## Report JSON: overlapping lists

`report.json` lists a finding once per list. `blocking` is every open Critical/High finding that is neither a false
positive nor an accepted risk; `new_critical_high` is the Critical/High findings new in the selected run. On a first lap
both lists hold the same findings: that is the same data seen two ways, not a duplicate. The markdown report and the PR body
print each finding once.
