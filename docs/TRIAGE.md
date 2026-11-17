# Triage, reports and ODD tasks

All commands read the **DefectDojo API only** (never the raw reports under `<data root>/runs/` (`~/.local/share/labsecurity/runs/` on Linux)), print compact text
or `--json` with a versioned schema, and never output exploit details, finding descriptions or credential values. Titles
are passed through the redaction filter and cut to 200 characters. Use them through `bin/labsec` (a symlink to `bin/scan`).

`<project>` is a project directory or its DefectDojo slug (the directory name, or `name:` from `.appsec.yml`).

## What counts as classified

A finding is *classified* when it is a false positive, is risk-accepted, or carries a LabSecurity tag. `--untriaged` hides them.

| State (`triage` field) | Source |
| --- | --- |
| `risk-accepted` | `risk_accepted` in DefectDojo; **human decision, read only** |
| `false-positive` | `false_p` (set by `mark-fp` or by a person in the UI) |
| `true-positive` | tag `labsec-triaged-tp` (set by `mark --true-positive`) |
| `to-confirm` | tag `labsec-to-confirm` (set by `mark --to-confirm`) |
| `untriaged` | none of the above |

Blocking (assumption A1): every open (active, not duplicate) Critical/High finding in the product that is not a false positive and not risk-accepted.

## Commands

```bash
labsec findings <project> [--new|--open|--blocking] [--severity critical,high] [--limit N] [--untriaged] [--run latest] [--json]
labsec report   <project> [--run latest] [--pr-body] [--out DIR] [--no-save] [--json]
labsec mark-fp  <dd-id> --reason "<file:line> - why" [--json]
labsec unmark-fp <dd-id> [--json]
labsec mark     <dd-id> (--true-positive [--note T] | --to-confirm) [--json]
labsec tasks    <project> [--out FILE | --feature-doc FILE] [--dry-run] [--json]
labsec tasks    <project> --close <dd-id> --commit <sha> --out FILE [--dry-run]
labsec verify-closed <project> <dd-id...> [--json]
```

- `findings`: `--open` (default) is every active finding of the product; `--new` is the findings first seen in the chosen run; `--blocking` is the gate set. Default `--limit` 50; the output says how many more exist.
- `report`: markdown with counts by severity, new Critical/High (`file:line`, one-line explanation, DD link), what blocks, items to confirm, false positives with their reasons, and the DefectDojo engagement link. `--pr-body` is the PR description variant: it omits the path of credential findings (it only counts them). Every `report` run also saves `report.json`, `report.md` and `pr-body.md` under `<data root>/reports/<repo>-<hash>/<UTC timestamp>/` and prints that path (see [PLATFORMS.md](PLATFORMS.md)); `--out DIR` changes the folder, `--no-save` disables saving.
- `mark-fp`: the reason must contain a `file:line` and an explanation (10 to 500 characters in total). It adds a note with the reason, sets `false_p=true`, `active=false` and the tag `labsec-fp`. `unmark-fp` reverts only marks made by LabSecurity (tag `labsec-fp`) and re-activates the finding.
- `mark --true-positive` adds the tag and a note; `--to-confirm` adds only the tag (status unchanged, so the finding keeps blocking).
- **No command sets `risk_accepted` or calls a risk-acceptance endpoint.** `DojoClient` refuses any write whose path contains `risk_accept` or whose payload has a `risk_accept*` key, and `update_finding` only accepts `false_p`, `active`, `verified` and `tags`. `tests/unit/test_no_risk_acceptance.py` asserts the runtime guard and, with an AST scan, that the sources never write those fields.

DefectDojo behaviour observed on the live lab: deactivating a finding as a false positive also flags it `is_mitigated`, and `PATCH active=true` clears the flag. So `verify-closed` reports `false-positive` before looking at `is_mitigated`, and `unmark-fp` always re-activates.

## Triage workflow for agents

1. True positive: `mark --true-positive`, then `tasks`.
2. False positive: `mark-fp --reason "<file:line> - why"`; the report lists every false positive with its reason.
3. Doubt: `mark --to-confirm`; report it as "a confirmar"; do not mark it as FP.

## ODD tasks

`tasks <project>` prints the task document (dry run). It writes only with an explicit `--out FILE` or `--feature-doc FILE`, and never with `--dry-run`.
The path read for the dry run is `<project>/odd/tasks/security-findings.md` when `<project>` is a directory.

Each confirmed true positive (active, not duplicate, tagged `labsec-triaged-tp`) becomes one block:

```markdown
<!-- labsec:task id=193 sev=High -->
- [ ] SEC-193 - High - sql raw built text - SQL injection - `Api/Program.cs:13`
  - DefectDojo finding: #193 <http://127.0.0.1:19080/finding/193>
  - Severity: High (blocks the PR)
  - Location: `Api/Program.cs:13` (opengrep)
  - Rule / CWE: rule `...`, CWE-89 (SQL injection)
  - Proposed fix: ...
  - Test-first: first write a test that fails and reproduces the problem, then apply the fix ...
  - Authorization: check project rules before fixing (e.g. backend changes may need maintainer approval).
  - Close the cycle: ...
<!-- /labsec:task id=193 -->
```

- Ordered Critical, High, Medium, Low (then by id).
- Idempotent, keyed by DD id: re-running adds only the missing tasks. Existing blocks and everything outside the `labsec:tasks:begin/end` markers are untouched (a ticked task stays ticked). In an ODD feature document the block is inserted before `## Log`.
- Proposed fixes come from a per-category table in `labsec/knowledge.py` (CWE, rule id, tool and title pick the category): SQL injection, XSS, leaked credentials (rotate and purge), dependency CVEs (upgrade to the Trivy fixed version), misconfiguration, eval/code injection, with a generic fallback.

## Closing the cycle

1. Fix, then re-run `bin/scan <project>`.
2. `verify-closed <project> <id...>` exits 0 only when every finding is `mitigated` (states: `mitigated`, `open`, `false-positive`, `risk-accepted`, `not-found`).
3. `tasks <project> --close <id> --commit <sha> --out FILE` ticks the task (`- [x]` plus a `Done: fix commit ...` line). It refuses with exit 2 unless DefectDojo shows the finding mitigated.

## Schemas

| Schema | Command | Key fields |
| --- | --- | --- |
| `labsec.findings/v1` | `findings` | `project`, `filter{view,severity,untriaged,limit}`, `total`, `returned`, `findings[]{id,severity,title,file,line,cwe,rule,tool,status{active,false_p,risk_accepted,mitigated,duplicate},triage,url}` |
| `labsec.report/v1` | `report` | `project`, `branch`, `run{engagement_id,run_id,url}`, `tools`, `blocked`, `counts`, `blocking[]`, `new_critical_high[]`, `to_confirm[]`, `false_positives[]` (with `reason`), `markdown` |
| `labsec.mark/v1` | `mark-fp`, `unmark-fp`, `mark` | `action`, `changed`, `finding`, `reason` (mark-fp) |
| `labsec.tasks/v1` | `tasks` | `target`, `mode` (`dry-run`/`written`), `added[]`, `kept[]`, `true_positives`, `changed`, `content`; with `--close`: `closed`, `already_closed`, `commit` |
| `labsec.verify/v1` | `verify-closed` | `project`, `all_mitigated`, `results[]{id,state,file,line,severity}` |
| `labsec.error/v1` | any failure with `--json` | `error`, `exit_code` |

Exit codes of every subcommand: 0 ok, 1 usage or invalid input (unknown product or finding, bad reason, missing `--commit`), 2 negative answer (`verify-closed` not all mitigated, `--close` refused), 3 lab or DefectDojo failure.
