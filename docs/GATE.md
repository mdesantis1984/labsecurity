# Pre-PR gate

```bash
bin/labsec gate <project-path> [--branch NAME] [--json]
```

Run it before every pull request. It guarantees that the lab is up, runs one full lap and answers PASS or BLOCKED.

1. **Lab**: runs the doctor checks. If any fails it runs `docker compose up -d --wait` (nothing is stopped, recreated or pruned) and checks again. If the lab is still unhealthy the gate ends with exit 3 and never scans.
2. **Lap**: the same pipeline as `bin/scan` (one heavy lock, work copy, import into DefectDojo). The summary is captured, not printed.
3. **Verdict** from the DefectDojo-backed summary.

## Exit codes

| Code | Verdict | Meaning |
| --- | --- | --- |
| 0 | PASS | every required tool is `ok` and no blocking finding is open |
| 1 | BLOCKED | the gate could not start (not a directory, invalid `.appsec.yml`); never a pass |
| 2 | BLOCKED | blocking findings: open Critical/High that are not false positives and not risk-accepted (including earlier runs) |
| 3 | BLOCKED | lab or tool failure: a required tool is `failed`/`skipped`/missing, import failed, counts did not stabilize, the lab did not come up, or another heavy analysis holds the lock |

Failure (3) wins over findings (2): an incomplete analysis is never reported as "only findings". There is no silent pass: a missing
summary, a tool that did not run or a skipped required tool all give 3.

## Required tools

`opengrep`, `gitleaks` (with the branch history), `trivy`, `sonarqube`, the DefectDojo import (`engagement_url` must exist),
`dotnet-analyzers` when the project has C# files, and `zap` only when `.appsec.yml` declares a loopback `zap.target_url`
(then it must be `ok`; without a declared target ZAP is `skipped` and not required).

## Output

Text: a first line `GATE PASS|BLOCKED (reason): <project> @ <branch>`, the problems, then the PR body.
`--json` prints `labsec.gate/v1`:

```json
{
  "schema": "labsec.gate/v1",
  "project": "my-project",
  "branch": "feature/x",
  "verdict": "BLOCKED",
  "reason": "findings",
  "exit_code": 2,
  "problems": [],
  "lab_started": false,
  "summary": {"schema": "labsec.summary/v1", "...": "..."},
  "pr_body": "### Security (LabSecurity)\n\nGate: **BLOCKED** ..."
}
```

`reason` is `null` for PASS, `findings` (2), `lab_or_tool_failure` (3) or `usage` (1). `summary` is the full `labsec.summary/v1` of the lap, or `null` when the lab never came up. `pr_body` is the markdown to paste in the PR: verdict, counts by severity, what blocks (`file:line`, DD id), the DefectDojo link and the tool list. It omits the path and title of credential findings.

## What to do with each result

- **0**: paste `pr_body` into the PR.
- **2**: triage with `labsec findings <project> --blocking --untriaged --json` ([TRIAGE.md](TRIAGE.md)): true positive → `mark --true-positive` + `tasks`; false positive → `mark-fp --reason "<file:line> - why"`; doubt → `mark --to-confirm`. Fix, re-run the gate. The PR stays BLOCKED until it is 0.
- **3**: read `problems`. If the lab is down: `docker compose up -d --wait` from the repo root and `bin/scan --doctor`. If it still fails, the PR is BLOCKED and the failure is reported. If another analysis holds the lock, wait and retry.

## Tests

Unit: `tests/unit/test_gate.py` (verdicts, exit codes, required tools, lab start, ZAP/C# conditions, no sink = unchanged scan output).
Live: `tests/integration/test_gate_live.py` (exit 2 on the vulnerable fixture, exit 0 once every blocking finding has a reasoned false positive, exit 3 with the lock held, exit 1 for a missing directory).
