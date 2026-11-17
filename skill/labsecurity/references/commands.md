# LabSecurity command reference (for agents)

Paths below are relative to the LabSecurity clone (see "Locate the lab" in `SKILL.md`). Every command accepts `--json` and prints a versioned schema.
Errors are `{"schema": "labsec.error/v1", "error": "...", "exit_code": N}` with `--json`, plain text on stderr otherwise.

| Command | Purpose | Schema | Exit |
| --- | --- | --- | --- |
| `bin/scan <path> [--json] [--branch X]` | full lap | `labsec.summary/v1` | 0 ok, 1 usage, 2 blocking, 3 lab/tool failure |
| `bin/labsec gate <project> [--branch X] [--json]` | pre-PR gate | `labsec.gate/v1` | 0 PASS, 1 cannot start, 2 findings, 3 lab/tool failure |
| `bin/labsec findings <project> [--new\|--open\|--blocking] [--severity critical,high] [--untriaged] [--limit N]` | query DefectDojo | `labsec.findings/v1` | 0 |
| `bin/labsec report <project> [--run latest] [--pr-body] [--out DIR] [--no-save]` | markdown report, saved as `report.json`, `report.md`, `pr-body.md` under `<data root>/reports/<repo>-<hash>/<UTC timestamp>/` (path printed on stderr, `saved_to` in JSON) | `labsec.report/v1` (`markdown` field) | 0 |
| `bin/labsec mark-fp <id> --reason "<file:line> - why"` | false positive (false_p, inactive, note, tag `labsec-fp`) | `labsec.mark/v1` | 0, 1 invalid reason |
| `bin/labsec unmark-fp <id>` | revert a LabSecurity FP mark | `labsec.mark/v1` | 0 |
| `bin/labsec mark <id> --true-positive [--note T]` | tag `labsec-triaged-tp` + note | `labsec.mark/v1` | 0 |
| `bin/labsec mark <id> --to-confirm` | tag `labsec-to-confirm`, no status change | `labsec.mark/v1` | 0 |
| `bin/labsec tasks <project> [--out F] [--feature-doc F] [--dry-run]` | ODD tasks (dry run unless `--out`/`--feature-doc`) | `labsec.tasks/v1` | 0 |
| `bin/labsec tasks <project> --close <id> --commit <sha> --out F` | tick a task once mitigated | `labsec.tasks/v1` | 0, 2 not mitigated |
| `bin/labsec verify-closed <project> <id...>` | are these findings mitigated? | `labsec.verify/v1` | 0 all mitigated, 2 otherwise |
| `bin/scan --doctor [--json]` | lab health | `labsec.doctor/v1` | 0, 3 |

Triage state in `findings`: `untriaged`, `false-positive`, `true-positive` (tag `labsec-triaged-tp`), `to-confirm` (tag `labsec-to-confirm`), `risk-accepted` (set by a human reviewer, read only).
"Already classified" = false positive, risk accepted, or carrying one of the two LabSecurity tags. `--untriaged` hides those.
Exit codes: 1 usage/invalid input (including unknown product), 2 gate-style negative answer, 3 lab or DefectDojo failure.
