---
name: labsecurity
description: Install, run and triage the LabSecurity AppSec lab (Opengrep, Gitleaks, Trivy, SonarQube, DefectDojo, .NET analyzers, ZAP). Use before opening any pull request (pre-PR security gate), when asked to scan a repository, run a security review, check vulnerabilities, leaked credentials, SAST, SCA or CVEs, triage or mark a false positive, report security findings, turn confirmed findings into tasks, or install LabSecurity. Triggers - labsecurity, security gate, pre-PR gate, appsec, scan repository, DefectDojo, SonarQube, false positive, vulnerability report, security findings.
---

# LabSecurity

A self-hosted AppSec lab that runs in Docker on this machine. One command scans a repository with several open-source
tools, files the results in DefectDojo and answers with a short summary, a JSON document and an exit code.

## Locate the lab

Commands below are written `labsec ...`. Resolve it once per session, in this order:

1. `command -v labsec` (the user put `bin/labsec` on the `PATH`);
2. `$LABSECURITY_DIR/bin/labsec` if that variable is set;
3. if this skill was installed as a symlink, the lab is two folders above the real path of this skill:
   `readlink -f <this skill folder>` ends in `<lab>/skill/labsecurity`, so the command is `<lab>/bin/labsec`;
4. otherwise ask the user where LabSecurity is cloned. If it is not installed, follow "Install the lab".

`bin/scan` and `bin/labsec` are the same program: `scan <path>` runs one lap; `labsec <subcommand>` queries, triages,
reports and gates. `<project>` is a repository directory (query commands also accept its DefectDojo slug, the directory name).

## Install the lab

Requirements: Docker with the compose plugin (Docker Desktop, OrbStack, Colima or Docker Engine), `git`, `rsync`,
[`uv`](https://docs.astral.sh/uv/). Windows is supported through WSL2 only: run everything inside the WSL distribution
and keep repositories in the WSL filesystem.

```bash
git clone <LabSecurity repository URL> && cd LabSecurity
scripts/init.sh              # credentials and .env; mode 600; prints no values
docker compose up -d --wait  # SonarQube and DefectDojo, bound to 127.0.0.1 only
bin/scan --bootstrap         # API tokens; safe to repeat
bin/scan --doctor            # every check must be ok
```

The first start downloads images and takes a few minutes. DefectDojo is at `http://127.0.0.1:19080`, SonarQube at
`http://127.0.0.1:19000`; the admin passwords are in the config folder (see "Where files go"). Never print them.

## Hard rules

1. **Never accept risk.** No command does it; do not use the DefectDojo UI or API to set `risk_accepted`. Accepting a risk is
   a human decision.
2. A false positive needs a **reason with `file:line`** (`--reason "Api/Repo.cs:42 - value is a compile-time constant"`).
   No reason, no mark.
3. Doubt is not a false positive: use `mark --to-confirm`, report it as "to confirm", and let it keep blocking.
4. Never put exploit payloads, credential values or full descriptions in chat, PRs, task files or commits. Refer to
   findings by DefectDojo id + `file:line`.
5. Never read raw reports (`<data root>/runs/**`) and never print or open the config folder: DefectDojo, through
   `labsec`, is the only source of truth.
6. Never stop, recreate, prune or reconfigure the lab's containers. If the lab is down, follow "Lab down".
7. Never scan a target you are not allowed to test. ZAP only runs against loopback URLs declared in `.appsec.yml`
   (`127.0.0.1`, `localhost`, `::1`); `.appsec.yml` is added to a repository only with the user's approval.

## Workflow A: pre-PR gate (before every PR)

```bash
labsec gate <project> --json
```

It starts the lab if needed, runs the full lap (every required tool must be `ok`) and prints PASS or BLOCKED plus a
PR-body summary (`pr_body`).

| Exit | Meaning | What to do |
| --- | --- | --- |
| 0 | PASS: no open Critical/High that is not a false positive or an accepted risk | paste `pr_body` in the PR description |
| 2 | BLOCKED by findings | triage (Workflow C), fix, run the gate again |
| 3 | BLOCKED by a lab or tool failure (never a pass) | see "Lab down"; report the `problems` list |
| 1 | cannot start (bad path, invalid `.appsec.yml`) | fix the input |

Blocking = every open Critical/High finding of the product that is not a false positive and not an accepted risk,
including findings from earlier runs. A PR with exit 2 or 3 is **BLOCKED**: say so explicitly; never present it as
clean. Medium and Low are reported and turned into tasks but do not block. Only one heavy analysis runs at a time: if the
lap says another analysis is running, wait a minute and retry; never delete the lock.

## Workflow B: a lap without the gate

```bash
scan <project> --json                         # exit 0 ok, 1 usage, 2 blocking findings, 3 lab or tool failure
labsec findings <project> --new --untriaged --json
labsec report <project>
```

`scan --doctor` checks the lab (exit 0 healthy, 3 failing checks).

## Workflow C: triage

For each untriaged Critical/High (`labsec findings <project> --blocking --untriaged --json`), read the code at
`file:line` and decide:

| Verdict | Action |
| --- | --- |
| True positive | `labsec mark <id> --true-positive [--note "..."]`, then a task (Workflow D) |
| False positive | `labsec mark-fp <id> --reason "<file:line> - why it is not exploitable"`; list it in your report so a human can review it (`labsec unmark-fp <id>` reverts) |
| Doubt | `labsec mark <id> --to-confirm`, report it as "to confirm", do not mark it as a false positive |

Judge against the real code, not the tool title: reachability, input source, sanitization and framework protections
decide. Never mark a false positive just to unblock a PR. Findings already classified in DefectDojo are not reviewed again.

## Workflow D: tasks for confirmed true positives

```bash
labsec tasks <project>                                    # dry run: prints the document, writes nothing
labsec tasks <project> --out <project>/odd/tasks/security-findings.md   # explicit opt-in to write (any markdown file works)
labsec tasks <project> --feature-doc <feature doc> --out <file>          # put the tasks in a feature document instead
```

One task per confirmed true positive: DefectDojo id, severity, `file:line`, rule or CWE, proposed fix, a test-first proof
and an Authorization line (check the project's own rules before fixing, for example whether backend changes need approval).
Order: Critical, High, Medium, Low. Re-running is idempotent (keyed by DefectDojo id) and keeps human edits outside the
markers. Write the failing test first, then fix.

## Workflow E: close the cycle

1. After the fix, run `scan <project>` (or the gate) again.
2. `labsec verify-closed <project> <id...>`: every finding must be `mitigated` (exit 0).
3. `labsec tasks <project> --close <id> --commit <sha> --out <task file>` ticks the task; it refuses unless DefectDojo
   shows the finding mitigated.

## Report format

`labsec report <project> [--pr-body]` returns markdown: counts by severity, new Critical/High with `file:line` and a
one-line explanation, what blocks, items to confirm, false positives with reasons and the DefectDojo link. Use `--pr-body`
for PR descriptions (it omits the paths of credential findings). Your final message always states: verdict (PASS or
BLOCKED), blocking count, false positives marked (with reasons), items "to confirm", tasks created and the report link.

## Where files go

Reports are saved automatically outside every repository:

| OS | Data root |
| --- | --- |
| Linux, WSL2 | `${XDG_DATA_HOME:-~/.local/share}/labsecurity` |
| macOS | `~/Library/Application Support/LabSecurity` |
| any | `$LABSEC_HOME` when set |

`labsec report` writes `reports/<repo>-<hash>/<UTC timestamp>/report.json`, `report.md` and `pr-body.md` under the data
root and prints the folder (`--json` adds `saved_to`; `--out DIR` changes it; `--no-save` prints only). Raw tool output
is in `runs/`, backups in `backups/`, credentials in the config folder (Linux `~/.config/labsecurity`, macOS
`<data root>/config`). Never copy any of these into a repository.

## Lab down

Symptoms: exit 3, "lab is not configured", DefectDojo or SonarQube unreachable.

```bash
cd <lab> && docker compose up -d --wait
scan --doctor
```

Only these two commands. If the lab still does not come up, the PR is **BLOCKED**: report the failing check names from
`--doctor`. Do not try to repair containers, volumes or data.

More: `references/commands.md` (every subcommand, schemas, exit codes) and, in the repository, `docs/GATE.md`,
`docs/TRIAGE.md`, `docs/PLATFORMS.md`, `docs/AGENT-INTEGRATION.md`.
