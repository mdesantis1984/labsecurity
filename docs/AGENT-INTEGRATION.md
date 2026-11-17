# Agent integration

Two steps make any coding agent (Claude Code, Codex, Gemini CLI, Cursor, Aider, ...) use LabSecurity the same way:

1. install the **skill** so the agent knows the commands (see "Use from an agent" in the [README](../README.md));
2. paste the **snippet** below into the instructions file the agent reads on every session (`AGENTS.md`, `CLAUDE.md`,
   `GEMINI.md`, `.cursor/rules`, ...), either user-wide or per repository.

Replace `<LABSECURITY_DIR>` with the folder where you cloned LabSecurity, or put `bin/labsec` on your `PATH`
(`ln -s <LABSECURITY_DIR>/bin/labsec /usr/local/bin/labsec`, any folder on your `PATH` works) and write `labsec`.

## Snippet to paste

```markdown
## Security gate before every pull request (LabSecurity)

Before opening or updating a pull request, run the local LabSecurity gate on the project. It reads the project and
writes nothing to it.

- Command: `<LABSECURITY_DIR>/bin/labsec gate <project-path> --json`. If the lab is down it starts it
  (`docker compose up -d --wait`) and runs one full lap: Opengrep, Gitleaks over the branch history, Trivy, SonarQube,
  the .NET analyzers when there is C#, ZAP only when `.appsec.yml` declares a loopback URL, and the import into DefectDojo.
- Blocking rule: every open Critical or High finding in DefectDojo blocks, unless it is a false positive or an accepted
  risk. Exit codes: 0 PASS, 2 BLOCKED by findings, 3 BLOCKED by a lab or tool failure, 1 could not start. Never treat 2
  or 3 as a pass: the PR stays BLOCKED and you say so.
- With findings: check each one against the real code. True positive: `labsec mark <id> --true-positive` and a task with
  `labsec tasks <project> --out <task file>`. False positive: `labsec mark-fp <id> --reason "<file:line> - why it is not
  exploitable"`. Doubt: `labsec mark <id> --to-confirm`, report it as "to confirm" and do not mark it as a false
  positive. After the fix, run the gate again, check with `labsec verify-closed`, and close the task with
  `labsec tasks --close <id> --commit <sha>`.
- Never accept a risk (that is a human decision), never mark a false positive without `file:line` or just to unblock a
  PR, and never read raw reports: query only `labsec findings --json` and `labsec report`.
- If the lab does not start, the PR is BLOCKED: report the failing checks of `<LABSECURITY_DIR>/bin/scan --doctor`. Do
  not stop, recreate or clean the lab's containers.
- Put the gate's `pr_body` summary (or `labsec report <project> --pr-body`) in the PR description, and in your final
  report: verdict, number of blocking findings, false positives marked with their reasons, findings "to confirm" and
  tasks created. Never include exploit details or credential values.
- Read the `labsecurity` skill once per session before using it.
```

Reports from `labsec report` are saved outside the repositories, see [PLATFORMS.md](PLATFORMS.md).
