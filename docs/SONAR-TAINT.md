# SonarQube Community Build and taint analysis

Verified on **2026-11-17** against the lab's SonarQube Community Build `26.11.0.134175` (from `/api/server/version`).

Owner question: "si SonarQube Community Build incluye taint analysis. Creo que es de las ediciones pagas; confirmalo con la
documentación oficial y una prueba real. Community además analiza solo la rama principal."

## Conclusion

Both statements are **confirmed**:

1. **No taint analysis (injection vulnerability detection) in Community Build.** SonarQube reported nothing for three
   request-to-sink flows that cross two methods each, the server has no taint rules for C#, and the rules that do exist are
   purely syntactic.
2. **Only the main branch.** Analyzing with `sonar.branch.name` is refused by the scanner.

## Evidence

### Official documentation (logged earlier as L5)

Feature comparison table, <https://docs.sonarsource.com/sonarqube-community-build/feature-comparison-table>:
"Security analysis / Injection vulnerabilities detection: Not available" in the Community column (included in the paid
editions) and "Code analysis / Branch analysis: Main branch only".

### Real test: `tests/integration/test_sonar_taint.py`

The test builds a throw-away git repository with an ASP.NET Core project (`Npgsql`), runs one full lap with `bin/scan`, then
queries the SonarQube API. The code has the same three flows twice, once as minimal-API lambdas and once as an MVC controller:

| Flow | Source | Through | Sink |
| --- | --- | --- | --- |
| SQL | `request.Query["name"]` / action parameter | `Lookup` -> `Find` (two methods) | `new NpgsqlCommand($"... '{value}'")` / `IDbCommand.CommandText = "..." + value` |
| OS command | `request.Query["tool"]` / action parameter | `RunTool` -> `Launch` | `Process.Start(value)` |
| File path | `request.Query["path"]` / action parameter | `ReadFile` -> `Read` | `File.ReadAllText("/data/" + value)` |

Observed API output (counts and rule keys only):

| Query | Result |
| --- | --- |
| `GET /api/issues/search?componentKeys=<key>&types=VULNERABILITY` | `total: 1`, rule `csharpsquid:S2077` |
| `GET /api/issues/search?componentKeys=<key>` (all types) | `total: 5`: `csharpsquid:S2077`, `csharpsquid:S3903`, `csharpsquid:S6966`, `external_roslyn:CA1050`, `external_roslyn:CA1859` |
| `GET /api/hotspots/search?project=<key>` | `total: 0` |
| `GET /api/rules/repositories?language=cs` | one repository: `csharpsquid` |
| `GET /api/rules/search?repositories=roslyn.sonaranalyzer.security.cs` | `total: 0` |
| `GET /api/rules/search?q=S3649` | `total: 0` |
| `GET /api/rules/search?repositories=csharpsquid` | `total: 456` (of which 36 of type VULNERABILITY, none taint) |
| `GET /api/rules/show?key=csharpsquid:<K>` for `S2076`, `S2083`, `S2631`, `S3649`, `S5131`, `S5144`, `S5145`, `S5146`, `S6096`, `S6287`, `S6350`, `S6399` | HTTP 404 for every key (none exists) |
| `GET /api/rules/show?key=csharpsquid:S2077` | HTTP 200, type `VULNERABILITY`, "SQL queries should not be dynamically formatted" |

Reading of the table:

- The only vulnerability, `S2077`, is a **syntactic** rule (it looks at how the SQL string is formatted at the call, not at
  where the data comes from). It fired once, so at most one of the two SQL flows was reported.
- The OS-command flow (`Process.Start`) and the file-path flow (`File.ReadAllText`) produced **no** Sonar finding at all.
- The security taint rules that Sonar documents for C# (SQL injection S3649, OS command injection S2076, path injection S2083,
  XSS S5131, and the rest of the list above) are **absent** from the Community server, and the security analyzer repository
  `roslyn.sonaranalyzer.security.cs` has zero rules.
- The `external_roslyn:CA*` issues come from the .NET analyzers that LabSecurity imports into SonarQube; they are not Sonar's own
  analysis.

### Branch analysis

Re-running the scanner on the same project with `-Dsonar.branch.name=feature-taint-probe` (sonar-scanner container) exits
with code 3 and:

```text
ERROR Validation of project failed:
  o To use the property "sonar.branch.name" and analyze branches, Developer Edition or above is required.
```

`GET /api/project_branches/list` afterwards shows only `main`. LabSecurity therefore labels runs by branch in DefectDojo
(one engagement per run and branch), while the SonarQube project always reflects the latest run.

## What compensates in LabSecurity

| Gap in Sonar Community | Covered by | Observed on the same code |
| --- | --- | --- |
| Taint from request input to SQL | Opengrep `labsec.csharp.sql-raw-*` rules (custom, `--taint-intrafile`, see [RULES.md](RULES.md)) | `labsec.csharp.sql-raw-built-text` fired in `Program.cs` and `ToolsController.cs` (the `$"..."` and `+` built text at the sink) |
| Taint to SQL, OS command and file path | .NET SDK analyzers `CA3001`-`CA3012` (run by the dotnet scanner image) | `CA3001` (SQL), `CA3003` (file path) and `CA3006` (OS command) fired in `ToolsController.cs`; `CA2100` fired in `Program.cs` |
| Branch analysis | DefectDojo engagement per run and branch | n/a |

Limits seen in this test, to keep expectations honest:

- The `CA3xxx` analyzers found the three controller flows but **not** the same flows written as minimal-API lambdas
  (`app.MapGet("/x", (HttpRequest request) => ...)`); only `CA2100` fired there. Minimal-API-only services have a taint blind spot
  in the .NET analyzers.
- The custom Opengrep rules cover SQL (and Angular/TS XSS). They do not cover `Process.Start` or file-path sinks; those rely on
  `CA3006`/`CA3003`. The Opengrep taint rule `labsec.csharp.sql-raw-tainted-input`
  deliberately skips text built in place (reported once by `sql-raw-built-text`), so it was not the one that fired here.
- Opengrep and the CA analyzers are intraprocedural-plus-same-file/assembly analyses: they do not follow data across projects or
  through the database.

## Reproduce

```bash
# needs the lab up and bootstrapped; ~2 min; removes its SonarQube project and DefectDojo product afterwards
LABSEC_SONAR_TAINT_OUT=/tmp/sonar-taint.json uv run pytest -m integration tests/integration/test_sonar_taint.py
```

The test asserts the conclusions above: if a future SonarQube upgrade adds taint rules or branch analysis, it fails and this
document must be revisited.
