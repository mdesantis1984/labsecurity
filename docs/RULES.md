# Rules: sources, licenses and destinations

Everything LabSecurity scans with comes from one of the sources below. This page is the single inventory: what each source
is, which version or commit is pinned, its license, the languages it covers, how many rules it brings, and where its
findings go. The last sections explain the noise exclusions and the sources that were looked at and **not** used.

Verification date for every pin: **2026-11-17**. Exact digests and checksums are in `docs/VERSIONS.md`, `compose.yaml` and
the Dockerfiles under `docker/`.

## What is downloaded and what is shipped

The repository contains **no third-party rule pack, rule text or binary**. Everything third-party is downloaded when an image
is built, pinned by commit, version and checksum, and lives only inside the resulting image. The repository itself ships:

| Shipped in this repository | What it is |
| --- | --- |
| `rules/opengrep/*.yaml`, `rules/optin/*.yaml`, `labsec/standards.py`, `tests/rules/*`, `tests/rules-optin/*` | LabSecurity's own rules (gated and opt-in) and their fixtures |
| `config/gitleaks.toml` | LabSecurity's own Gitleaks rules (it only *extends* the upstream default ruleset by reference) |
| `docker/dotnet/labsec.globalconfig`, `labsec*.targets` | our own severity settings for the .NET analyzers (rule ids and severities only) |
| `docker/eslint/eslint.config.mjs`, `package.json`, `package-lock.json` | our own ESLint config and the dependency lock (names, versions, integrity hashes; no code) |
| `docker/*/Dockerfile`, `docker/opengrep/*.sh` | the build recipes that download and verify the third-party material |

| Downloaded at image build (never stored in the repo) | Pinned by |
| --- | --- |
| Opengrep binary, `opengrep/opengrep-rules`, GitLab `sast-rules`, Trail of Bits `semgrep-rules` | release SHA-256 (binary), git commit (rules; the Dockerfile fails if `git rev-parse HEAD` differs) |
| Roslyn analyzer NuGet packages (Meziantou, Roslynator, SecurityCodeScan) | version and SHA-256 of each `.nupkg` |
| ESLint and its plugins | `package-lock.json` (`npm ci --ignore-scripts`, integrity hashes) on a digest-pinned Node image |
| ZAP add-ons `pscanrulesBeta`, `ascanrulesBeta` | version and SHA-256 of each `.zap` file |
| Gitleaks, Trivy, ZAP, .NET SDK, SonarQube | image digest |
| Trivy vulnerability and misconfiguration databases | downloaded by Trivy at run time into the local cache (not pinned: they are data feeds) |

The license text of every vendored pack is copied into the image (`/opt/labsec/licenses/`) next to the rules, and the rule
files keep their original headers. The image records what it contains in `/opt/labsec/rules/PACKS` (pack and commit) and
`/opt/labsec/rules/EXCLUDED` (rules removed because they do not parse).

## Destination: what feeds the gate

The design rule is simple: **everything security-relevant goes to DefectDojo** (that is what feeds the merge gate);
**pure quality and style rules go to SonarQube only** and never to DefectDojo.

* SonarQube runs every rule of every language (profile `LabSecurity`, see below). Only its *security* issues and
  hotspots are exported to DefectDojo; bugs, code smells and every `external_*` issue stay in SonarQube
  (`labsec/sonar.py`, `is_security_issue`).
* .NET: one SARIF with the security analyzers goes to DefectDojo (`labsec/reports.py`, `merge_sarif`, filtered to the
  `Security` category plus the `SCS` rules). A second pass with `AnalysisMode=All`, Meziantou and Roslynator reaches
  SonarQube as external issues (the SonarScanner for .NET imports the Roslyn issues of that build as `external_roslyn:*` issues).
* TypeScript/JavaScript/Angular: ESLint writes one JSON; `security/*` and `no-unsanitized/*` rules go to DefectDojo
  (`ESLint Scan` parser), every rule goes to SonarQube as a Generic Issue Format external report.

## Rule sources

Counts are rule ids found in the pinned artifact (rules, not files). "DD" is DefectDojo, "Sonar" is SonarQube.

| Source | Version / commit | License | Languages | Rules | Destination |
| --- | --- | --- | --- | --- | --- |
| LabSecurity custom Opengrep rules | this repository | project license | C#, TypeScript/Angular | 8 | DD |
| `opengrep/opengrep-rules` (community rules, `security/` dirs only) | `f1d2b562b414783763fd02a6ed2736eaed622efa` | LGPL-2.1 with the Commons Clause License Condition (the repository is a fork of `semgrep/semgrep-rules`; it states its terms in its own `LICENSE`). Internal, self-hosted use only: nothing is sold or offered as a service | C#, TS, JS, Python, Go, Java, Kotlin, PHP, Ruby, Dockerfile | 843 | DD |
| GitLab `sast-rules` | `83144bd2ec7d3200cda96347fa923f81c8ad8413` | repository MIT (GitLab Inc.); `rules/lgpl` LGPL-3.0; `rules/lgpl-cc` LGPL plus Commons Clause (internal use). `rules/gitlab` (GitLab EE license) is **not used** | C#, Go, Java, JS, Kotlin, PHP, Python, Ruby | 425 (C# 21, Go 27, Java 98, JS 95, Kotlin 58, PHP 9, Python 77, Ruby 40) | DD |
| Trail of Bits `semgrep-rules` | `31390b3a99c04c81522d1b37c8d1900aa2dd4094` | **AGPL-3.0**. Internal use only: it is run by the lab, never redistributed, never offered over a network to third parties. Do not ship an image that contains it | Go, Java, Kotlin, JS, Python, Ruby, Terraform | 79 (Go 18, Java 2, JS 9, Kotlin 2, Python 24, Ruby 15, Terraform 9) | DD |
| Opengrep engine | `v2.0.0` | LGPL-2.1 | - | - | - |
| .NET SDK analyzers (`CA*`) | .NET SDK 10.0.404 | MIT | C#, VB | 100 explicit severities in `labsec.globalconfig`; all `CA` rules with `AnalysisMode=All` | security-category rules to DD; the rest to Sonar |
| SecurityCodeScan.VS2019 | `5.6.7` | LGPL-3.0-or-later (project unmaintained since 2022; kept because it loads and fires on .NET 10) | C#, VB | about 35 ids (`SCS0000`-`SCS0034`) | DD |
| Meziantou.Analyzer | `3.0.341` | MIT | C# | about 242 ids; the security-category ones are `MA0009` and `MA0039` | those two to DD, the rest to Sonar |
| Roslynator.Analyzers | `5.0.1` | Apache-2.0 | C# | about 284 ids | Sonar |
| ESLint | `10.15.0` (`@eslint/js` 10.0.1, `globals` 17.14.0) | MIT | TS, JS | recommended set | Sonar |
| typescript-eslint | `8.73.0` (TypeScript `6.0.3`, Apache-2.0) | MIT | TS | `strict` set, non type-aware | Sonar |
| angular-eslint | `22.7.0` | MIT | Angular TS and templates (including inline templates) | recommended + template accessibility | Sonar |
| eslint-plugin-security | `4.2.1` | Apache-2.0 | JS, TS | 14 active (`detect-object-injection` is off, see below) | DD and Sonar |
| eslint-plugin-no-unsanitized | `4.1.5` | MPL-2.0 | JS, TS | 2 (`method`, `property`) | DD and Sonar |
| Gitleaks (default ruleset) | `v8.30.1` | MIT | any text | upstream default set, loaded with `useDefault = true` | DD |
| LabSecurity custom Gitleaks rules (`config/gitleaks.toml`) | this repository | project license | ASP.NET/Npgsql connection strings, `appsettings*.json`, Keycloak realm exports and settings | 5 | DD |
| Trivy | `0.76.2` | Apache-2.0 | dependencies (lockfiles) and IaC (Dockerfile, compose, Kubernetes, Terraform) | `--scanners vuln,misconfig` | DD |
| ZAP stable | `2.17.0` | Apache-2.0 | web targets on loopback | release rules bundled in the image | DD |
| ZAP `pscanrulesBeta` | `v50` (SHA-256 in `docker/zap/Dockerfile`) | Apache-2.0 (the `zap-extensions` repository license) | web targets | passive scan: 62 rules before, 68 after (baseline run on a throw-away target) | DD |
| ZAP `ascanrulesBeta` | `v67` (SHA-256 in `docker/zap/Dockerfile`) | Apache-2.0 (the `zap-extensions` repository license) | web targets | full scan: 114 rule rows before, 143 after (same target) | DD |
| SonarQube Community Build | `26.11.0.134175` | LGPL-3.0 | 20 languages and file types | every rule active, table below | Sonar; security issues also to DD |

`pscanrulesAlpha` and `ascanrulesAlpha` are **not** installed: alpha means experimental by ZAP's own definition, and the
stock `zap-baseline.py` / `zap-full-scan.py` scripts would otherwise download unpinned add-ons on every run, so LabSecurity
passes `-z -silent` (`labsec/tools.py`, `zap_command`) and only the add-ons baked into `labsecurity/zap` load.

Rule totals of the Opengrep image: **843 before, 1347 after** (843 community + 425 GitLab + 79 Trail of Bits). One rule
fails to parse with Opengrep 2.0.0 and is removed at build time (see `EXCLUDED`):
`csharp/x-gitlab-sast-rules/mit/crypto/rule-CertificateValidationDisabled.yml`.

### How a pack reaches a scan

The image lays rules out per language: `/opt/labsec/rules/<language>/...`, with the third-party packs in `x-gitlab-sast-rules/`
and `x-trailofbits-semgrep-rules/` subdirectories. `bin/scan` detects the languages of the project and loads only those
directories (`RULE_DIRS` in `labsec/tools.py`; Terraform files load `terraform`). `docker/opengrep/prune-invalid.sh` runs at
build time: it scans a throw-away target per language directory with the pinned Opengrep, removes every rule file reported as
a rule parse error and repeats until clean, so a broken upstream rule can never abort a scan.

Runtime impact on a mixed 676-file tree: **2.8 s before, 3.8 s after, 0 errors**. A whole `bin/scan` of the test fixture
(all tools, including a DefectDojo import): **26-28 s before, 29-30 s after**.

## SonarQube: every rule active

SonarQube's built-in `Sonar way` profiles activate only part of the rules. `bin/scan --bootstrap` creates a `LabSecurity`
profile per language, activates **all** rules and makes it the default; `bin/scan --doctor` fails when a profile is missing,
is not the default or has fewer active than available rules (`labsec/profiles.py`).

| Language | Active / total now | Before (`Sonar way`) |
| --- | --- | --- |
| C# (`cs`) | 456 / 456 | 121 / 456 |
| TypeScript (`ts`) | 552 / 552 | 199 / 553 |
| JavaScript (`js`) | 533 / 533 | 200 / 534 |
| Web (`web`) | 96 / 96 | 36 / 106 |
| CSS | 52 / 52 | 30 / 52 |
| Docker | 28 / 28 | 18 / 28 |
| Python (`py`) | 452 / 452 | 232 / 453 |
| Go | 37 / 37 | 6 / 37 |
| Java | 776 / 776 | 263 / not recorded |
| Kotlin | 145 / 145 | 54 / not recorded |
| Jupyter (`ipynb`) | 452 / 452 | 230 / not recorded |
| PHP | 245 / 245 | not recorded |
| VB.NET | 197 / 197 | not recorded |
| Flex | 74 / 74 | not recorded |
| Terraform | 54 / 54 | not recorded |
| XML | 37 / 37 | not recorded |
| Azure Resource Manager | 38 / 38 | not recorded |
| CloudFormation | 28 / 28 | not recorded |
| Kubernetes | 26 / 26 | not recorded |
| Secrets | 30 / 30 | not recorded |
| Text | 3 / 3 | not recorded |

Totals can move by one or two rules when SonarQube updates a plugin; `--bootstrap` simply activates what is new.

## Noise exclusions

| Where | Excluded | Why |
| --- | --- | --- |
| ESLint | `security/detect-object-injection` is off | it flags every `obj[key]` access (thousands of findings on ordinary code) and cannot tell a real prototype or property injection from a lookup; the Angular and `no-unsanitized` rules cover the real sinks |
| ESLint | `--no-inline-config`, `reportUnusedDisableDirectives` off | the project's `eslint-disable` comments and config must not silence the lab; the lab uses only its own config |
| ESLint | type-aware `typescript-eslint` rules | they need the project's `tsconfig` and a full type check of the repository |
| ESLint | `eslint-plugin-sonarjs` is not installed | LGPL-3.0-only and redundant: SonarQube already runs the same analyzer with every rule active |
| .NET | `MA0037`, `MA0039`, `MA0049` forced to `warning` | Meziantou ships them as `error`, which would fail the build; the lab only reports |
| .NET | non-security rules are filtered out of the DefectDojo SARIF | they stay in SonarQube; the gate sees only security findings |
| Gitleaks | placeholder values (`changeme`, `password`, `<...>`, `${...}`, `{{...}}`, masked `***`) | the custom rules would otherwise flag templates and documentation |
| Gitleaks | lockfiles and `*.min.js` (global allowlist) | high-entropy hashes that are not secrets |
| Opengrep packs | `rules/gitlab` of GitLab `sast-rules` | GitLab EE license; not vendored |
| Opengrep packs | rules that do not parse (1 today) | removed at build time by `prune-invalid.sh`; recorded in `EXCLUDED` |
| Scan scope | files ignored by the repository's `.gitignore`, `.agents/**`, `**/*.min.js`, `**/*.min.mjs`, `**/node_modules/**`, nested repositories, source files with a line longer than 5000 bytes | linked worktrees, local SDKs, package caches, vendored agent skills and minified bundles are not the project's code; what is excluded, per reason, is in every run summary (see [CLI.md](CLI.md#what-gets-scanned)) |
| Trivy | `.cache` and `.toolchain` directories (`--skip-dirs`) | `*.deps.json` files of a package cache or a local SDK carry third-party CVEs, not the project's |
| Trivy | `secrets` and `license` scanners | secrets stay with Gitleaks (it also reads history); license findings are not security rules |

## Looked at and not used

| Candidate | Reason |
| --- | --- |
| `semgrep/semgrep-rules` (and the Semgrep registry packs) | Semgrep Rules License (source-available, restricts use and redistribution); the rules the community fork `opengrep-rules` carries are the allowed path |
| GitLab `sast-rules`, `rules/gitlab` | GitLab EE license |
| Puma Scan | unmaintained project; superseded by the .NET SDK security analyzers and SecurityCodeScan |
| SonarQube taint analysis rules | paid editions only (see `docs/SONAR-TAINT.md`); the custom Opengrep taint rules compensate |
| `eslint-plugin-sonarjs` | LGPL-3.0-only; duplicates the SonarQube analyzer |
| `security/detect-object-injection` | see noise exclusions |
| ZAP alpha rule add-ons | experimental; unstable output on a gate |
| SecurityCodeScan.VS2019 *upgrade* | no newer release exists; kept at `5.6.7` because it works on .NET 10 |
| Trivy license scanning | not a security signal; revisit when a license policy exists |

## Third-party license summary

Only licenses that allow what the lab does (run locally, internal use) are used. The lab is not a hosted service and does
not redistribute any of the packs. The copyleft and "no selling" terms that matter if the lab is ever published or shared:

* **AGPL-3.0**: Trail of Bits `semgrep-rules`. Do not publish an image that contains it; the repository does not contain it.
* **LGPL-3.0**: SecurityCodeScan, GitLab `rules/lgpl*`. Used as unmodified analyzers or rules; dynamic use, no linking.
* **Commons Clause License Condition**: `opengrep-rules` and GitLab `rules/lgpl-cc`. Forbids selling the software or a service
  whose value derives from it. Do not offer the lab (or a scan service built on it) for a fee.
* **MPL-2.0**: `eslint-plugin-no-unsanitized`, used unmodified.
* **MIT / Apache-2.0 / BSD / ISC**: everything else.

---

# Custom Opengrep rules


LabSecurity ships its own Opengrep rules in `rules/opengrep/*.yaml`, on top of the community rules baked into the scanner image. `bin/scan`
mounts that directory read-only as an extra `--config` whenever it contains YAML files, so every project gets them
without any per-project setup. The scan runs with `--taint-intrafile`, so the taint rules follow data across the
methods of one file.

Owner policy they encode (verbatim):

- "C#/EF Core/Npgsql: prohibido FromSqlRaw/ExecuteSqlRaw/NpgsqlCommand con texto concatenado o interpolado; usar
  FromSqlInterpolated o NpgsqlParameter."
- "Angular/TS: marcar innerHTML, bypassSecurityTrust*, document.write y eval."

## Rule list

All ids start with `labsec.`. Every rule carries `metadata.category: security`, `cwe`, `owasp` (OWASP Top 10 **2025** category and name, https://owasp.org/Top10/2025/) and `confidence`.

| Rule id | File | Mode | Severity | CWE | Catches |
| --- | --- | --- | --- | --- | --- |
| `labsec.csharp.sql-raw-built-text` | `csharp-sql-injection.yaml` | pattern | ERROR | 89 | `FromSqlRaw`, `ExecuteSqlRaw`, `ExecuteSqlRawAsync`, `SqlQueryRaw<T>`, `new NpgsqlCommand/SqlCommand/SqliteCommand/MySqlCommand(...)` and `.CommandText =` whose text is a concatenation (`+`), an interpolated string (`$"..."`) or `string.Format(...)` written in place. Not reported: text whose interpolation holes are all `const` values, `nameof(...)` or literals, or a concatenation of `const` values |
| `labsec.csharp.sql-raw-built-text-variable` | `csharp-sql-taint.yaml` | taint | ERROR | 89 | the same sinks when the text was built first (concatenation, interpolation, `string.Format`, `new StringBuilder`) and reaches the sink through a local variable or `sb.ToString()` |
| `labsec.csharp.sql-raw-tainted-input` | `csharp-sql-taint.yaml` | taint (intrafile) | ERROR | 89 | request input (`Request.Query/Form/Headers/Cookies/RouteValues[...]`) or a `string` method / minimal-API lambda parameter reaching the text of those sinks, across the methods of one file, for example `Handler -> Lookup -> Run -> FromSqlRaw(Compose(value))`. Parsing with `int.Parse`, `long.Parse`, `decimal.Parse`, `Guid.Parse` or `Convert.ToInt32/64` sanitizes. Text whose interpolation holes are all `const`, `nameof(...)` or literals is not a source |
| `labsec.angular.inner-html-binding` | `angular-ts-xss.yaml` | regex | WARNING | 79 | `[innerHTML]` and `[outerHTML]` bindings in `.html` templates and in inline templates inside `.ts` files |
| `labsec.typescript.dom-html-assignment` | `angular-ts-xss.yaml` | pattern | ERROR | 79 | `el.innerHTML = x`, `+=`, `el.outerHTML = x`, `el.insertAdjacentHTML(pos, x)` (assigning `''` is allowed). Not reported: a variable created in the same scope with `document.createElement('template')`: a detached `<template>` is inert |
| `labsec.angular.bypass-security-trust` | `angular-ts-xss.yaml` | pattern | ERROR | 79 | `bypassSecurityTrustHtml`, `...Script`, `...Style`, `...Url`, `...ResourceUrl` |
| `labsec.typescript.document-write` | `angular-ts-xss.yaml` | pattern | ERROR | 79 | `document.write(...)`, `document.writeln(...)` (also through `window.`) |
| `labsec.typescript.dynamic-code-execution` | `angular-ts-xss.yaml` | pattern | ERROR | 95 | `eval(...)`, `new Function(...)`, `Function(...)`, `setTimeout/setInterval` with a string, template literal or concatenated first argument |

What is deliberately **not** flagged: constant SQL (`FromSqlRaw("SELECT 1")`, `"a" + "b"`), `FromSqlInterpolated`,
`ExecuteSqlInterpolated`, `SqlQuery<T>` with a `FormattableString`, `FromSqlRaw("... {0}", value)` (EF Core parameterizes
format arguments), a constant `CommandText` with `Parameters.AddWithValue` or `NpgsqlParameter`, `innerText`,
`textContent`, `innerHTML = ''`, `setTimeout(() => ..., ms)`.

### Safe alternatives

| Instead of | Use |
| --- | --- |
| `ctx.Users.FromSqlRaw($"... {name}")` | `ctx.Users.FromSqlInterpolated($"... {name}")` (the holes become parameters) |
| `ctx.Database.ExecuteSqlRaw("... " + name)` | `ctx.Database.ExecuteSqlInterpolated($"... {name}")`, or `ExecuteSqlRaw("... @name", new NpgsqlParameter("name", name))` |
| `ctx.Database.SqlQueryRaw<T>($"... {name}")` | `ctx.Database.SqlQuery<T>($"... {name}")` |
| `new NpgsqlCommand($"... {name}", conn)` | constant text `"... @name"` plus `cmd.Parameters.AddWithValue("name", name)` / `new NpgsqlParameter` |
| `el.innerHTML = value` | `el.textContent = value`, an Angular template, or sanitize with a vetted library (DOMPurify) first |
| `sanitizer.bypassSecurityTrustHtml(value)` | drop it and let Angular sanitize; keep it only for constants and document why |
| `document.write(x)` | DOM API (`createElement`, `textContent`) |
| `eval(x)`, `new Function(x)`, `setTimeout("code", ms)` | a function reference, `JSON.parse` for data, a lookup table |

## Standards-derived rules

These rules come from official standards (OWASP ASVS 5.0.0, OWASP Cheat Sheets, CWE, Microsoft Learn, angular.dev, npm and
OpenSSF docs, Cloudflare docs). Every one carries `metadata.standard` (the exact requirement or page), `cwe`, `owasp`,
`confidence` and `references` (https only). Every Opengrep rule has a `ruleid` and an `ok` fixture (`tests/rules/`,
`tests/rules-optin/`) run by `uv run pytest tests/rules`. The Python checks have unit tests in `tests/unit/test_standards.py`.
References were opened and read on 2026-11-17; a standard that could not be verified did not become a rule (see "Not shipped").

### Gated rules (`rules/opengrep` and `labsec/standards.py`)

`ERROR` blocks the gate (High). `WARNING` is reported and becomes a task (Medium). Loaded by every scan.

| Rule id | Standard reference | CWE | Severity (DefectDojo) | Engine | In the gate |
| --- | --- | --- | --- | --- | --- |
| `labsec.config.npgsql-ssl-mode-weak` | OWASP ASVS 5.0.0 V12.3.1; Npgsql docs, Security and encryption, Encryption (SSL/TLS) | 319 | WARNING (Medium) | Opengrep regex | yes |
| `labsec.config.npgsql-trust-server-certificate` | OWASP ASVS 5.0.0 V12.3.2; Npgsql docs, connection string parameters (Trust Server Certificate) | 295 | WARNING (Medium) | Opengrep regex | yes |
| `labsec.csharp.jwt-validate-issuer-disabled` | OWASP ASVS 5.0.0 V9.1.3; Microsoft Learn, TokenValidationParameters.ValidateIssuer | 345 | ERROR (High) | Opengrep pattern | yes |
| `labsec.csharp.jwt-validate-audience-disabled` | OWASP ASVS 5.0.0 V9.2.3; Microsoft Learn, TokenValidationParameters.ValidateAudience | 345 | ERROR (High) | Opengrep pattern | yes |
| `labsec.csharp.jwt-signature-validation-disabled` | OWASP ASVS 5.0.0 V9.1.1; Microsoft Learn, TokenValidationParameters.RequireSignedTokens | 347 | ERROR (High) | Opengrep pattern | yes |
| `labsec.csharp.jwt-require-https-metadata-disabled` | OWASP ASVS 5.0.0 V12.3.1; Microsoft Learn, JwtBearerOptions.RequireHttpsMetadata | 319 | WARNING (Medium) | Opengrep pattern | yes |
| `labsec.csharp.cors-reflect-any-origin-with-credentials` | OWASP ASVS 5.0.0 V3.4.2; Microsoft Learn, ASP.NET Core CORS, credentials in cross-origin requests | 942 | ERROR (High) | Opengrep pattern | yes |
| `labsec.csharp.cookie-secure-disabled` | OWASP ASVS 5.0.0 V3.3.1; OWASP ASVS V3.3.1 (Secure attribute) | 614 | WARNING (Medium) | Opengrep pattern | yes |
| `labsec.csharp.cookie-httponly-disabled` | OWASP ASVS 5.0.0 V3.3.4; OWASP ASVS V3.3.4 (HttpOnly attribute) | 1004 | WARNING (Medium) | Opengrep pattern | yes |
| `labsec.csharp.tls-certificate-validation-bypass` | OWASP ASVS 5.0.0 V12.3.2; Microsoft Learn, HttpClient guidelines; OWASP ASVS V12.3.2 | 295 | ERROR (High) | Opengrep pattern | yes |
| `labsec.csharp.developer-exception-page-unguarded` | OWASP ASVS 5.0.0 V13.4.2, V16.5.1; Microsoft Learn, Developer Exception Page | 209 | WARNING (Medium) | Opengrep pattern | yes |
| `labsec.csharp.log-injection` | OWASP ASVS 5.0.0 V16.4.1; OWASP Logging Cheat Sheet, Log Injection | 117 | WARNING (Medium) | Opengrep taint | yes |
| `labsec.csharp.unsafe-reflection-tainted-type` | OWASP ASVS 5.0.0 V1.3.2; OWASP ASVS V1.3.2 (dynamic code execution features) | 470 | ERROR (High) | Opengrep taint | yes |
| `labsec.bicep.output-exposes-secret` | OWASP ASVS 5.0.0 V13.3.1; Microsoft Learn, Bicep linter rule outputs-should-not-contain-secrets | 200 | ERROR (High) | Opengrep regex | yes |
| `labsec.bicep.secure-parameter-default` | OWASP ASVS 5.0.0 V13.3.1; Microsoft Learn, Bicep linter rule secure-parameter-default | 798 | ERROR (High) | Opengrep regex | yes |
| `labsec.cloudflare.tunnel-no-tls-verify` | OWASP ASVS 5.0.0 V12.3.4; Cloudflare docs, cloudflared origin parameters (noTLSVerify) | 295 | WARNING (Medium) | Opengrep regex | yes |
| `labsec.bicep.admin-username-literal` | Microsoft Learn, Bicep linter rule adminusername-should-not-be-literal ("Don't use a literal value or an expression that evaluates to a literal value") | 798 | WARNING (Medium) | Opengrep regex | yes |
| `labsec.cloudflare.tunnel-ingress-no-catch-all` | Cloudflare docs, cloudflared configuration file ("Configuration files that contain ingress rules must always include a catch-all rule that concludes the file") | 1188 | WARNING (Medium) | Opengrep regex | yes |
| `labsec.cloudflare.wrangler-vars-literal-secret` | Cloudflare Workers configuration docs (do not use plaintext environment variables for sensitive information; use encrypted values or store bindings). `vars` entries named like KEY, TOKEN, PASSWORD, SECRET or CREDENTIAL with a non-empty literal; names containing PUBLIC are skipped | 798 (also 312) | ERROR (High) | Opengrep regex | yes |
| `labsec.cloudflare.dev-vars-committed` | Cloudflare Workers configuration docs (local variables files belong in .gitignore). A tracked `.dev.vars` or `.dev.vars.<env>` file; `.example`, `.sample`, `.template`, `.dist` and `.tpl` templates are ignored | 798 (also 312) | ERROR (High) | Python (`labsec/standards.py`; needs `git ls-files`, so it ignores files that .gitignore keeps out) | yes |
| `labsec.sshd.permit-root-login` | Azure Linux security baseline, PermitRootLogin = no (CIS Distribution Independent Linux L1 Server 5.2.10) | 250 | WARNING (Medium) | Opengrep regex (`sshd_config`, `sshd_config.d/*.conf`) | yes |
| `labsec.sshd.permit-empty-passwords` | Azure Linux security baseline, PermitEmptyPasswords = no (CIS L1 Server 5.2.11) | 258 | ERROR (High) | Opengrep regex (`sshd_config`, `sshd_config.d/*.conf`) | yes |
| `labsec.angular.xsrf-protection-disabled` | OWASP ASVS 5.0.0 V3.5.1; angular.dev security guide, Disabling XSRF protection | 352 | WARNING (Medium) | Opengrep pattern | yes |
| `labsec.angular.jsonp-enabled` | Angular source, packages/common/http/src/module.ts (JSONP deprecation note); no ASVS requirement names JSONP | 79 | WARNING (Medium) | Opengrep pattern | yes |
| `labsec.typescript.browser-storage-sensitive-data` | OWASP ASVS 5.0.0 V14.3.3; OWASP HTML5 Security Cheat Sheet, Local Storage | 922 | WARNING (Medium) | Opengrep pattern | yes |
| `labsec.typescript.jwt-verify-ignore-expiration` | OWASP ASVS 5.0.0 V9.2.1; OWASP ASVS V9.2.1 (nbf and exp must be validated) | 324 | ERROR (High) | Opengrep pattern | yes |
| `labsec.npm.no-lockfile` | OpenSSF Package Manager Best Practices, npm, Use a Lockfile; OWASP NPM Security Cheat Sheet, Enforce the lockfile | 1357 | WARNING (Medium) | Python (`labsec/standards.py`) | yes |
| `labsec.npm.lockfile-insecure-source` | OpenSSF Package Manager Best Practices, npm, package-lock.json; OWASP ASVS 5.0.0 V15.2.4 | 829 | WARNING (Medium) | Python (`labsec/standards.py`) | yes |
| `labsec.npm.lockfile-no-integrity` | OpenSSF Package Manager Best Practices, npm, package-lock.json (integrity field) | 494 | WARNING (Medium) | Python (`labsec/standards.py`) | yes |
| `labsec.npm.npmrc-strict-ssl-disabled` | npm docs, config: strict-ssl; OWASP ASVS 5.0.0 V12.3.2 | 295 | WARNING (Medium) | Python (`labsec/standards.py`) | yes |
| `labsec.npm.npmrc-http-registry` | npm docs, config: registry; OWASP ASVS 5.0.0 V12.3.1 | 319 | WARNING (Medium) | Python (`labsec/standards.py`) | yes |
| `labsec.npm.npmrc-literal-auth-token` | OpenSSF Package Manager Best Practices, npm (do not commit ~/.npmrc credentials) | 798 | ERROR (High) | Python (`labsec/standards.py`) | yes |
| `labsec.angular.allowed-hosts-wildcard` | angular.dev security guide, Configuring allowed hosts (a bare * 'presents a security risk') | 918 | WARNING (Medium) | Python (`labsec/standards.py`) | yes |

### Opt-in rules (outside the gate)

Severity `INFO` (Low in DefectDojo): often legitimate, so they never block. They are **not** loaded by default.

- Opengrep rules live in `rules/optin/`; `bin/scan` does not mount that directory. A project enables them by copying the
  wanted file into its own repository and listing it under `rules:` in `.appsec.yml`; or set `LABSEC_OPTIN=1` in the scan
  environment to load the whole directory.
- The Python opt-in checks run only with `LABSEC_OPTIN=1`.

| Rule id | Standard reference | CWE | Severity (DefectDojo) | Engine | In the gate |
| --- | --- | --- | --- | --- | --- |
| `labsec.csharp.antiforgery-disabled` | OWASP ASVS 5.0.0 V3.5.1; Microsoft Learn, ASP.NET Core anti-request-forgery (opting an endpoint out) | 352 | INFO (Low) | Opengrep pattern | no |
| `labsec.csharp.cors-allow-any-origin` | OWASP ASVS 5.0.0 V3.4.2; OWASP ASVS V3.4.2 (CORS Access-Control-Allow-Origin fixed value) | 942 | INFO (Low) | Opengrep pattern | no |
| `labsec.bicep.secret-parameter-not-secure` | OWASP ASVS 5.0.0 V13.3.1; Microsoft Learn, Bicep linter rule secure-secrets-in-params | 532 | INFO (Low) | Opengrep regex | no |
| `labsec.npm.npmrc-ignore-scripts-absent` | OWASP NPM Security Cheat Sheet, Minimize attack surfaces by ignoring run-scripts | 829 | INFO (Low) | Python (`labsec/standards.py`) | no |
| `labsec.npm.npmrc-min-release-age-absent` | npm docs, config: min-release-age (npm v11.10.0 and later) | 829 | INFO (Low) | Python (`labsec/standards.py`) | no |
| `labsec.angular.autocsp-unsafe-eval` | angular.dev workspace configuration, Security configuration (autoCsp unsafeEval) | 79 | INFO (Low) | Python (`labsec/standards.py`) | no |
| `labsec.angular.production-source-map` | angular.dev workspace configuration, build options (sourceMap, hidden, sourcesContent) | 540 | INFO (Low) | Python (`labsec/standards.py`) | no |

### Coverage: what is covered by another source (not duplicated)

| Area | Covered by | Notes |
| --- | --- | --- |
| BinaryFormatter and unsafe deserialization, XXE, weak hash/cipher/RNG, open redirect, SQL injection, hardcoded JWT key, `alg=none` | Opengrep community rules, GitLab `sast-rules` (MIT) and Trail of Bits packs, .NET SDK analyzers, SecurityCodeScan | the vendored packs already have these C# and JS rules |
| Cookie `HttpOnly` / `Secure` flags on the framework default, CSRF without antiforgery, node `NODE_TLS_REJECT_UNAUTHORIZED` | the same packs | own rules only cover explicit `CookieOptions` / `SecurePolicy` settings |
| `ValidateLifetime = false` | the same packs (`jwt-tokenvalidationparameters-no-expiry-validation`) | the own `jwt-verify-ignore-expiration` covers the Node `jsonwebtoken` API |
| Dockerfile running as root, privileged containers | Trivy misconfig, Opengrep `dockerfile` pack | |
| Terraform, CloudFormation, Azure ARM and Bicep resource settings, Kubernetes and GKE manifests, AWS Security Hub CSPM and Azure/Google resource controls | Trivy misconfig (`trivy-checks`, MIT: aws, azure, google, kubernetes, docker providers), SonarQube IaC profiles | not rewritten: a second copy of the same checks would only add duplicate findings |
| Secrets in files and history | Gitleaks with `config/gitleaks.toml` | |
| ESLint security and Angular template rules | ESLint image | |

### Not statically detectable: ZAP or manual review

These checks need a running application or a human, so no rule was written (the ZAP baseline runs where the project declares a target):

- Response headers: CSP, HSTS, `X-Content-Type-Options`, `Referrer-Policy`, CORS behavior at runtime, cookie attributes as actually sent.
- Authorization: broken object-level authorization, missing role checks, IDOR, rate limiting and lockout.
- Token lifetime and session behavior (rotation, logout invalidation), password policy, MFA enforcement.
- TLS configuration of the deployed host (protocols, ciphers, certificate chain).
- Live cloud account posture (AWS Security Hub, Azure Defender, Google Security Command Center, Cloudflare dashboard): needs credentials, out of scope offline.

### Not shipped (UNVERIFIED)

Rules whose standard could not be confirmed on the official page stay out until it can be:

- Cloudflare API-token scope and security-level settings: dashboard settings, not visible in a repository (documentation only). The tunnel catch-all, the Bicep admin user name, the Workers `vars` and `.dev.vars` pages were re-read later (2026-11-17) and became rules.
- GCP and AWS resource rules: not rewritten, see the coverage table (Trivy misconfig).
- `HttpClientXsrfModule.disable()` is cited from the Angular source (`module.ts`); the angular.dev page documents `withNoXsrfProtection()`.
- React 19 `javascript:` URL claim from the JS research was dropped after verification.

## Severity mapping

The scan imports the Opengrep JSON into DefectDojo with the "Semgrep JSON Report" parser, which maps the rule severity to
the DefectDojo severity and reads the CWE from `metadata.cwe`:

| Rule `severity` | DefectDojo severity | Gate |
| --- | --- | --- |
| `ERROR` | High | blocks the PR (open Critical/High) |
| `WARNING` | Medium | reported, converted into a task, does not block |

Among the original injection rules (`angular-ts-xss.yaml`, `csharp-sql-*.yaml`) every sink is `ERROR` and the single `WARNING` is `labsec.angular.inner-html-binding`: Angular sanitizes
`[innerHTML]` by itself, so the binding is a review point, not a confirmed vulnerability. It becomes dangerous only when the
value is wrapped by `bypassSecurityTrustHtml`, which is its own `ERROR` rule. Raise or lower a rule by changing
`severity` in its YAML. The contract test requires `ERROR` or `WARNING` for gated rules and `INFO` for opt-in ones.

A C# line can be reported by two rules only when the text sits in a variable: `sql-raw-built-text-variable` (how the text was
built) and `sql-raw-tainted-input` (where it came from). Text built in place is reported once, by `sql-raw-built-text`.

## Known limits

- Taint is followed inside one file (`--taint-intrafile`), not across files.
- `string` parameters are treated as untrusted. A helper method that receives a non-`string` value is covered only when the
  value arrives from request input in the same file (this is what the intrafile fixture checks).
- Expression-bodied helper methods (`string Compose(object v) => "..." + v;`) are not summarized by the intrafile engine;
  use a block body for the helper or rely on `labsec.csharp.sql-raw-built-text` where the text is built at the sink.
- `new StringBuilder(...)` is treated as built text even if only constants are appended: constant-only builders are rare in
  SQL code, and the rule prefers a false positive to a missed injection.
- The regex rule also matches an `[innerHTML]` string inside a comment or documentation snippet.
- C# SQL rules treat as constant only: `const` fields and locals (constant propagation), literals, numbers and
  `nameof(...)` as interpolation holes. `static readonly` strings, properties, method calls and a concatenation that
  mixes `nameof(...)` with other operands are not constants: they stay findings. A helper whose `string sql` parameter
  reaches `FromSqlRaw(sql, args)` is reported (`sql-raw-tainted-input`) even when every caller passes a constant; mark
  it as a false positive with the file:line of the callers.
- `labsec.typescript.dom-html-assignment` skips a detached `<template>`, so the later insertion of `template.content`
  into the live document is the step that matters; it is not reported by this rule.
- Known false positive of an upstream pack: GitLab `rules_lgpl_javascript_ssrf_rule-node-ssrf` reports a call to a
  function parameter that happens to be named `fetch` (an injected callback, not the global `fetch`). The pack is not
  edited here and no filter is applied, because telling the callback from the global needs scope information; triage it
  with `labsec mark-fp` and the file:line of the parameter declaration.

## Per-project rules (`.appsec.yml`)

A project can add its own rule files or folders (relative to the project root); they are mounted read-only next to the
lab rules and are never run on other projects:

```yaml
rules:
  - security/rules
```

Write each rule with the same shape as the files here (`id`, `languages`, `severity`, `message`, `metadata` with `cwe`, and
`owasp`), then run the checks below on them. Paths outside the project are rejected. See [CLI.md](CLI.md) for the whole
`.appsec.yml` format. The file is added to a repository only with the repository maintainers' approval.

## Adding or changing a rule

1. Put the rule in `rules/opengrep/<name>.yaml` with an id `labsec.<area>.<name>` (noisy rules go to `rules/optin/` with
   severity `INFO`, fixtures in `tests/rules-optin/`). Metadata needs `category`, `cwe` (`CWE-n: name`), `owasp`, `confidence`,
   `standard` and https `references`.
2. Put a fixture with the same stem in `tests/rules/<name>.cs|.ts|.html|.bicep|.txt|.toml|.jsonc` (`.txt`, `.toml` or `.jsonc` for regex rules on config files). Mark every line that must match with
   `// ruleid: <id>` (or `<!-- ruleid: <id> -->`) on the line before it, and every near miss that must stay quiet with
   `// ok: <id>`. Several ids on one line are separated by commas. A rule needs at least one of each.
3. Run the checks.

## Running the rule tests

```bash
# Everything (static contract, `opengrep scan --validate`, native `opengrep test`); needs Docker and the opengrep image
uv run pytest tests/rules

# The native Opengrep test on its own
docker run --rm -v "$PWD":/src:ro labsecurity/opengrep:2.0.0-r2 test --taint-intrafile --strict \
  --config /src/rules/opengrep /src/tests/rules

# Validate the rule files (downloads the public rule-lint ruleset, so it needs the network)
docker run --rm -v "$PWD":/src:ro labsecurity/opengrep:2.0.0-r2 scan --validate --config /src/rules/opengrep
```

The image is built by `docker compose --profile tools build opengrep`. The pytest wrapper skips the Docker steps when
Docker or the image is missing, and skips the validation step when the lint ruleset cannot be downloaded; the static
contract tests always run.
