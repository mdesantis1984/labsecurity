# Third-party notices and acknowledgements

LabSecurity's own source is distributed under the [Apache License 2.0](LICENSE). That license covers only the files in
this repository that LabSecurity's authors wrote. It does **not** apply to any component listed below.

**This repository contains no third-party code, binaries, images, or rule packs.** Everything below is **downloaded on
your machine** when you run `docker compose` or build an image (`docker/*/Dockerfile`), pinned by version and digest or
checksum (see [docs/VERSIONS.md](docs/VERSIONS.md)). LabSecurity does not redistribute any of it: each component keeps its
own license and you receive it from its own publisher, under that publisher's terms. Per-pack versions, rule counts, and
destinations are in [docs/RULES.md](docs/RULES.md).

LabSecurity exists because of these projects. Thank you to their authors and maintainers.

## Do not publish the built images

The images built from `docker/opengrep` **contain rule packs with restrictive terms**. Keep them on your machine. Never push
`labsecurity/opengrep` (or an image derived from it) to a public or shared registry, and never sell or host a scanning
service built on it.

| Content inside the image | Why it matters |
| --- | --- |
| Trail of Bits `semgrep-rules` (**AGPL-3.0**) | Copyleft: giving the image to others, or offering it over a network, triggers AGPL obligations. Internal use only. |
| `opengrep/opengrep-rules` (LGPL-2.1 with the **Commons Clause** License Condition) | You may not sell the software or a service whose value derives from it. |
| GitLab `sast-rules` `rules/lgpl*` (LGPL-3.0, partly with Commons Clause) | Keep unmodified; internal use. |

If you want to share an image, build it without those packs (remove them from `docker/opengrep/Dockerfile`) and review the
remaining licenses first. Pull requests that vendor any third-party rule or binary into this repository will not be accepted.

## Tools and images

License as published by each upstream; the ones marked * come from [docs/RULES.md](docs/RULES.md), where they were checked
against the pinned version, the others are the upstream project's general license and were **not re-verified** per version.

| Component | Version | License | Obtained from |
| --- | --- | --- | --- |
| Opengrep engine * | v2.0.0 | LGPL-2.1 | GitHub release binary, checksum-pinned |
| Gitleaks * | v8.30.1 | MIT | `zricethezav/gitleaks` image |
| Trivy * | 0.76.2 | Apache-2.0 | `aquasec/trivy` image |
| OWASP ZAP * and the beta rule add-ons * | 2.17.0; pscanrulesBeta v50, ascanrulesBeta v67 | Apache-2.0 | `zaproxy/zap-stable` image; zap-extensions releases, checksum-pinned |
| SonarQube Community Build * | 26.11.0.134175 | LGPL-3.0 | `sonarqube` image |
| sonar-scanner CLI | 12.4.0.4321_8.4.0 | LGPL-3.0 | `sonarsource/sonar-scanner-cli` image |
| SonarScanner for .NET | 12.1.0 | LGPL-3.0 | NuGet |
| DefectDojo | 3.5.200 | BSD-3-Clause | `defectdojo/defectdojo-django` and `-nginx` images |
| PostgreSQL | 18.6 | PostgreSQL License | `postgres` image |
| Valkey | 9.1.2 | BSD-3-Clause | `valkey/valkey` image |
| .NET SDK and CA analyzers * | 10.0.404 | MIT | `mcr.microsoft.com/dotnet/sdk` image |
| Node.js | 24 | MIT | `node` image |
| Alpine Linux | 3.24.4 | mixed open-source licenses per package | `alpine` image |
| PyYAML | see `uv.lock` | MIT | PyPI, installed by `uv` on your machine |
| Requests | see `uv.lock` | Apache-2.0 | PyPI, installed by `uv` on your machine |
| pytest (development only) | see `uv.lock` | MIT | PyPI, installed by `uv` on your machine |
| GitHub Actions `actions/checkout`, `actions/setup-node`, `astral-sh/setup-uv` (CI only) | pinned by commit in `.github/workflows/ci.yml` | MIT | GitHub, used only by the hosted CI |

## Analyzers and rule packs downloaded at build time

| Component | Pinned to | License | Notes |
| --- | --- | --- | --- |
| `opengrep/opengrep-rules` * | commit `f1d2b562b414783763fd02a6ed2736eaed622efa` | LGPL-2.1 + Commons Clause | `security/` directories of the supported languages only |
| GitLab `sast-rules` * | commit `83144bd2ec7d3200cda96347fa923f81c8ad8413` | MIT; `rules/lgpl` LGPL-3.0; `rules/lgpl-cc` LGPL + Commons Clause | `rules/gitlab` (GitLab EE license) is **not** used |
| Trail of Bits `semgrep-rules` * | commit `31390b3a99c04c81522d1b37c8d1900aa2dd4094` | **AGPL-3.0** | internal use only |
| SecurityCodeScan.VS2019 * | 5.6.7 | LGPL-3.0-or-later | unmaintained since 2022 |
| Meziantou.Analyzer * | 3.0.341 | MIT | |
| Roslynator.Analyzers * | 5.0.1 | Apache-2.0 | |
| ESLint, `@eslint/js`, typescript-eslint, angular-eslint, globals * | see `docker/eslint/package-lock.json` | MIT | |
| TypeScript * | 6.0.3 | Apache-2.0 | |
| eslint-plugin-security * | 4.2.1 | Apache-2.0 | |
| eslint-plugin-no-unsanitized * | 4.1.5 | MPL-2.0 | used unmodified |
| other npm dependencies of the ESLint image | `docker/eslint/package-lock.json` | MIT, Apache-2.0, BSD-2/3-Clause, ISC, BlueOak-1.0.0, 0BSD, MPL-2.0 (SPDX identifiers read from the lockfile) | |

Not used on purpose: `semgrep/semgrep-rules` (Semgrep Rules License, restricts use and redistribution) and GitLab
`rules/gitlab` (GitLab EE license).

## Standards

LabSecurity's own rules cite public standards by identifier and link (OWASP Top 10 and ASVS, CWE, CIS benchmarks,
Microsoft and Cloudflare documentation). Only short identifiers and titles are used; the texts stay at their publishers.

## Disclaimer

- **Separate licenses.** Each component above is licensed by its own authors. Their licenses apply to them, not to
  LabSecurity's Apache-2.0 license, and using LabSecurity does not grant you any right to them beyond what their licenses
  give. Read them before you use, share, or build on any component, in particular the copyleft and Commons Clause terms
  called out above.
- **No redistribution.** LabSecurity downloads the components on your machine from their publishers. It does not host,
  mirror, or relicense them.
- **Trademarks.** SonarQube, SonarSource, DefectDojo, OWASP, ZAP, Docker, GitHub, GitLab, Microsoft, .NET, Cloudflare,
  Trivy, Aqua Security, and every other product or company name belong to their respective owners and are used only to
  identify the software LabSecurity works with.
- **No affiliation or endorsement.** LabSecurity is an independent project. It is not affiliated with, sponsored by, or
  endorsed by any of the projects or companies named in this repository.
- **Accuracy.** License information is read from each upstream's own publication on the verification date recorded in
  [docs/RULES.md](docs/RULES.md). Entries without a star were not re-verified per version. If you find a mistake, open an
  issue.
- **No warranty.** LabSecurity and this notice are provided "AS IS", without warranty of any kind, express or implied. A
  clean LabSecurity result is not proof that software is secure, and the authors are not liable for any damage that arises
  from using it. See the Apache License 2.0 for the full terms that apply to LabSecurity itself.
