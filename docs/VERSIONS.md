# Pinned versions

Verification date: **2026-11-17**. Every tag and digest below was read from the registry API
(Docker Hub `v2/repositories/.../tags/<tag>`, MCR `v2/.../manifests/<tag>`) or the GitHub releases API
on that date. Images are referenced as `tag@digest`, so a re-pushed tag cannot change what runs.

| Component | Image / artifact | Tag | Digest / checksum | Upstream date | Source |
|---|---|---|---|---|---|
| SonarQube Community Build | `sonarqube` | `26.11.0.134175-community` | `sha256:65541acc…6996fa` | 2026-11-12 | https://hub.docker.com/_/sonarqube |
| PostgreSQL (SonarQube and DefectDojo, separate containers) | `postgres` | `18.6-alpine` | `sha256:9ba53c7d…3085b` | 2026-11-11 | https://hub.docker.com/_/postgres |
| DefectDojo django (uwsgi, celery, initializer) | `defectdojo/defectdojo-django` | `3.5.200` | `sha256:a72b66bf…a38` | 2026-11-16 | https://github.com/DefectDojo/django-DefectDojo/releases/tag/3.5.200 |
| DefectDojo nginx | `defectdojo/defectdojo-nginx` | `3.5.200` | `sha256:830957d2…134` | 2026-11-16 | same release |
| Valkey (DefectDojo broker/cache) | `valkey/valkey` | `9.1.2-alpine` | `sha256:48332870…8d11` | 2026-09-21 | pinned by upstream DefectDojo 3.5.200 compose |
| sonar-scanner CLI | `sonarsource/sonar-scanner-cli` | `12.4.0.4321_8.4.0` | `sha256:6e6eca4d…2d51` | 2026-11-10 | https://hub.docker.com/r/sonarsource/sonar-scanner-cli |
| SonarScanner for .NET | NuGet `dotnet-sonarscanner` | `12.1.0` | NuGet signed package | - | https://www.nuget.org/packages/dotnet-sonarscanner |
| .NET SDK (CA analyzers) | `mcr.microsoft.com/dotnet/sdk` | `10.0.404` | `sha256:fe0fd4e9…3ff4fb` (tag re-pushed on 2026-11-17; previous digest `abba009a…790c` no longer resolves) | - | https://mcr.microsoft.com/artifact/mar/dotnet/sdk |
| Opengrep | release binaries `opengrep_linux_x86` and `opengrep_linux_aarch64` (the image picks one by CPU) | `v2.0.0` | x86 SHA-256 `37e93f4d…62da0`, Sigstore signature verified (cosign v3.0.2 `verify-blob`); aarch64 SHA-256 `6257b654…6d6d8`, checked against a fresh download, signature not verified | 2026-11-13 | https://github.com/opengrep/opengrep/releases/tag/v2.0.0 |
| Opengrep base image | `alpine` | `3.24.4` | `sha256:f59abe65…c71bf` | - | https://hub.docker.com/_/alpine |
| ZAP | `zaproxy/zap-stable` (base of `labsecurity/zap:2.17.0-r2`) | `2.17.0` | `sha256:9624669d…f328af` | 2026-11-03 | https://hub.docker.com/r/zaproxy/zap-stable |
| Gitleaks | `zricethezav/gitleaks` | `v8.30.1` | `sha256:c00b6bd0…bb7f` | 2026-03-21 | https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1 |
| Trivy | `aquasec/trivy` | `0.76.2` | `sha256:8f6bb947…768fb` | 2026-11-05 | https://github.com/aquasecurity/trivy/releases/tag/v0.76.2 |
| Node.js (ESLint image base) | `node` | `24-alpine` | `sha256:116b800c…e85f5` | - | https://hub.docker.com/_/node |
| ESLint toolchain | npm packages in `docker/eslint/package-lock.json`: `eslint` 10.15.0, `@eslint/js` 10.0.1, `typescript-eslint` 8.73.0, `typescript` 6.0.3, `angular-eslint` 22.7.0, `eslint-plugin-security` 4.2.1, `eslint-plugin-no-unsanitized` 4.1.5, `globals` 17.14.0 | see lockfile | npm integrity hashes in the lockfile | - | https://www.npmjs.com/ |
| Meziantou.Analyzer | NuGet | `3.0.341` | SHA-256 `094d584a…86d5e7` | - | https://www.nuget.org/packages/Meziantou.Analyzer |
| Roslynator.Analyzers | NuGet | `5.0.1` | SHA-256 `c34f0658…edf580` | - | https://www.nuget.org/packages/Roslynator.Analyzers |
| SecurityCodeScan.VS2019 | NuGet | `5.6.7` | SHA-256 `2f81fefe…eb08d` | 2022 (unmaintained) | https://www.nuget.org/packages/SecurityCodeScan.VS2019 |
| opengrep-rules | git `opengrep/opengrep-rules` | commit `f1d2b562b414783763fd02a6ed2736eaed622efa` | git commit hash | - | https://github.com/opengrep/opengrep-rules |
| GitLab sast-rules | git `gitlab-org/security-products/sast-rules` | commit `83144bd2ec7d3200cda96347fa923f81c8ad8413` | git commit hash | - | https://gitlab.com/gitlab-org/security-products/sast-rules |
| Trail of Bits semgrep-rules | git `trailofbits/semgrep-rules` | commit `31390b3a99c04c81522d1b37c8d1900aa2dd4094` | git commit hash | - | https://github.com/trailofbits/semgrep-rules |
| ZAP pscanrulesBeta | `.zap` add-on | `v50` | SHA-256 `a979f7cd…e921b` | - | https://github.com/zaproxy/zap-extensions/releases/tag/pscanrulesBeta-v50 |
| ZAP ascanrulesBeta | `.zap` add-on | `v67` | SHA-256 `81e84d59…7db69` | - | https://github.com/zaproxy/zap-extensions/releases/tag/ascanrulesBeta-v67 |

## CPU architectures (Apple Silicon, Linux arm64)

Checked on **2026-11-17** with `docker manifest inspect <image>@<pinned digest>` (read-only; the pinned digests are the
multi-platform indexes, so the same digest works on both CPUs). "Multi-arch" means the pinned digest contains a
`linux/arm64` image.

| Image | Platforms in the pinned digest | On Apple Silicon / arm64 |
| --- | --- | --- |
| `sonarqube:26.11.0.134175-community` | amd64, arm64 | native |
| `postgres:18.6-alpine` | amd64, arm64 (+ 386, arm, ppc64le, riscv64, s390x) | native |
| `defectdojo/defectdojo-django:3.5.200` | amd64, arm64 | native |
| `defectdojo/defectdojo-nginx:3.5.200` | amd64, arm64 | native |
| `valkey/valkey:9.1.2-alpine` | amd64, arm64 (+ arm/v7, ppc64le) | native |
| `aquasec/trivy:0.76.2` | amd64, arm64 (+ ppc64le, s390x) | native |
| `zricethezav/gitleaks:v8.30.1` | amd64, arm64 | native |
| `zaproxy/zap-stable:2.17.0` (base of `labsecurity/zap`) | amd64, arm64 | native; the beta rule add-ons are `.zap` archives, architecture independent |
| `mcr.microsoft.com/dotnet/sdk:10.0.404` (base of `labsecurity/dotnet-analyzers`) | amd64, arm64 (+ arm/v7) | native; the NuGet analyzers and `dotnet-sonarscanner` are architecture independent |
| `node:24-alpine` (base of `labsecurity/eslint`) | amd64, arm64 (+ s390x) | native; `package-lock.json` has no CPU-specific package |
| `alpine:3.24.4` (base of `labsecurity/opengrep` and the backup helper) | amd64, arm64 (+ 386, arm, ppc64le, riscv64, s390x) | native |
| `sonarsource/sonar-scanner-cli:12.4.0.4321_8.4.0` | **amd64 only** (single manifest; the upstream tag has no arm64 image either) | runs through emulation (Rosetta or QEMU); `compose.yaml` sets `platform: linux/amd64` on that service so Docker does not warn |
| `labsecurity/opengrep:2.0.0-r2` (built locally) | built for the host CPU: `docker/opengrep/select-asset.sh` picks `opengrep_linux_aarch64` on arm64 and `opengrep_linux_x86` on amd64, each with its pinned SHA-256 | native on arm64 (UNVERIFIED: no arm64 host or emulator was available; the amd64 build was run and prints `2.0.0`, and `file` reports the aarch64 asset as a statically linked ARM aarch64 ELF) |

Multi-arch images need no change. The only emulated service is the Sonar scanner client, which is a short-lived
container; the long-running services (SonarQube, DefectDojo, PostgreSQL, Valkey) are native. Docker Desktop on Apple
Silicon needs Rosetta enabled ("Use Rosetta for x86_64/amd64 emulation") for the one emulated image; OrbStack and Colima
(`--vm-type vz --vz-rosetta`) provide it too.

## Notes

- **Trivy supply-chain incident (CVE-2026-33634, Feb–Mar 2026).** Trivy release v0.69.4, container images
  pushed in that window, and the `trivy-action` / `setup-trivy` GitHub Action tags were compromised.
  `0.76.2` is later than the incident and is pinned by digest. Never use the GitHub Actions by tag.
  Sources: https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/ ,
  https://safedep.io/trivy-teampcp-supply-chain-compromise/
- **DefectDojo images** are pulled from Docker Hub (`docker.io`), not the upstream default
  `registry.defectdojo.com`, which logs each pull with the client IP.
- **SonarQube Community Build** officially supports PostgreSQL 15 to 18 (since Community Build 26.8):
  https://docs.sonarsource.com/sonarqube-community-build/server-installation/installing-the-database
- Full digests are in `compose.yaml` and the Dockerfiles under `docker/`.
- **Locally built images** (`docker compose --profile tools build`): `labsecurity/opengrep:2.0.0-r2`, `labsecurity/dotnet-analyzers:10.0.404-r2`,
  `labsecurity/eslint:10.15.0`, `labsecurity/zap:2.17.0-r2`. Licenses and what is downloaded versus shipped: `docs/RULES.md`.
- **typescript 6.0.3**: TypeScript 7.x is out but `typescript-eslint` 8.73.0 declares a peer range below 6.1.0.

## Updating a version

1. Read the new tag's digest from the registry API and the upstream release notes (breaking changes, migrations).
2. Run `scripts/backup.sh` first; DefectDojo and SonarQube run database migrations on upgrade.
3. Change `tag@digest` in `compose.yaml` (or the Dockerfile), update this table and its verification date.
4. `docker compose up -d --wait`, then `bin/scan --doctor`.
