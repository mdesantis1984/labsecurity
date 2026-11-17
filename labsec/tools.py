"""Tool runners. Each one analyzes a copy (or a read-only mount) of the project, never the project itself."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

from labsec import reports, scope as scope_mod, standards
from labsec.appsec import AppSecConfig
from labsec.config import Paths, private_dir
from labsec.docker import Compose
from labsec.guard import ensure_loopback
from labsec.sonar import SonarClient

# Languages that have community Opengrep rules in the image, mapped to the rule directories to load.
RULE_DIRS = {
    "csharp": ["csharp"],
    "typescript": ["typescript", "javascript"],
    "javascript": ["javascript", "typescript"],
    "python": ["python"],
    "go": ["go"],
    "java": ["java"],
    "kotlin": ["kotlin"],
    "php": ["php"],
    "ruby": ["ruby"],
    "dockerfile": ["dockerfile"],
    "terraform": ["terraform"],
}
SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@+-]*$")

DOTNET_SCRIPT = r"""
umask 077
mkdir -p "$LABSEC_SARIF_DIR"
# The token only reaches the scanner through a short-lived settings file inside the container.
SETTINGS=$(mktemp /tmp/labsec-XXXXXX.xml)
trap 'rm -f "$SETTINGS"' EXIT
printf '<SonarQubeAnalysisProperties xmlns="http://www.sonarsource.com/msbuild/integration/2015/1">\n<Property Name="sonar.token">%s</Property>\n</SonarQubeAnalysisProperties>\n' "$SONAR_TOKEN" > "$SETTINGS"
# Pass 1 (security): SDK security rules + SecurityCodeScan + Meziantou, one SARIF per project; labsec/reports.py keeps the
# security rules for DefectDojo. It must not run inside begin/end: the scanner relies on its own ErrorLog property,
# which the SARIF log would replace.
while IFS= read -r target; do
  [ -n "$target" ] || continue
  dotnet build "$target" --nologo --no-incremental \
    -p:CustomAfterMicrosoftCommonTargets=/opt/labsec/labsec.targets \
    -p:LabsecSarifDir="$LABSEC_SARIF_DIR"
done <<< "$LABSEC_TARGETS"
# Pass 2 (quality): the instrumented build that feeds SonarQube. AnalysisMode=All, Meziantou.Analyzer and Roslynator.Analyzers
# are loaded here (labsec-quality.targets); the scanner imports what they report as SonarQube external issues.
EXTRA=()
[ -z "${LABSEC_EXTERNAL_ISSUES:-}" ] || EXTRA+=("/d:sonar.externalIssuesReportPaths=$LABSEC_EXTERNAL_ISSUES")
dotnet sonarscanner begin /k:"$LABSEC_SLUG" /n:"$LABSEC_SLUG" /d:sonar.host.url="$SONAR_HOST_URL" /d:sonar.scm.disabled=true "${EXTRA[@]}" /s:"$SETTINGS"
while IFS= read -r target; do
  [ -n "$target" ] || continue
  dotnet build "$target" --nologo --no-incremental \
    -p:CustomAfterMicrosoftCommonTargets=/opt/labsec/labsec-quality.targets
done <<< "$LABSEC_TARGETS"
dotnet sonarscanner end
"""


@dataclass
class ToolOutcome:
    name: str
    status: str  # ok | failed | skipped
    reason: str | None = None
    report: Path | None = None
    scan_type: str | None = None
    test_title: str | None = None
    detail: dict = field(default_factory=dict)


@dataclass
class Ctx:
    paths: Paths
    compose: Compose
    project: Path
    slug: str
    branch: str
    commit: str | None
    run_id: str
    run_dir: Path
    appsec: AppSecConfig
    langs: dict[str, int]
    sonar_token: str
    sonar: SonarClient
    project_vars: dict
    log: Callable[[str], None]
    started: datetime
    scope: scope_mod.Scope | None = None

    @property
    def raw(self) -> Path:
        return self.run_dir / "raw"

    @property
    def work(self) -> Path:
        return self.paths.work_dir(self.slug)

    @property
    def is_git(self) -> bool:
        return (self.project / ".git").exists()


# ----------------------------------------------------------------------------- git (read-only)
def git(project: Path, *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")
    return subprocess.run(
        ["git", "-c", "safe.directory=*", "-C", str(project), *args],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def tracked_files(project: Path) -> set[str] | None:
    """Paths git tracks in the project (relative, POSIX), or None when it is not a git repository."""
    if not (project / ".git").exists():
        return None
    proc = git(project, "ls-files", "-z")
    if proc.returncode != 0:
        return None
    return {path for path in proc.stdout.split("\0") if path}


def resolve_branch(project: Path, requested: str | None) -> tuple[str, str | None]:
    """Return (branch label, commit sha). Never writes to the repository."""
    if not (project / ".git").exists():
        return requested or "no-git", None
    if requested:
        if not SAFE_REF.match(requested):
            raise ValueError(f"invalid branch name {requested!r}")
        proc = git(project, "rev-parse", "--verify", "--quiet", f"{requested}^{{commit}}")
        if proc.returncode != 0:
            raise ValueError(f"branch {requested!r} not found in {project}")
        return requested, proc.stdout.strip()
    branch = git(project, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip() or "HEAD"
    commit = git(project, "rev-parse", "HEAD").stdout.strip() or None
    return branch, commit


# ----------------------------------------------------------------------------- work copy
def prepare_work_copy(ctx: Ctx) -> None:
    """Copy exactly the scan scope (see labsec.scope) into the disposable work directory."""
    if shutil.which("rsync") is None:
        raise RuntimeError("rsync is required on the host (it builds the disposable work copy)")
    if ctx.scope is None:
        ctx.scope = scope_mod.build_scope(ctx.project, ctx.appsec.exclude)
    scope_mod.sync_work_copy(ctx.project, private_dir(ctx.work), ctx.scope)


def _tool_dir(ctx: Ctx, name: str) -> Path:
    return private_dir(ctx.raw / name)


def _out_mount(ctx: Ctx):
    return (str(ctx.raw), "/out", "rw")


# ----------------------------------------------------------------------------- runners
def run_opengrep(ctx: Ctx) -> ToolOutcome:
    wanted: list[str] = []
    for lang in ctx.langs:
        for rule_dir in RULE_DIRS.get(lang, []):
            if rule_dir not in wanted:
                wanted.append(rule_dir)
    mounts = [(str(ctx.work), "/src", "ro"), _out_mount(ctx)]
    configs = [f"/opt/labsec/rules/{d}" for d in wanted]
    custom = ctx.paths.root / "rules" / "opengrep"
    if custom.is_dir() and any(custom.rglob("*.y*ml")):
        mounts.append((str(custom), "/rules/custom", "ro"))
        configs.append("/rules/custom")
    # Opt-in rules (INFO, outside the gate) load only when LABSEC_OPTIN=1.
    optin = os.environ.get("LABSEC_OPTIN") == "1"
    optin_dir = ctx.paths.root / "rules" / "optin"
    if optin and optin_dir.is_dir() and any(optin_dir.rglob("*.y*ml")):
        mounts.append((str(optin_dir), "/rules/optin", "ro"))
        configs.append("/rules/optin")
    for index, rel in enumerate(ctx.appsec.rules):
        mounts.append((str((ctx.project / rel).resolve()), f"/rules/extra{index}", "ro"))
        configs.append(f"/rules/extra{index}")
    if not configs:
        return ToolOutcome("opengrep", "skipped", reason="no language with Opengrep rules detected")
    command = ["scan", "--taint-intrafile", "--json", "--output", "/out/opengrep.json", ]
    command += ["--disable-version-check", "--quiet"]
    for config in configs:
        command += ["--config", config]
    command.append(".")
    result = ctx.compose.run_tool(
        "opengrep",
        command,
        mounts=mounts,
        env={"HOME": "/tmp"},
        workdir="/src",
        log_path=ctx.raw / "opengrep.log",
    )
    report = ctx.raw / "opengrep.json"
    if not result.ok or not report.is_file():
        return ToolOutcome("opengrep", "failed", reason=f"exit {result.returncode}: {result.tail(4)}")
    reports.normalize_opengrep(report)
    extra = standards.augment_report(report, ctx.work, optin=optin, tracked=tracked_files(ctx.project))
    if extra:
        ctx.log(f"standards checks: {extra} finding(s) added to the Opengrep report")
    return ToolOutcome("opengrep", "ok", report=report, scan_type="Semgrep JSON Report", test_title="opengrep")


def run_eslint(ctx: Ctx) -> ToolOutcome:
    """LabSecurity's own ESLint config over the work copy (the project's config and inline disables are ignored)."""
    if not (ctx.langs.get("typescript") or ctx.langs.get("javascript")):
        return ToolOutcome("eslint", "skipped", reason="no TypeScript or JavaScript detected")
    command = [
        "--config", "/opt/labsec/eslint/eslint.config.mjs",
        "--no-inline-config",
        "--format", "json",
        "--output-file", "/out/eslint-raw.json",
        ".",
    ]
    result = ctx.compose.run_tool(
        "eslint",
        command,
        mounts=[(str(ctx.work), "/src", "ro"), _out_mount(ctx)],
        env={"HOME": "/tmp"},
        workdir="/src",
        log_path=ctx.raw / "eslint.log",
    )
    raw = ctx.raw / "eslint-raw.json"
    # ESLint exits 1 when it reports errors: that is a normal result. Exit 2 (or no report) is a tool failure.
    if result.returncode not in (0, 1) or not raw.is_file():
        return ToolOutcome("eslint", "failed", reason=f"exit {result.returncode}: {result.tail(4)}")
    counts = reports.split_eslint(raw, ctx.raw / "eslint.json", ctx.raw / "eslint-sonar.json")
    ctx.log(f"  eslint: {counts['security']} security and {counts['quality']} quality findings")
    return ToolOutcome("eslint", "ok", report=ctx.raw / "eslint.json", scan_type="ESLint Scan", test_title="eslint", detail=dict(counts))


GITLEAKS_CONFIG = "config/gitleaks.toml"


def run_gitleaks(ctx: Ctx) -> ToolOutcome:
    # LabSecurity's own config (defaults + custom rules), explicit so a project's .gitleaks.toml cannot weaken it.
    config_mount = (str(ctx.paths.root / GITLEAKS_CONFIG), "/config/gitleaks.toml", "ro")
    if ctx.is_git:
        mounts = [(str(ctx.project), "/repo", "ro"), _out_mount(ctx), config_mount]
        command = ["git", "/repo", f"--log-opts={ctx.branch}"]
        env = {"HOME": "/tmp", "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "safe.directory", "GIT_CONFIG_VALUE_0": "*"}
    else:
        mounts = [(str(ctx.work), "/repo", "ro"), _out_mount(ctx), config_mount]
        command = ["dir", "/repo"]
        env = {"HOME": "/tmp"}
    command += [
        "--config",
        "/config/gitleaks.toml",
        "--redact",
        "--report-format",
        "json",
        "--report-path",
        "/out/gitleaks.json",
        "--exit-code",
        "0",
        "--no-banner",
    ]
    result = ctx.compose.run_tool("gitleaks", command, mounts=mounts, env=env, log_path=ctx.raw / "gitleaks.log")
    report = ctx.raw / "gitleaks.json"
    if not result.ok or not report.is_file():
        return ToolOutcome("gitleaks", "failed", reason=f"exit {result.returncode}: {result.tail(4)}")
    reports.normalize_gitleaks(report)
    return ToolOutcome("gitleaks", "ok", report=report, scan_type="Gitleaks Scan", test_title="gitleaks")


TRIVY_SCANNERS = "vuln,misconfig"  # secrets stay with Gitleaks (history-aware); licence findings are not security rules


def trivy_command() -> list[str]:
    return [
        "fs",
        "--scanners",
        TRIVY_SCANNERS,
        "--format",
        "json",
        "--output",
        "/out/trivy.json",
        "--no-progress",
        # Package caches and local SDKs hold third-party *.deps.json files: their CVEs are not the project's findings.
        # (The work copy already leaves gitignored directories out; this is the second line of defence.)
        "--skip-dirs",
        "**/.cache",
        "--skip-dirs",
        "**/.toolchain",
        "--timeout",
        "20m",
        "/src",
    ]


def run_trivy(ctx: Ctx) -> ToolOutcome:
    command = trivy_command()
    result = ctx.compose.run_tool(
        "trivy",
        command,
        mounts=[(str(ctx.work), "/src", "ro"), _out_mount(ctx)],
        log_path=ctx.raw / "trivy.log",
    )
    report = ctx.raw / "trivy.json"
    if not result.ok or not report.is_file():
        return ToolOutcome("trivy", "failed", reason=f"exit {result.returncode}: {result.tail(4)}")
    return ToolOutcome("trivy", "ok", report=report, scan_type="Trivy Scan", test_title="trivy")


def _dotnet_targets(work: Path) -> list[str]:
    solutions = sorted(p for p in work.rglob("*") if p.suffix in (".sln", ".slnx"))
    if solutions:
        return [str(solutions[0].relative_to(work))]
    return [str(p.relative_to(work)) for p in sorted(work.rglob("*.csproj"))[:20]]


def run_sonar(ctx: Ctx) -> list[ToolOutcome]:
    """SonarQube analysis. C# repositories go through the .NET image (also produces the CA SARIF)."""
    sonar_url_since = ctx.started
    credentials = {"SONAR_TOKEN": ctx.sonar_token}
    outcomes: list[ToolOutcome] = []
    # ESLint ran before this step: its full report (quality + security) enters SonarQube as external issues.
    external = "/out/eslint-sonar.json" if (ctx.raw / "eslint-sonar.json").is_file() else ""
    if ctx.langs.get("csharp"):
        targets = _dotnet_targets(ctx.work)
        if not targets:
            return [
                ToolOutcome("sonarqube", "failed", reason="C# detected but no .sln/.csproj found"),
                ToolOutcome("dotnet-analyzers", "failed", reason="no .sln/.csproj found"),
            ]
        result = ctx.compose.run_tool(
            "dotnet",
            ["-ceu", DOTNET_SCRIPT],
            entrypoint="bash",
            mounts=[(str(ctx.work), "/work", "rw"), _out_mount(ctx)],
            env={
                "LABSEC_SLUG": ctx.slug,
                "LABSEC_TARGETS": "\n".join(targets),
                "LABSEC_SARIF_DIR": "/out/dotnet-sarif",
                "LABSEC_EXTERNAL_ISSUES": external,
            },
            credentials=credentials,
            workdir="/work",
            log_path=ctx.raw / "dotnet.log",
        )
        sarif_files = list((ctx.raw / "dotnet-sarif").glob("*.sarif")) if (ctx.raw / "dotnet-sarif").is_dir() else []
        if not result.ok:
            reason = f"exit {result.returncode}: {result.tail(5)}"
            return [ToolOutcome("sonarqube", "failed", reason=reason), ToolOutcome("dotnet-analyzers", "failed", reason=reason)]
        if sarif_files:
            merged = ctx.raw / "dotnet-analyzers.sarif"
            reports.merge_sarif(sarif_files, merged)
            outcomes.append(
                ToolOutcome("dotnet-analyzers", "ok", report=merged, scan_type="SARIF", test_title="dotnet-analyzers")
            )
        else:
            outcomes.append(ToolOutcome("dotnet-analyzers", "failed", reason="build produced no SARIF logs"))
    else:
        command = [
            "sonar-scanner",
            f"-Dsonar.projectKey={ctx.slug}",
            f"-Dsonar.projectName={ctx.slug}",
            "-Dsonar.projectBaseDir=/usr/src",
            "-Dsonar.sources=.",
            "-Dsonar.scm.disabled=true",
            "-Dsonar.working.directory=/out/sonar-work",
        ]
        if external:
            command.append(f"-Dsonar.externalIssuesReportPaths={external}")
        result = ctx.compose.run_tool(
            "sonar-scanner",
            command,
            mounts=[(str(ctx.work), "/usr/src", "ro"), _out_mount(ctx)],
            credentials=credentials,
            log_path=ctx.raw / "sonar-scanner.log",
        )
        if not result.ok:
            return [ToolOutcome("sonarqube", "failed", reason=f"exit {result.returncode}: {result.tail(5)}")]
    try:
        ctx.sonar.wait_for_analysis(ctx.slug, since=sonar_url_since)
        export = ctx.sonar.export_for_dojo(ctx.slug)
    except Exception as exc:  # noqa: BLE001 - reported as a tool failure
        outcomes.insert(0, ToolOutcome("sonarqube", "failed", reason=str(exc)[:300]))
        return outcomes
    import json

    report = ctx.raw / "sonarqube.json"
    report.write_text(json.dumps(export), encoding="utf-8")
    os.chmod(report, 0o600)
    outcomes.insert(
        0, ToolOutcome("sonarqube", "ok", report=report, scan_type="SonarQube Scan", test_title="sonarqube")
    )
    return outcomes


def zap_command(zap) -> list[str]:
    """ZAP script and arguments. `-z -silent` stops the stock scripts from running `-addonupdate -addoninstall ...`:
    without it every scan would download the latest (unpinned) add-ons; with it only the add-ons baked into
    labsecurity/zap (docker/zap/Dockerfile, pinned by SHA-256) are loaded."""
    if zap.openapi_url:
        return ["zap-api-scan.py", "-t", zap.openapi_url, "-f", "openapi", "-x", "zap.xml", "-I", "-z", "-silent"]
    return ["zap-baseline.py", "-t", zap.target_url, "-x", "zap.xml", "-I", "-z", "-silent"]


def run_zap(ctx: Ctx) -> ToolOutcome:
    zap = ctx.appsec.zap
    if zap is None:
        return ToolOutcome("zap", "skipped", reason="no zap target declared in .appsec.yml")
    ensure_loopback(zap.target_url)
    if zap.openapi_url:
        ensure_loopback(zap.openapi_url)
    command = zap_command(zap)
    zap_dir = _tool_dir(ctx, "zap")
    result = ctx.compose.run_tool(
        "zap",
        command,
        mounts=[(str(zap_dir), "/zap/wrk", "rw")],
        env={"HOME": "/tmp"},
        workdir="/zap/wrk",
        log_path=ctx.raw / "zap.log",
        timeout=3600,
    )
    report = zap_dir / "zap.xml"
    if not report.is_file():
        return ToolOutcome("zap", "failed", reason=f"exit {result.returncode}: {result.tail(4)}")
    return ToolOutcome("zap", "ok", report=report, scan_type="ZAP Scan", test_title="zap")
