"""S8 real test: does SonarQube Community Build do taint analysis (injection detection) for C#?

Builds a throw-away ASP.NET Core minimal API in which request input flows through two methods into
`new NpgsqlCommand($"...{value}")`, into `Process.Start(value)` and into a file path, runs one full lap with `bin/scan`,
then asks the SonarQube API what it reported and which security rules exist in this edition. It also tries to analyze a
non-main branch. The results are asserted (so a Sonar upgrade that adds taint analysis fails this test loudly) and, when
LABSEC_SONAR_TAINT_OUT is set, written to that JSON file for docs/SONAR-TAINT.md.

Run with: uv run pytest -m integration tests/integration/test_sonar_taint.py
Everything it creates (SonarQube project, DefectDojo product, work copy, run folders) is removed afterwards.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

import pytest
import requests

import fixture_repo
from labsec.config import Paths, read_vars
from labsec.docker import Compose

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.integration

CSPROJ = """\
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Npgsql" Version="9.0.*" />
  </ItemGroup>
</Project>
"""

# Request input -> two methods -> sink, three times: SQL (NpgsqlCommand), OS command (Process.Start), file path.
PROGRAM = """\
using System.Diagnostics;
using Npgsql;

var app = WebApplication.CreateBuilder(args).Build();

app.MapGet("/users", (HttpRequest request) => Lookup(request.Query["name"].ToString()));
app.MapGet("/tools", (HttpRequest request) => RunTool(request.Query["tool"].ToString()));
app.MapGet("/files", (HttpRequest request) => ReadFile(request.Query["path"].ToString()));

app.Run();

static string Lookup(string value)
{
    return Find(value);
}

static string Find(string value)
{
    using var connection = new NpgsqlConnection("Host=127.0.0.1;Database=app");
    using var command = new NpgsqlCommand($"SELECT id FROM users WHERE name = '{value}'", connection);
    return command.ExecuteScalar()?.ToString() ?? "";
}

static string RunTool(string value)
{
    return Launch(value);
}

static string Launch(string value)
{
    Process.Start(value);
    return "started";
}

static string ReadFile(string value)
{
    return Read(value);
}

static string Read(string value)
{
    return File.ReadAllText("/data/" + value);
}
"""

# The same three flows written as a classic MVC controller: a second data point for the .NET security analyzers.
CONTROLLER = """\
using System.Data;
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Npgsql;

public class ToolsController : Controller
{
    [HttpGet("/c/users")]
    public string Users(string name)
    {
        return Find(name);
    }

    [HttpGet("/c/tools")]
    public string Tools(string tool)
    {
        return Launch(tool);
    }

    [HttpGet("/c/files")]
    public string Files(string path)
    {
        return Read(path);
    }

    private static string Find(string value)
    {
        using var connection = new NpgsqlConnection("Host=127.0.0.1;Database=app");
        IDbCommand command = connection.CreateCommand();
        command.CommandText = "SELECT id FROM users WHERE name = '" + value + "'";
        return command.ExecuteScalar()?.ToString() ?? "";
    }

    private static string Launch(string value)
    {
        Process.Start(value);
        return "started";
    }

    private static string Read(string value)
    {
        return System.IO.File.ReadAllText("/data/" + value);
    }
}
"""

# Rule keys that Sonar documents as taint ("injection vulnerabilities detection") rules for C#.
TAINT_RULE_KEYS = [
    "S2076",  # OS command injection
    "S2083",  # path traversal injection
    "S2631",  # regex injection
    "S3649",  # SQL injection
    "S5131",  # XSS
    "S5144",  # SSRF
    "S5145",  # log injection
    "S5146",  # open redirect
    "S6096",  # zip slip
    "S6287",  # untrusted deserialization (taint flavor)
    "S6350",  # XPath injection
    "S6399",  # LDAP injection
]


def scan(project: Path) -> tuple[int, dict, str]:
    deadline = time.monotonic() + 1800
    while True:
        proc = subprocess.run(
            [str(ROOT / "bin" / "scan"), str(project), "--json"], capture_output=True, text=True, timeout=3000, check=False
        )
        if proc.returncode == 3 and "another heavy analysis" in proc.stderr and time.monotonic() < deadline:
            time.sleep(60)  # another lap holds the lock: wait, never delete it
            continue
        return proc.returncode, json.loads(proc.stdout or "{}"), proc.stderr


@pytest.fixture(scope="module")
def lab():
    paths = Paths.from_env()
    cli = read_vars(paths.cli_vars)
    if not cli.get("SONAR_TOKEN") or not cli.get("DD_API_TOKEN"):
        pytest.skip("lab not bootstrapped (run bin/scan --bootstrap)")
    return paths, cli


@pytest.fixture(scope="module")
def project(lab):
    paths, cli = lab
    slug = f"labsec-taint-{uuid.uuid4().hex[:8]}"
    scratch = Path(tempfile.mkdtemp(prefix="labsec-taint-"))
    repo = scratch / slug
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q", "-b", "main"], check=True)
    fixture_repo.write(repo, "Api/Api.csproj", CSPROJ)
    fixture_repo.write(repo, "Api/Program.cs", PROGRAM)
    fixture_repo.write(repo, "Api/ToolsController.cs", CONTROLLER)
    fixture_repo.git(repo, "add", "-A")
    fixture_repo.git(repo, "commit", "-q", "-m", "taint fixture")
    yield repo
    shutil.rmtree(paths.work_dir(slug), ignore_errors=True)
    shutil.rmtree(paths.data_dir / "runs" / slug, ignore_errors=True)
    requests.post(
        f"{cli['SONAR_URL']}/api/projects/delete", auth=(cli["SONAR_TOKEN"], ""), data={"project": slug}, timeout=60
    )
    headers = {"Authorization": f"Token {cli['DD_API_TOKEN']}"}
    products = requests.get(f"{cli['DD_URL']}/api/v2/products/", headers=headers, params={"name": slug}, timeout=60)
    for product in products.json().get("results", []):
        requests.delete(f"{cli['DD_URL']}/api/v2/products/{product['id']}/", headers=headers, timeout=120)
    shutil.rmtree(scratch, ignore_errors=True)


@pytest.fixture(scope="module")
def observed(project, lab):
    """Run the lap and collect everything Sonar and the other tools report. Counts and rule keys only."""
    paths, cli = lab
    slug = project.name
    auth = (cli["SONAR_TOKEN"], "")
    base = cli["SONAR_URL"]

    def get(path: str, **params):
        return requests.get(f"{base}{path}", auth=auth, params=params, timeout=60)

    code, summary, stderr = scan(project)
    out: dict = {"scan_exit": code, "scan_errors": summary.get("errors"), "scan_stderr_tail": stderr[-500:]}
    out["tools"] = {t["name"]: t["status"] for t in summary.get("tools", [])}
    out["sonar_version"] = get("/api/server/version").text.strip()

    issues = get("/api/issues/search", componentKeys=slug, types="VULNERABILITY", ps=500).json()
    out["vulnerability_issues"] = {"total": issues["total"], "rules": sorted({i["rule"] for i in issues["issues"]})}
    all_issues = get("/api/issues/search", componentKeys=slug, ps=500).json()
    out["all_issues"] = {"total": all_issues["total"], "rules": sorted({i["rule"] for i in all_issues["issues"]})}
    hotspots = get("/api/hotspots/search", project=slug, ps=500).json()
    out["hotspots"] = {"total": hotspots["paging"]["total"], "rules": sorted({h["ruleKey"] for h in hotspots["hotspots"]})}

    out["roslyn_security_repository_rules"] = get(
        "/api/rules/search", repositories="roslyn.sonaranalyzer.security.cs", ps=1
    ).json()["total"]
    out["repositories_cs"] = [r["key"] for r in get("/api/rules/repositories", language="cs").json()["repositories"]]
    out["csharpsquid_rules"] = get("/api/rules/search", repositories="csharpsquid", ps=1).json()["total"]
    out["csharpsquid_vulnerability_rules"] = get(
        "/api/rules/search", repositories="csharpsquid", types="VULNERABILITY", ps=1
    ).json()["total"]
    out["taint_rules_present"] = sorted(
        key for key in TAINT_RULE_KEYS if get("/api/rules/show", key=f"csharpsquid:{key}").status_code == 200
    )
    out["rule_search_S3649_total"] = get("/api/rules/search", q="S3649", ps=1).json()["total"]
    s2077 = get("/api/rules/show", key="csharpsquid:S2077").json().get("rule", {})
    out["S2077"] = {"type": s2077.get("type"), "name": s2077.get("name")}

    # What the rest of the lab reports for the same code (this is what compensates for the missing taint rules).
    raw = paths.run_dir(slug, summary["run_id"]) / "raw" if summary.get("run_id") else None
    out["opengrep_rules"] = {}
    out["dotnet_analyzer_rules"] = {}
    if raw and (raw / "opengrep.json").is_file():
        results = json.loads((raw / "opengrep.json").read_text())["results"]
        out["opengrep_total"] = len(results)
        for result in results:
            rule = result["check_id"].split("rules.custom.")[-1]
            if rule.startswith("labsec."):
                key = f"{rule} @ {Path(result['path']).name}"
                out["opengrep_rules"][key] = out["opengrep_rules"].get(key, 0) + 1
    if raw and (raw / "dotnet-analyzers.sarif").is_file():
        sarif = json.loads((raw / "dotnet-analyzers.sarif").read_text())
        for run in sarif.get("runs", []):
            for result in run.get("results", []):
                locations = result.get("locations") or [{}]
                uri = locations[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                key = f"{result.get('ruleId', '')} @ {Path(uri).name}"
                out["dotnet_analyzer_rules"][key] = out["dotnet_analyzer_rules"].get(key, 0) + 1

    # Non-main branch analysis of the same project.
    compose = Compose(paths)
    with tempfile.TemporaryDirectory(prefix="labsec-branch-") as outdir:
        os.chmod(outdir, 0o700)
        result = compose.run_tool(
            "sonar-scanner",
            [
                "sonar-scanner",
                f"-Dsonar.projectKey={slug}",
                "-Dsonar.branch.name=feature-taint-probe",
                "-Dsonar.projectBaseDir=/usr/src",
                "-Dsonar.sources=.",
                "-Dsonar.scm.disabled=true",
                "-Dsonar.working.directory=/out/sonar-work",
            ],
            mounts=[(str(project), "/usr/src", "ro"), (outdir, "/out", "rw")],
            credentials={"SONAR_TOKEN": cli["SONAR_TOKEN"]},
            timeout=900,
        )
    lines = [line.strip()[:240] for line in result.output.splitlines()]
    error_lines = []
    for index, line in enumerate(lines):
        if "ERROR" in line:
            error_lines.extend(lines[index : index + 3])
            break
    branches = get("/api/project_branches/list", project=slug).json()
    out["branch_analysis"] = {
        "exit": result.returncode,
        "error_lines": error_lines,
        "branches_after": [b["name"] for b in branches.get("branches", [])],
    }

    destination = os.environ.get("LABSEC_SONAR_TAINT_OUT")
    if destination:
        Path(destination).write_text(json.dumps(out, indent=2, sort_keys=True))
    return out


def test_lap_completed_and_sonar_analyzed_the_project(observed):
    assert observed["tools"].get("sonarqube") == "ok", observed["tools"]
    assert observed["tools"].get("opengrep") == "ok", observed["tools"]
    assert observed["all_issues"]["total"] >= 1


def test_sonar_community_reports_no_taint_vulnerability_for_request_to_sink_flows(observed):
    # Three request-to-sink flows exist in the fixture; a taint engine would raise a VULNERABILITY for each.
    taint_hits = [r for r in observed["vulnerability_issues"]["rules"] if r.split(":")[-1] in TAINT_RULE_KEYS]
    assert taint_hits == []
    assert observed["hotspots"]["total"] == 0


def test_sonar_community_has_no_security_taint_rules(observed):
    assert observed["taint_rules_present"] == []
    assert observed["roslyn_security_repository_rules"] == 0
    assert observed["rule_search_S3649_total"] == 0
    assert observed["repositories_cs"] == ["csharpsquid"]


def test_sonar_community_rejects_branch_analysis(observed):
    branch = observed["branch_analysis"]
    assert branch["exit"] != 0, branch
    assert branch["branches_after"] in ([], ["main"]), branch
    assert any("branch" in line.lower() for line in branch["error_lines"]), branch


def test_labsecurity_compensates_with_opengrep_taint_and_dotnet_analyzers(observed):
    assert any(rule.startswith("labsec.csharp.sql-raw") for rule in observed["opengrep_rules"]), observed["opengrep_rules"]
