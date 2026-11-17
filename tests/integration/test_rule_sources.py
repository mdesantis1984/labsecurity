"""Every rule source fires on the fixture repository (needs Docker and the built tool images; no lab services).

Run with: uv run pytest -m integration tests/integration/test_rule_sources.py
Each test runs one tool image directly, offline, against a fixture built into a temp directory at test time
(the fake credentials are random text generated then, never literals).
"""

from __future__ import annotations

import json
import re
import os
import shutil
import subprocess
from pathlib import Path

import pytest

import fixture_repo
from labsec.reports import split_eslint

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.integration

OPENGREP = "labsecurity/opengrep:2.0.0-r2"
ESLINT = "labsecurity/eslint:10.15.0"
ZAP = "labsecurity/zap:2.17.0-r2"
GITLEAKS = "docker.io/zricethezav/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"


def docker(*args: str, timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, check=False)


def require_image(image: str) -> None:
    if shutil.which("docker") is None or docker("image", "inspect", image).returncode != 0:
        pytest.skip(f"image {image} is not built (docker compose --profile tools build)")


@pytest.fixture(scope="module")
def tree(tmp_path_factory):
    """The fixture working tree, readable by the non-root users inside the tool containers."""
    repo = tmp_path_factory.mktemp("rules") / "fixture"
    fixture_repo.build_fixture(repo)
    shutil.rmtree(repo / ".git")
    for path in [repo, *repo.rglob("*")]:
        os.chmod(path, 0o755 if path.is_dir() else 0o644)
    return repo


@pytest.fixture
def out(tmp_path):
    directory = tmp_path / "out"
    directory.mkdir()
    os.chmod(directory, 0o777)
    return directory


def user() -> list[str]:
    return ["--user", f"{os.getuid()}:{os.getgid()}"]


def run_opengrep(tree: Path, out: Path, languages: list[str]) -> list[dict]:
    require_image(OPENGREP)
    command = ["run", "--rm", "--network", "none", *user(), "-e", "HOME=/tmp", "-v", f"{tree}:/src:ro", "-v", f"{out}:/out", "-w", "/src", OPENGREP]
    command += ["scan", "--taint-intrafile", "--json", "--output", "/out/o.json", "--quiet"]
    for language in languages:
        command += ["--config", f"/opt/labsec/rules/{language}"]
    proc = docker(*command, ".")
    assert proc.returncode == 0, proc.stderr[-1500:]
    data = json.loads((out / "o.json").read_text())
    assert data["errors"] == []
    return data["results"]


def test_gitlab_sast_rules_fire_on_python_and_csharp(tree, out):
    results = run_opengrep(tree, out, ["python", "csharp"])
    ids = {r["check_id"] for r in results if "x-gitlab-sast-rules" in r["check_id"]}
    assert any(i.endswith("python_deserialization_rule-pickle") for i in ids), sorted(ids)
    assert any("csharp_crypto_rule-WeakRNG" in i for i in ids), sorted(ids)


def test_trail_of_bits_rules_fire_on_python(tree, out):
    results = run_opengrep(tree, out, ["python"])
    ids = {r["check_id"] for r in results if "x-trailofbits-semgrep-rules" in r["check_id"]}
    assert any(i.endswith("pandas-eval") for i in ids), sorted(ids)


def test_base_opengrep_rules_still_fire_next_to_the_packs(tree, out):
    results = run_opengrep(tree, out, ["python", "javascript", "typescript"])
    base = [r for r in results if "x-gitlab" not in r["check_id"] and "x-trailofbits" not in r["check_id"]]
    assert base, "the community rules of opengrep-rules produced nothing"


def test_the_opengrep_image_records_its_pinned_packs_and_prunes_what_does_not_parse():
    require_image(OPENGREP)
    packs = docker("run", "--rm", "--entrypoint", "cat", OPENGREP, "/opt/labsec/rules/PACKS").stdout
    assert "gitlab-sast-rules 83144bd2ec7d3200cda96347fa923f81c8ad8413" in packs
    assert "trailofbits-semgrep-rules 31390b3a99c04c81522d1b37c8d1900aa2dd4094" in packs
    excluded = docker("run", "--rm", "--entrypoint", "cat", OPENGREP, "/opt/labsec/rules/EXCLUDED").stdout
    assert "csharp_crypto_rule-CertificateValidationDisabled" in excluded
    licenses = docker("run", "--rm", "--entrypoint", "ls", OPENGREP, "/opt/labsec/licenses").stdout.split()
    assert {"gitlab-sast-rules.LICENSE", "trailofbits-semgrep-rules.LICENSE"} <= set(licenses)
    # The GitLab EE-licensed rules are never vendored.
    tree = docker("run", "--rm", "--entrypoint", "find", OPENGREP, "/opt/labsec/rules", "-path", "*x-gitlab-sast-rules/gitlab*").stdout
    assert tree.strip() == ""


def test_eslint_security_rules_go_to_defectdojo_and_every_rule_to_sonarqube(tree, out):
    require_image(ESLINT)
    command = ["run", "--rm", "--network", "none", *user(), "-e", "HOME=/tmp", "-v", f"{tree}:/src:ro", "-v", f"{out}:/out", "-w", "/src", ESLINT]
    command += ["--config", "/opt/labsec/eslint/eslint.config.mjs", "--no-inline-config", "--format", "json", "--output-file", "/out/raw.json", "."]
    proc = docker(*command)
    assert proc.returncode in (0, 1), proc.stderr[-1500:]
    counts = split_eslint(out / "raw.json", out / "dojo.json", out / "sonar.json")
    assert counts["security"] >= 3 and counts["quality"] >= 1
    dojo_rules = {m["ruleId"] for f in json.loads((out / "dojo.json").read_text()) for m in f["messages"]}
    assert {"no-unsanitized/property", "security/detect-eval-with-expression", "security/detect-non-literal-require"} <= dojo_rules
    assert not {r for r in dojo_rules if not r.startswith(("security/", "no-unsanitized/"))}
    assert "security/detect-object-injection" not in dojo_rules  # disabled on purpose (docs/RULES.md)
    sonar = json.loads((out / "sonar.json").read_text())
    sonar_rules = {r["id"] for r in sonar["rules"]}
    assert dojo_rules <= sonar_rules
    assert "@angular-eslint/template/alt-text" in sonar_rules  # Angular template rule, quality: Sonar only
    assert all(issue["primaryLocation"]["filePath"].startswith(("web/", "scripts/", "Api/")) for issue in sonar["issues"])


def test_gitleaks_custom_rules_fire_on_the_generated_credentials(tree, out):
    config = ROOT / "config" / "gitleaks.toml"
    command = ["run", "--rm", "--network", "none", *user(), "-e", "HOME=/tmp", "-v", f"{tree}:/repo:ro", "-v", f"{out}:/out", "-v", f"{config}:/config/gitleaks.toml:ro", GITLEAKS]
    command += ["dir", "/repo", "--config", "/config/gitleaks.toml", "--redact", "--report-format", "json", "--report-path", "/out/leaks.json", "--exit-code", "0", "--no-banner"]
    proc = docker(*command)
    assert proc.returncode == 0, proc.stderr[-1500:]
    leaks = json.loads((out / "leaks.json").read_text())
    by_rule = {}
    for leak in leaks:
        by_rule.setdefault(leak["RuleID"], set()).add(leak["File"].removeprefix("/repo/"))
    assert by_rule["labsec-connection-string-password"] == {"Api/appsettings.json"}
    assert by_rule["labsec-appsettings-secret"] == {"Api/appsettings.json"}
    assert by_rule["labsec-keycloak-realm-client-secret"] == {"keycloak/realm-export.json"}
    # Negative: nothing else in the tree is reported by the custom rules.
    custom = {r: files for r, files in by_rule.items() if r.startswith("labsec-")}
    assert set().union(*custom.values()) <= {"Api/appsettings.json", "keycloak/realm-export.json"}


def test_zap_image_has_the_pinned_beta_addons_and_loads_them_offline():
    require_image(ZAP)
    proc = docker("run", "--rm", "--network", "none", "--entrypoint", "/zap/zap.sh", ZAP, "-cmd", "-addonlist")
    listing = proc.stdout + proc.stderr
    assert "pscanrulesBeta\tv50.0.0\tbeta" in listing
    assert "ascanrulesBeta\tv67.0.0\tbeta" in listing
    assert "pscanrulesAlpha" not in listing and "ascanrulesAlpha" not in listing


def test_labsecurity_own_rules_fire_on_the_fixture(tree, out):
    """rules/opengrep (gated own rules) and labsec.standards fire on the planted samples, and only there."""
    require_image(OPENGREP)
    command = ["run", "--rm", "--network", "none", *user(), "-e", "HOME=/tmp", "-v", f"{tree}:/src:ro", "-v", f"{out}:/out"]
    command += ["-v", f"{ROOT / 'rules' / 'opengrep'}:/rules/custom:ro", "-w", "/src", OPENGREP]
    command += ["scan", "--taint-intrafile", "--json", "--output", "/out/own.json", "--quiet", "--config", "/rules/custom", "."]
    proc = docker(*command)
    assert proc.returncode == 0, proc.stderr[-1500:]
    data = json.loads((out / "own.json").read_text())
    assert data["errors"] == []
    from labsec import standards

    (out / "own.json").chmod(0o600)
    standards.augment_report(out / "own.json", tree)
    results = json.loads((out / "own.json").read_text())["results"]
    found = {(r["check_id"].removeprefix("rules.custom."), r["path"]) for r in results}
    assert {
        ("labsec.csharp.developer-exception-page-unguarded", "Api/Hosting.cs"),
        ("labsec.csharp.cookie-secure-disabled", "Api/Hosting.cs"),
        ("labsec.csharp.cookie-httponly-disabled", "Api/Hosting.cs"),
        ("labsec.csharp.tls-certificate-validation-bypass", "Api/Hosting.cs"),
        ("labsec.config.npgsql-ssl-mode-weak", "Api/appsettings.Production.json"),
        ("labsec.cloudflare.tunnel-no-tls-verify", "deploy/tunnel.yml"),
        ("labsec.bicep.secure-parameter-default", "infra/main.bicep"),
        ("labsec.angular.xsrf-protection-disabled", "web/src/app/security.ts"),
        ("labsec.typescript.browser-storage-sensitive-data", "web/src/app/security.ts"),
        ("labsec.npm.lockfile-no-integrity", "web/package-lock.json"),
        ("labsec.npm.npmrc-strict-ssl-disabled", "web/.npmrc"),
    } <= found, sorted(found)
    # Every own finding imports into DefectDojo: CWE as "CWE-n: name" and a known severity.
    own = [r for r in results if r["check_id"].startswith("rules.custom.labsec.")]
    assert own and all(re.match(r"^CWE-\d+:", r["extra"]["metadata"]["cwe"]) for r in own)
    assert {r["extra"]["severity"] for r in own} <= {"ERROR", "WARNING"}
    # The gated rule set does not flag the clean, parameterized samples.
    assert not any(r["check_id"].endswith("labsec.csharp.log-injection") for r in results)
