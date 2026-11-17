import json
import os
import re
import shutil
import subprocess

import pytest

from labsec import standards
from labsec.standards import OWASP_TOP10_2025, RULES, augment_report, check_angular, check_cloudflare, check_npm, run_checks, strip_json_comments

PKG = json.dumps({"name": "app", "dependencies": {"left-pad": "1.3.0"}})


def ids(findings):
    return sorted(f["check_id"].removeprefix("rules.custom.") for f in findings)


def lock(packages):
    return json.dumps({"lockfileVersion": 3, "packages": {"": {"name": "app"}, **packages}}, indent=2)


def test_rule_metadata_is_complete():
    for rule_id, spec in RULES.items():
        assert re.fullmatch(r"labsec\.[a-z0-9]+\.[a-z0-9]+(-[a-z0-9]+)*", rule_id)
        assert re.match(r"^CWE-\d+: \S", spec["cwe"])
        assert spec["owasp"] in OWASP_TOP10_2025, spec["owasp"]
        assert spec["severity"] in {"ERROR", "WARNING", "INFO"}
        assert spec["confidence"] in {"HIGH", "MEDIUM", "LOW"}
        assert spec["standard"].strip() and spec["message"].strip()
        assert spec["references"] and all(ref.startswith("https://") for ref in spec["references"])
        for asvs in spec.get("asvs", []):
            assert re.fullmatch(r"V\d+\.\d+\.\d+", asvs)


def test_finding_has_semgrep_json_shape(make_tree):
    root = make_tree({"package.json": PKG})
    (finding,) = check_npm(root)
    assert finding["check_id"] == "rules.custom.labsec.npm.no-lockfile"
    assert finding["path"] == "package.json"
    assert finding["start"]["line"] == 1 and finding["end"]["line"] == 1
    assert finding["extra"]["severity"] == "WARNING"
    assert finding["extra"]["metadata"]["cwe"].startswith("CWE-1357:")
    assert finding["extra"]["metadata"]["references"]


def test_no_lockfile_reported_only_when_dependencies_exist(make_tree):
    assert ids(check_npm(make_tree({"package.json": PKG}))) == ["labsec.npm.no-lockfile"]


def test_lockfile_present_or_no_dependencies_is_clean(make_tree, tmp_path):
    clean = make_tree({"package.json": PKG, "yarn.lock": "# yarn lockfile v1\n"})
    assert check_npm(clean) == []
    assert check_npm(make_tree({"other/package.json": json.dumps({"name": "x"})})) == []


def test_workspace_package_uses_root_lockfile(make_tree):
    root = make_tree({"package.json": PKG, "package-lock.json": lock({}), "packages/a/package.json": PKG})
    assert check_npm(root) == []


def test_node_modules_is_ignored(make_tree):
    assert check_npm(make_tree({"node_modules/x/package.json": PKG})) == []


def test_lockfile_http_and_missing_integrity(make_tree):
    packages = {
        "node_modules/ok": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/ok/-/ok-1.0.0.tgz", "integrity": "sha512-abc"},
        "node_modules/plain": {"version": "1.0.0", "resolved": "http://registry.example.test/plain-1.0.0.tgz", "integrity": "sha512-abc"},
        "node_modules/noint": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/noint/-/noint-1.0.0.tgz"},
        "node_modules/linked": {"resolved": "../linked", "link": True},
    }
    findings = check_npm(make_tree({"package.json": PKG, "package-lock.json": lock(packages)}))
    assert ids(findings) == ["labsec.npm.lockfile-insecure-source", "labsec.npm.lockfile-no-integrity"]
    insecure = next(f for f in findings if f["check_id"].endswith("insecure-source"))
    assert insecure["start"]["line"] > 1
    assert "plain" in insecure["extra"]["message"] and "ok" not in insecure["extra"]["message"].split("Affected:")[1].split(",")[0]
    assert "noint" in next(f for f in findings if f["check_id"].endswith("no-integrity"))["extra"]["message"]


def test_clean_lockfile_has_no_findings(make_tree):
    packages = {"node_modules/ok": {"resolved": "https://registry.npmjs.org/ok/-/ok-1.0.0.tgz", "integrity": "sha512-abc"}}
    assert check_npm(make_tree({"package.json": PKG, "package-lock.json": lock(packages)})) == []


def test_lockfile_v1_nested_dependencies(make_tree):
    data = {"lockfileVersion": 1, "dependencies": {"a": {"resolved": "https://r.example.test/a.tgz", "integrity": "sha1-x", "dependencies": {"b": {"resolved": "http://r.example.test/b.tgz", "integrity": "sha1-y"}}}}}
    findings = check_npm(make_tree({"package.json": PKG, "package-lock.json": json.dumps(data)}))
    assert ids(findings) == ["labsec.npm.lockfile-insecure-source"]


def test_npmrc_findings_never_echo_secrets(make_tree):
    npmrc = "\n".join(
        [
            "; comment",
            "strict-ssl=false",
            "registry=http://registry.example.test/",
            "//registry.example.test/:_authToken=literal-token-value",
            "@scope:registry=http://localhost:4873/",
            "//other.example.test/:_authToken=${NPM_TOKEN}",
        ]
    )
    findings = check_npm(make_tree({"package.json": PKG, "package-lock.json": lock({}), ".npmrc": npmrc}))
    assert ids(findings) == [
        "labsec.npm.npmrc-http-registry",
        "labsec.npm.npmrc-literal-auth-token",
        "labsec.npm.npmrc-strict-ssl-disabled",
    ]
    assert "literal-token-value" not in json.dumps(findings)
    assert {f["check_id"].removeprefix("rules.custom."): f["start"]["line"] for f in findings}["labsec.npm.npmrc-strict-ssl-disabled"] == 2


def test_secure_npmrc_is_clean(make_tree):
    npmrc = "strict-ssl=true\nregistry=https://registry.npmjs.org/\nignore-scripts=true\nmin-release-age=1\n"
    assert check_npm(make_tree({"package.json": PKG, "package-lock.json": lock({}), ".npmrc": npmrc}), optin=True) == []


def test_optin_checks_are_off_by_default(make_tree):
    root = make_tree({"package.json": PKG, "package-lock.json": lock({})})
    assert check_npm(root) == []
    assert ids(check_npm(root, optin=True)) == ["labsec.npm.npmrc-ignore-scripts-absent", "labsec.npm.npmrc-min-release-age-absent"]
    assert {f["extra"]["severity"] for f in check_npm(root, optin=True)} == {"INFO"}


ANGULAR = """{
  // comments are valid in angular.json
  "projects": {
    "web": {
      "architect": {
        "build": {
          "options": { "security": { "allowedHosts": %s, "autoCsp": %s } },
          "configurations": { "production": { "sourceMap": %s } }
        }
      }
    }
  }
}
"""


def angular(hosts='["app.example.test", "*.example.test"]', csp="true", source_map="false"):
    return {"angular.json": ANGULAR % (hosts, csp, source_map)}


def test_angular_wildcard_host(make_tree):
    findings = check_angular(make_tree(angular(hosts='["*"]')))
    assert ids(findings) == ["labsec.angular.allowed-hosts-wildcard"]
    assert findings[0]["start"]["line"] == 7


def test_angular_specific_hosts_are_clean(make_tree):
    assert check_angular(make_tree(angular()), optin=True) == []


def test_angular_optin_checks(make_tree):
    root = make_tree(angular(csp='{"unsafeEval": true}', source_map="true"))
    assert check_angular(root) == []
    assert ids(check_angular(root, optin=True)) == ["labsec.angular.autocsp-unsafe-eval", "labsec.angular.production-source-map"]
    hidden = make_tree(angular(source_map='{"scripts": true, "hidden": true}'))
    assert check_angular(hidden, optin=True) == []


def test_invalid_json_is_skipped(make_tree):
    assert run_checks(make_tree({"angular.json": "{ not json", "package.json": "{ nope"})) == []


def test_strip_json_comments_keeps_strings():
    text = '{"url": "http://x//y", /* c */ "a": 1 // tail\n}'
    assert json.loads(strip_json_comments(text)) == {"url": "http://x//y", "a": 1}


def test_augment_report_appends_and_keeps_existing(make_tree, tmp_path):
    root = make_tree({"package.json": PKG})
    report = tmp_path / "opengrep.json"
    report.write_text(json.dumps({"results": [{"check_id": "x", "path": "a", "start": {"line": 1}, "extra": {}}], "errors": []}))
    assert augment_report(report, root) == 1
    data = json.loads(report.read_text())
    assert [r["check_id"] for r in data["results"]] == ["x", "rules.custom.labsec.npm.no-lockfile"]
    assert data["errors"] == []
    assert oct(report.stat().st_mode & 0o777) == "0o600"


def test_run_opengrep_wires_standards():
    import inspect

    from labsec import tools

    source = inspect.getsource(tools.run_opengrep)
    assert "standards.augment_report" in source and "LABSEC_OPTIN" in source and "tracked_files" in source


def test_module_exports():
    assert callable(standards.run_checks)


# ----------------------------------------------------------------------------- Cloudflare .dev.vars
def dev_vars_body():
    """A local variables file with values generated for this test, so the repository never holds one."""
    return f"API_TOKEN={os.urandom(8).hex()}\nDB_PASSWORD={os.urandom(8).hex()}\n"


def test_committed_dev_vars_files_are_flagged_without_their_content(make_tree):
    body = dev_vars_body()
    root = make_tree({".dev.vars": body, "worker/.dev.vars.staging": body, "README.md": "x"})
    tracked = {".dev.vars", "worker/.dev.vars.staging", "README.md"}
    findings = check_cloudflare(root, tracked=tracked)
    assert ids(findings) == ["labsec.cloudflare.dev-vars-committed"] * 2
    assert [f["path"] for f in findings] == [".dev.vars", "worker/.dev.vars.staging"]
    dumped = json.dumps(findings)
    assert all(line.split("=")[1] not in dumped for line in body.splitlines())
    extra = findings[0]["extra"]
    assert extra["severity"] == "ERROR"
    assert extra["metadata"]["cwe"].startswith("CWE-798") and extra["metadata"]["cwe_secondary"].startswith("CWE-312")
    assert extra["metadata"]["owasp"] in OWASP_TOP10_2025


def test_untracked_dev_vars_are_not_committed(make_tree):
    root = make_tree({".dev.vars": dev_vars_body(), ".dev.vars.prod": dev_vars_body()})
    assert check_cloudflare(root, tracked={"wrangler.toml"}) == []


def test_without_git_information_every_dev_vars_file_counts(make_tree):
    root = make_tree({".dev.vars": dev_vars_body()})
    assert ids(check_cloudflare(root, tracked=None)) == ["labsec.cloudflare.dev-vars-committed"]


def test_dev_vars_templates_and_lookalikes_are_clean(make_tree):
    files = {name: "API_TOKEN=\n" for name in (".dev.vars.example", ".dev.vars.sample", ".dev.vars.template", "dev.vars", ".dev.vars.x.bak", "x.dev.vars")}
    root = make_tree(files)
    assert check_cloudflare(root, tracked=set(files)) == []


def test_dev_vars_inside_dependency_dirs_are_skipped(make_tree):
    root = make_tree({"node_modules/pkg/.dev.vars": dev_vars_body()})
    assert check_cloudflare(root) == []


def test_run_checks_includes_the_cloudflare_check(make_tree):
    root = make_tree({".dev.vars": dev_vars_body()})
    assert ids(run_checks(root, tracked={".dev.vars"})) == ["labsec.cloudflare.dev-vars-committed"]
    assert run_checks(root, tracked=set()) == []


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_tracked_files_reads_the_git_index(tmp_path):
    from labsec.tools import tracked_files

    repo = tmp_path / "repo"
    (repo / "worker").mkdir(parents=True)
    (repo / ".dev.vars").write_text(dev_vars_body())
    (repo / "worker" / ".dev.vars.staging").write_text(dev_vars_body())
    (repo / ".gitignore").write_text("worker/.dev.vars*\n")
    run = lambda *args: subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)
    run("init", "-q")
    run("add", ".dev.vars", ".gitignore")
    assert tracked_files(repo) == {".dev.vars", ".gitignore"}
    assert ids(check_cloudflare(repo, tracked=tracked_files(repo))) == ["labsec.cloudflare.dev-vars-committed"]
    assert tracked_files(tmp_path / "plain") is None
