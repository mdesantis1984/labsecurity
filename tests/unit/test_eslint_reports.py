import json

import pytest

from labsec.reports import is_eslint_security_rule, split_eslint


def _file(path, *messages):
    return {"filePath": path, "messages": list(messages)}


def _msg(rule, severity=1, line=3, text="message"):
    return {"ruleId": rule, "severity": severity, "line": line, "column": 5, "endLine": line, "endColumn": 9, "message": text}


@pytest.fixture
def raw(tmp_path):
    data = [
        _file(
            "/src/src/app/a.component.ts",
            _msg("security/detect-eval-with-expression", 1, 12),
            _msg("no-unsanitized/property", 2, 8),
            _msg("@typescript-eslint/no-explicit-any", 2, 20),
        ),
        _file("/src/src/app/a.component.html", _msg("@angular-eslint/template/alt-text", 2, 2)),
        _file("/src/clean.js"),
        _file("/src/broken.ts", {"ruleId": None, "severity": 2, "line": 1, "column": 1, "message": "Parsing error", "fatal": True}),
    ]
    path = tmp_path / "eslint.json"
    path.write_text(json.dumps(data))
    return path


@pytest.mark.parametrize(
    "rule, expected",
    [
        ("security/detect-eval-with-expression", True),
        ("security/detect-child-process", True),
        ("no-unsanitized/method", True),
        ("no-unsanitized/property", True),
        ("@angular-eslint/template/alt-text", False),
        ("@typescript-eslint/no-explicit-any", False),
        ("no-undef", False),
        (None, False),
    ],
)
def test_only_security_plugin_rules_are_security(rule, expected):
    assert is_eslint_security_rule(rule) is expected


def test_split_sends_only_security_rules_to_defectdojo_with_relative_paths(raw, tmp_path):
    dojo, sonar = tmp_path / "dojo.json", tmp_path / "sonar.json"
    counts = split_eslint(raw, dojo, sonar)
    assert counts == {"security": 2, "quality": 2}
    report = json.loads(dojo.read_text())
    # The DefectDojo `ESLint Scan` parser reads a list of {filePath, messages[]} and skips files without messages.
    assert [f["filePath"] for f in report] == ["src/app/a.component.ts"]
    assert [m["ruleId"] for m in report[0]["messages"]] == ["security/detect-eval-with-expression", "no-unsanitized/property"]


def test_split_writes_every_rule_to_sonarqube_in_generic_issue_format(raw, tmp_path):
    dojo, sonar = tmp_path / "dojo.json", tmp_path / "sonar.json"
    split_eslint(raw, dojo, sonar)
    report = json.loads(sonar.read_text())
    rules = {r["id"]: r for r in report["rules"]}
    assert set(rules) == {
        "security/detect-eval-with-expression",
        "no-unsanitized/property",
        "@typescript-eslint/no-explicit-any",
        "@angular-eslint/template/alt-text",
    }
    assert all(r["engineId"] == "eslint" for r in rules.values())
    assert rules["no-unsanitized/property"]["type"] == "VULNERABILITY"
    assert rules["no-unsanitized/property"]["impacts"] == [{"softwareQuality": "SECURITY", "severity": "HIGH"}]
    assert rules["security/detect-eval-with-expression"]["impacts"] == [{"softwareQuality": "SECURITY", "severity": "MEDIUM"}]
    assert rules["@typescript-eslint/no-explicit-any"]["type"] == "CODE_SMELL"
    assert rules["@typescript-eslint/no-explicit-any"]["impacts"] == [{"softwareQuality": "MAINTAINABILITY", "severity": "MEDIUM"}]
    assert len(report["issues"]) == 4
    first = report["issues"][0]
    assert first["ruleId"] == "security/detect-eval-with-expression"
    assert first["primaryLocation"]["filePath"] == "src/app/a.component.ts"
    assert first["primaryLocation"]["textRange"] == {"startLine": 12, "endLine": 12, "startColumn": 4, "endColumn": 8}


def test_split_drops_parse_errors_without_a_rule(raw, tmp_path):
    dojo, sonar = tmp_path / "dojo.json", tmp_path / "sonar.json"
    split_eslint(raw, dojo, sonar)
    assert "broken.ts" not in dojo.read_text() + sonar.read_text()


def test_split_of_a_clean_run_still_writes_valid_reports(tmp_path):
    raw = tmp_path / "e.json"
    raw.write_text(json.dumps([_file("/src/a.js")]))
    dojo, sonar = tmp_path / "dojo.json", tmp_path / "sonar.json"
    assert split_eslint(raw, dojo, sonar) == {"security": 0, "quality": 0}
    assert json.loads(dojo.read_text()) == []
    assert json.loads(sonar.read_text()) == {"rules": [], "issues": []}


def test_split_clamps_zero_width_ranges_to_one_column(tmp_path):
    raw = tmp_path / "e.json"
    message = {"ruleId": "no-undef", "severity": 2, "line": 4, "column": 1, "message": "m"}  # no endLine/endColumn
    raw.write_text(json.dumps([_file("/src/a.js", message)]))
    split_eslint(raw, tmp_path / "d.json", tmp_path / "s.json")
    issue = json.loads((tmp_path / "s.json").read_text())["issues"][0]
    assert issue["primaryLocation"]["textRange"] == {"startLine": 4, "endLine": 4, "startColumn": 0, "endColumn": 1}
