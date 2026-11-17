import json

import pytest

from labsec.reports import merge_sarif, normalize_gitleaks, normalize_opengrep, relativize, sarif_level
from labsec.sonar import to_dojo_export


def issue(key, kind, severity, component="demo:src/a.cs"):
    return {
        "key": key,
        "rule": "csharpsquid:S1",
        "component": component,
        "line": 7,
        "status": "OPEN",
        "message": "msg",
        "type": kind,
        "severity": severity,
        "scope": "MAIN",
        "creationDate": "2026-11-17T10:00:00+0000",
    }


def test_sonar_export_has_the_shape_the_dojo_parser_requires():
    export = to_dojo_export("demo", [issue("i1", "VULNERABILITY", "BLOCKER")], [], {"demo:src/a.cs": {"key": "demo:src/a.cs", "path": "src/a.cs"}})
    assert export["paging"] and export["components"]
    assert {c["key"] for c in export["components"]} == {"src/a.cs", "demo"}
    assert export["issues"][0]["component"] == "src/a.cs"
    assert export["issues"][0]["project"] == "demo"


def test_empty_sonar_export_is_still_parseable():
    export = to_dojo_export("demo", [], [], {})
    assert export["paging"]["total"] == 0
    assert export["components"] == [{"key": "demo", "name": "demo", "qualifier": "TRK"}]


@pytest.mark.parametrize(
    "sonar_severity, wanted_input",
    [
        ("BLOCKER", "CRITICAL"),  # DefectDojo: Critical
        ("CRITICAL", "BLOCKER"),  # DefectDojo: High
        ("MAJOR", "MAJOR"),  # Medium
        ("MINOR", "MINOR"),  # Low
    ],
)
def test_sonar_vulnerability_severity_mapping_feeds_the_dojo_parser(sonar_severity, wanted_input):
    export = to_dojo_export("demo", [issue("i1", "VULNERABILITY", sonar_severity)], [], {})
    assert export["issues"][0]["severity"] == wanted_input


@pytest.mark.parametrize("kind", ["BUG", "CODE_SMELL"])
def test_quality_issues_stay_in_sonarqube_and_never_reach_defectdojo(kind):
    export = to_dojo_export("demo", [issue("i1", kind, "BLOCKER"), issue("i2", "VULNERABILITY", "CRITICAL")], [], {})
    assert [i["key"] for i in export["issues"]] == ["i2"]
    assert export["paging"]["total"] == 1


def test_external_issues_never_reach_defectdojo_through_sonarqube():
    external = {**issue("e1", "VULNERABILITY", "CRITICAL"), "rule": "external_roslyn:CA3001"}
    export = to_dojo_export("demo", [external], [], {})
    assert export["issues"] == []  # security analyzers reach DefectDojo from their own reports


def test_issue_with_a_security_impact_counts_as_security_even_if_typed_as_bug():
    raw = {**issue("i1", "BUG", "MAJOR"), "impacts": [{"softwareQuality": "SECURITY", "severity": "MEDIUM"}]}
    assert len(to_dojo_export("demo", [raw], [], {})["issues"]) == 1


def test_hotspots_never_exceed_medium():
    hotspot = {"key": "h1", "component": "demo:a.cs", "securityCategory": "weak-cryptography", "vulnerabilityProbability": "HIGH", "ruleKey": "r", "message": "m"}
    export = to_dojo_export("demo", [], [hotspot], {})
    assert export["hotspots"][0]["vulnerabilityProbability"] == "MEDIUM"
    assert export["hotspots"][0]["component"] == "a.cs"


def test_issue_without_legacy_type_or_severity_uses_impacts():
    raw = issue("i1", None, None)
    raw.pop("type"), raw.pop("severity")
    raw["impacts"] = [{"softwareQuality": "SECURITY", "severity": "HIGH"}]
    export = to_dojo_export("demo", [raw], [], {})
    assert export["issues"][0]["type"] == "VULNERABILITY"
    assert export["issues"][0]["severity"] == "BLOCKER"  # HIGH -> legacy CRITICAL -> DefectDojo High


def test_relativize_strips_container_prefixes():
    assert relativize("/src/a/b.ts") == "a/b.ts"
    assert relativize("file:///work/Api/P.cs") == "Api/P.cs"
    assert relativize("./x.py") == "x.py"
    assert relativize("already/relative.go") == "already/relative.go"


def test_opengrep_and_gitleaks_paths_are_normalized(tmp_path):
    og = tmp_path / "og.json"
    og.write_text(json.dumps({"results": [{"path": "/src/Api/P.cs"}, {"path": "web/a.ts"}]}))
    assert normalize_opengrep(og) == 2
    assert [r["path"] for r in json.loads(og.read_text())["results"]] == ["Api/P.cs", "web/a.ts"]
    gl = tmp_path / "gl.json"
    gl.write_text(json.dumps([{"File": "/repo/deploy/s.txt", "Secret": "REDACTED"}]))
    assert normalize_gitleaks(gl) == 1
    assert json.loads(gl.read_text())[0]["File"] == "deploy/s.txt"


def test_sarif_merge_keeps_only_security_analyzers_and_relative_paths(tmp_path):
    def result(rule, uri):
        return {"ruleId": rule, "level": "warning", "message": {"text": "m"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 3}}}]}

    log = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "csc"}}, "results": [result("CA3001", "file:///work/Api/P.cs"), result("CS8618", "file:///work/Api/P.cs"), result("CA2100", "/work/Api/Q.cs")]}]}
    (tmp_path / "Api.sarif").write_text(json.dumps(log))
    target = tmp_path / "merged.sarif"
    assert merge_sarif(list(tmp_path.glob("Api.sarif")), target) == 2
    merged = json.loads(target.read_text())
    results = merged["runs"][0]["results"]
    assert [r["ruleId"] for r in results] == ["CA3001", "CA2100"]
    assert all(r["level"] == "error" for r in results)
    assert [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results] == ["Api/P.cs", "Api/Q.cs"]


def test_sarif_merge_without_logs_fails(tmp_path):
    with pytest.raises(ValueError):
        merge_sarif([], tmp_path / "m.sarif")


def _sarif_log(rules, results):
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "csc", "rules": rules}}, "results": results}],
    }


def _result(rule, index, uri="file:///work/Api/P.cs", level="warning"):
    return {"ruleId": rule, "ruleIndex": index, "level": level, "message": {"text": "m"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 3}}}]}


def test_sarif_filter_keeps_every_rule_of_the_security_category_whatever_the_analyzer(tmp_path):
    rules = [
        {"id": "MA0039", "properties": {"category": "Security"}},  # Meziantou security rule
        {"id": "MA0038", "properties": {"category": "Design"}},  # Meziantou quality rule: SonarQube only
        {"id": "RCS1110", "properties": {"category": "Roslynator"}},
        {"id": "SCS0029", "properties": {"category": "Security"}},
        {"id": "CA5350", "properties": {"category": "Security"}},
        {"id": "CA1822", "properties": {"category": "Performance"}},
    ]
    results = [_result(r["id"], i) for i, r in enumerate(rules)]
    (tmp_path / "a.sarif").write_text(json.dumps(_sarif_log(rules, results)))
    target = tmp_path / "m.sarif"
    assert merge_sarif([tmp_path / "a.sarif"], target) == 3
    merged = json.loads(target.read_text())["runs"][0]
    assert [r["ruleId"] for r in merged["results"]] == ["MA0039", "SCS0029", "CA5350"]
    # The rules table shrinks to the kept rules and ruleIndex points into it.
    assert [r["id"] for r in merged["tool"]["driver"]["rules"]] == ["MA0039", "SCS0029", "CA5350"]
    assert [r["ruleIndex"] for r in merged["results"]] == [0, 1, 2]


def test_sarif_filter_drops_quality_rules_even_when_the_log_has_no_rules_table(tmp_path):
    log = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "csc"}}, "results": [_result("CA1822", 0), _result("MA0038", 1), _result("SCS0001", 2)]}]}
    (tmp_path / "a.sarif").write_text(json.dumps(log))
    assert merge_sarif([tmp_path / "a.sarif"], tmp_path / "m.sarif") == 1  # SCS0001 is recognized by its id shape


@pytest.mark.parametrize(
    "rule, level",
    [
        ("CA2100", "error"), ("CA3001", "error"), ("CA3012", "error"),  # injection (taint)
        ("CA2300", "error"), ("CA2326", "error"),  # unsafe deserialization
        ("CA3075", "error"), ("CA5359", "error"), ("CA5390", "error"),  # XXE, TLS validation off, hard-coded key
        ("SCS0001", "error"), ("SCS0002", "error"), ("SCS0029", "error"),
        ("CA5351", "warning"), ("CA5350", "warning"), ("SCS0008", "warning"), ("MA0039", "warning"),  # default: Medium
        ("CA5394", "note"), ("SCS0005", "note"),  # insecure randomness: Low
    ],
)
def test_sarif_level_maps_rule_to_defectdojo_severity(rule, level):
    assert sarif_level(rule) == level


def test_merged_sarif_applies_the_per_rule_level(tmp_path):
    rules = [{"id": "CA3001", "properties": {"category": "Security"}}, {"id": "CA5394", "properties": {"category": "Security"}}, {"id": "CA5351", "properties": {"category": "Security"}}]
    results = [_result(r["id"], i, level="note") for i, r in enumerate(rules)]
    (tmp_path / "a.sarif").write_text(json.dumps(_sarif_log(rules, results)))
    target = tmp_path / "m.sarif"
    merge_sarif([tmp_path / "a.sarif"], target)
    assert [r["level"] for r in json.loads(target.read_text())["runs"][0]["results"]] == ["error", "note", "warning"]
