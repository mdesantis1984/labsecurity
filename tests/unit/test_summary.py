import json

import pytest

from labsec.summary import SCHEMA, build_summary, exit_code, render_json, render_text

BLOCKING = {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}
FINDING = {
    "id": 12,
    "severity": "High",
    "title": "SQL built by concatenation",
    "file": "Api/Repo.cs",
    "line": 42,
    "cwe": 89,
    "tool": "opengrep",
    "description": "exploit payload ' OR 1=1",
    "mitigation": "internal",
}


def make(**overrides):
    base = dict(
        project="demo",
        branch="main",
        run_id="20261117T120000Z",
        engagement_url="http://127.0.0.1:19080/engagement/3",
        tools=[{"name": "opengrep", "status": "ok", "findings": 4}],
        counts={"new": 4, "open": 6, "closed": 1, "blocking": BLOCKING},
        blocking_findings=[FINDING],
        errors=[],
    )
    base.update(overrides)
    return build_summary(**base)


def test_json_schema_is_stable():
    data = json.loads(render_json(make()))
    assert list(data) == [
        "schema",
        "project",
        "branch",
        "run_id",
        "engagement_url",
        "tools",
        "counts",
        "blocking_findings",
        "errors",
    ]
    assert data["schema"] == SCHEMA == "labsec.summary/v1"
    assert list(data["counts"]) == ["new", "open", "closed", "blocking"]
    assert list(data["counts"]["blocking"]) == ["critical", "high", "medium", "low", "info"]
    assert data["tools"] == [{"name": "opengrep", "status": "ok", "findings": 4}]


def test_blocking_findings_keep_only_whitelisted_fields():
    data = json.loads(render_json(make()))
    finding = data["blocking_findings"][0]
    assert list(finding) == ["id", "severity", "title", "file", "line", "cwe", "tool"]
    assert "description" not in finding and "mitigation" not in finding


def test_secrets_are_redacted_in_json_and_text():
    leaky = dict(FINDING, title="Leaked ghp_" + "A1b2C3d4E5" * 3 + "ABCDEF in config")
    summary = make(blocking_findings=[leaky], errors=["login failed password=hunter2"])
    for rendered in (render_json(summary), render_text(summary)):
        assert "ghp_" not in rendered
        assert "hunter2" not in rendered


def test_exit_code_ok():
    summary = make(counts={"new": 0, "open": 0, "closed": 0, "blocking": dict.fromkeys(BLOCKING, 0)}, blocking_findings=[])
    assert exit_code(summary) == 0


def test_exit_code_blocking_is_2():
    assert exit_code(make()) == 2


def test_exit_code_tool_failure_is_3_even_with_blocking():
    summary = make(tools=[{"name": "trivy", "status": "failed", "findings": 0}], errors=["trivy: exit 1"])
    assert exit_code(summary) == 3


def test_exit_code_errors_alone_are_3():
    summary = make(blocking_findings=[], counts={"new": 0, "open": 0, "closed": 0, "blocking": dict.fromkeys(BLOCKING, 0)}, errors=["lab down"])
    assert exit_code(summary) == 3


def test_skipped_tools_do_not_fail_the_run():
    summary = make(
        tools=[{"name": "zap", "status": "skipped", "findings": 0, "reason": "no zap target declared"}],
        blocking_findings=[],
        counts={"new": 0, "open": 0, "closed": 0, "blocking": dict.fromkeys(BLOCKING, 0)},
    )
    assert exit_code(summary) == 0
    assert json.loads(render_json(summary))["tools"][0]["reason"] == "no zap target declared"


def test_text_is_short_and_has_the_essentials():
    text = render_text(make())
    assert len(text.splitlines()) <= 14
    assert "demo" in text and "main" in text
    assert "new 4" in text and "open 6" in text and "closed 1" in text
    assert "http://127.0.0.1:19080/engagement/3" in text
    assert "Api/Repo.cs:42" in text
    assert "BLOCKED" in text


def test_invalid_status_is_rejected():
    with pytest.raises(ValueError):
        make(tools=[{"name": "x", "status": "weird", "findings": 0}])
