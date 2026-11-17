import json
import re

import pytest
from fake_dojo import FakeDojo, finding

from labsec import report, triage
from labsec.triage import TAG_CONFIRM, TAG_FP, TAG_TP

REASON = "Api/Repo.cs:10 - the value is a compile-time constant, never user input"


@pytest.fixture
def lab():
    d = FakeDojo(
        [
            finding(1, "Critical", "Hard-coded token", file="deploy/settings.txt", line=1, cwe=798, test=2),
            finding(2, "High", "SQL built by concatenation", file="Api/Program.cs", line=14, cwe=89),
            finding(3, "High", "innerHTML assignment", file="web/app.ts", line=8, cwe=79, tags=[TAG_TP]),
            finding(4, "High", "Possible SQL injection", file="Api/Repo.cs", line=10, test=1),
            finding(5, "Medium", "Missing header", file="web/nginx.conf", line=3, cwe=693),
            finding(6, "High", "Doubtful finding", file="Api/Other.cs", line=5, tags=[TAG_CONFIRM]),
            finding(7, "Low", "Old finding", test=3),
        ],
        tests={
            1: {"title": "opengrep", "engagement": 10},
            2: {"title": "gitleaks", "engagement": 10},
            3: {"title": "opengrep", "engagement": 9},
        },
        engagements=[
            {"id": 9, "product": 1, "name": "main 20261116T100000Z", "branch_tag": "main"},
            {"id": 10, "product": 1, "name": "main 20261117T100000Z", "branch_tag": "main"},
        ],
    )
    triage.mark_false_positive(d, 4, REASON)
    return d


def test_report_counts_and_lists(lab):
    data = report.build_report(lab, "demo")
    assert data["schema"] == "labsec.report/v1"
    assert data["run"] == {"engagement_id": 10, "run_id": "20261117T100000Z", "url": "http://dd.test/engagement/10"}
    assert data["branch"] == "main" and data["tools"] == ["gitleaks", "opengrep"]
    counts = data["counts"]
    assert counts["new"] == 5 and counts["open"] == 6
    assert counts["new_by_severity"] == {"critical": 1, "high": 3, "medium": 1, "low": 0, "info": 0}
    assert counts["blocking"] == {"critical": 1, "high": 3, "medium": 0, "low": 0, "info": 0}
    assert [f["id"] for f in data["blocking"]] == [1, 2, 3, 6]
    assert [f["id"] for f in data["new_critical_high"]] == [1, 2, 3, 6]
    assert [f["id"] for f in data["to_confirm"]] == [6]
    assert counts["true_positives"] == 1 and counts["false_positives"] == 1 and counts["untriaged_new"] == 3
    assert data["blocked"] is True


def test_false_positives_are_listed_with_their_reason_for_review(lab):
    data = report.build_report(lab, "demo")
    assert [(f["id"], f["reason"]) for f in data["false_positives"]] == [(4, REASON)]
    text = report.render_markdown(data)
    assert "Marked false positive (1)" in text and "unmark-fp" in text
    assert f"DD #4 **High** `Api/Repo.cs:10` - {REASON}" in text


def test_markdown_has_everything_s12_asks_for(lab):
    text = report.render_markdown(report.build_report(lab, "demo"))
    assert "## LabSecurity report: demo @ main (run 20261117T100000Z)" in text
    assert "**BLOCKED**: 4 open Critical/High" in text
    assert "| Critical | 1 | 1 | 1 |" in text and "| **Total** | 5 | 6 | 4 |" in text
    assert "### New Critical/High (4)" in text and "### What blocks (4)" in text
    assert "**High** `Api/Program.cs:14` - SQL built by concatenation - SQL injection (DD #2, CWE-89, opengrep)" in text
    assert "http://dd.test/engagement/10" in text
    assert "### To confirm (1)" in text
    assert "3 new finding(s) still need triage" in text


def test_report_never_contains_descriptions_or_payloads(lab):
    data = report.build_report(lab, "demo")
    rendered = json.dumps(data) + report.render_markdown(data) + report.render_pr_body(data)
    assert "EXPLOIT-PAYLOAD" not in rendered


def test_pr_body_drops_paths_of_credential_findings_but_keeps_counts_and_links(lab):
    data = report.build_report(lab, "demo")
    body = report.render_pr_body(data, verdict="BLOCKED")
    assert "deploy/settings.txt" not in body and "Hard-coded token" not in body
    assert "1 credential-related, details only in DefectDojo" in body
    assert "Gate: **BLOCKED**" in body and "| Critical | 1 | 1 | 1 |" in body
    assert "`Api/Program.cs:14` SQL built by concatenation <http://dd.test/finding/2>" in body
    assert "http://dd.test/engagement/10" in body
    assert "False positives marked (with verifiable reasons): 1" in body
    assert REASON not in body


def test_report_for_a_clean_run_is_not_blocked():
    d = FakeDojo([finding(1, "Low", "Style")])
    data = report.build_report(d, "demo")
    text = report.render_markdown(data)
    assert data["blocked"] is False and "**Not blocked**" in text and "- none" in text
    assert "### New Critical/High (0)" in text


def test_run_selection(lab):
    old = report.build_report(lab, "demo", run="20261116T100000Z")
    assert old["run"]["engagement_id"] == 9 and old["counts"]["new"] == 1


def test_lists_are_capped_with_a_pointer_to_the_full_query():
    d = FakeDojo([finding(i, "High", f"Issue {i}", line=i) for i in range(1, 40)])
    text = report.render_markdown(report.build_report(d, "demo"))
    assert "... and 14 more (labsec findings <project> --new --severity critical,high)" in text
    assert "Issue 39" in text and "- plus the 25 listed above" in text  # what blocks lists only the rest


def test_what_blocks_does_not_repeat_the_new_findings_already_listed():
    d = FakeDojo([finding(1, "High", "Issue one")])
    text = report.render_markdown(report.build_report(d, "demo"))
    assert text.count("Issue one") == 1 and "- the 1 finding(s) listed above" in text


def test_report_from_summary_feeds_the_pr_body():
    summary = {
        "project": "demo",
        "branch": "main",
        "run_id": "20261117T100000Z",
        "engagement_url": "http://dd.test/engagement/10",
        "tools": [{"name": "opengrep", "status": "ok", "findings": 2}],
        "counts": {"new": 3, "open": 4, "closed": 1, "blocking": {"critical": 0, "high": 2, "medium": 0, "low": 0, "info": 0}},
        "blocking_findings": [
            {"id": 2, "severity": "High", "title": "SQL built", "file": "Api/P.cs", "line": 3, "cwe": 89, "tool": "opengrep"},
            {"id": 3, "severity": "High", "title": "Leaked key", "file": "deploy/s.txt", "line": 1, "cwe": 798, "tool": "gitleaks"},
        ],
        "errors": [],
    }
    body = report.render_pr_body(report.report_from_summary(summary), verdict="BLOCKED")
    assert "new 3 | open 4 | closed 1 | blocking 2" in body
    assert "`Api/P.cs:3` SQL built" in body
    assert "deploy/s.txt" not in body and "Leaked key" not in body
    assert "http://dd.test/engagement/10" in body


def test_report_json_never_repeats_a_finding_inside_one_list(lab):
    data = report.build_report(lab, "demo")
    for key in ("blocking", "new_critical_high", "to_confirm", "false_positives"):
        ids = [item["id"] for item in data[key]]
        assert len(ids) == len(set(ids)), key


def test_new_critical_high_and_blocking_overlap_by_design_and_markdown_lists_each_once(lab):
    data = report.build_report(lab, "demo")
    blocking = {item["id"] for item in data["blocking"]}
    new_high = {item["id"] for item in data["new_critical_high"]}
    assert blocking & new_high, "the blocking list is the open Critical/High view; a new one appears in both lists"
    text = report.render_markdown(data)
    confirm = {item["id"] for item in data["to_confirm"]}  # those also have their own "To confirm" section
    for finding_id in (blocking | new_high) - confirm:
        assert len(re.findall(rf"DD #{finding_id}\b", text)) == 1, finding_id
