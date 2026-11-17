import json

import pytest
from fake_dojo import FakeDojo, finding

from labsec import tasks, triage
from labsec.project import UsageError
from labsec.triage import TAG_CONFIRM, TAG_FP, TAG_TP

GOOD_REASON = "Api/Repo.cs:10 - the value is a compile-time constant, never user input"


def dojo_with(*findings, **kwargs):
    return FakeDojo(findings, **kwargs)


# ----------------------------------------------------------------------------- reason validation
@pytest.mark.parametrize(
    "reason",
    [
        GOOD_REASON,
        "web/src/app.ts:8-12 sanitized by DomSanitizer before it reaches the template",
        "The query in Program.cs:42 uses only constants so it cannot be influenced",
    ],
)
def test_valid_reasons_are_accepted(reason):
    assert triage.validate_reason(reason).startswith(reason[:10])


@pytest.mark.parametrize(
    "reason, fragment",
    [
        (None, "reason is required"),
        ("", "reason is required"),
        ("it is a false positive, trust me", "file:line"),
        ("Api/Repo.cs - not exploitable because constants", "file:line"),
        ("Api/Repo.cs:10", "explain"),
        ("Api/Repo.cs:10 - fine", "explain"),
        ("x" * 600 + " Api/Repo.cs:10", "too long"),
    ],
)
def test_invalid_reasons_are_rejected(reason, fragment):
    with pytest.raises(UsageError) as error:
        triage.validate_reason(reason)
    assert fragment in str(error.value)


def test_reason_is_redacted_before_it_is_stored():
    text = triage.validate_reason("Api/Repo.cs:10 - password=hunter2 is only a placeholder in this test file")
    assert "hunter2" not in text


# ----------------------------------------------------------------------------- classification
def test_triage_state_precedence():
    assert triage.triage_state(finding(1)) == "untriaged"
    assert triage.triage_state(finding(1, tags=[TAG_TP])) == "true-positive"
    assert triage.triage_state(finding(1, tags=[TAG_CONFIRM])) == "to-confirm"
    assert triage.triage_state(finding(1, false_p=True)) == "false-positive"
    assert triage.triage_state(finding(1, false_p=True, tags=[TAG_TP])) == "false-positive"
    assert triage.triage_state(finding(1, risk_accepted=True, false_p=True)) == "risk-accepted"


def test_human_reverting_an_agent_mark_is_a_disagreement_not_a_new_finding():
    assert triage.triage_state(finding(1, tags=[TAG_FP], false_p=False)) == "to-confirm"


def test_blocking_excludes_false_positive_accepted_risk_duplicates_and_medium():
    assert triage.is_blocking(finding(1, severity="Critical"))
    assert triage.is_blocking(finding(1, severity="High"))
    assert not triage.is_blocking(finding(1, severity="Medium"))
    assert not triage.is_blocking(finding(1, false_p=True))
    assert not triage.is_blocking(finding(1, risk_accepted=True))
    assert not triage.is_blocking(finding(1, duplicate=True))
    assert not triage.is_blocking(finding(1, active=False))


# ----------------------------------------------------------------------------- listing
@pytest.fixture
def lab():
    return dojo_with(
        finding(1, "Critical"),
        finding(2, "High", tags=[TAG_TP]),
        finding(3, "Medium"),
        finding(4, "High", false_p=True, active=False, tags=[TAG_FP]),
        finding(5, "Low", tags=[TAG_CONFIRM]),
        finding(6, "High", risk_accepted=True, active=False),
        finding(7, "High", duplicate=True),
        finding(8, "High", test=2),  # old run
        tests={1: {"title": "opengrep", "engagement": 10}, 2: {"title": "trivy", "engagement": 9}},
        engagements=[
            {"id": 9, "product": 1, "name": "main 20261116T100000Z", "branch_tag": "main"},
            {"id": 10, "product": 1, "name": "main 20261117T100000Z", "branch_tag": "main"},
        ],
    )


def ids(data):
    return [f["id"] for f in data["findings"]]


def test_open_view_is_active_and_not_duplicate_ordered_by_severity(lab):
    data = triage.list_findings(lab, "demo", view="open")
    assert ids(data) == [1, 2, 8, 3, 5]
    assert data["total"] == 5 and data["returned"] == 5
    assert data["schema"] == "labsec.findings/v1"


def test_new_view_is_the_latest_engagement_only(lab):
    assert ids(triage.list_findings(lab, "demo", view="new")) == [1, 2, 3, 5]
    assert ids(triage.list_findings(lab, "demo", view="new", run="9")) == [8]
    assert ids(triage.list_findings(lab, "demo", view="new", run="20261116T100000Z")) == [8]


def test_blocking_view_is_open_critical_high_without_fp_or_accepted(lab):
    assert ids(triage.list_findings(lab, "demo", view="blocking")) == [1, 2, 8]


def test_untriaged_filter_skips_everything_already_classified(lab):
    data = triage.list_findings(lab, "demo", view="open", untriaged=True)
    assert ids(data) == [1, 8, 3]  # 2 is a true positive, 5 is to-confirm


def test_false_positive_is_not_listed_as_new_blocking_or_untriaged(lab):
    for view in ("new", "open", "blocking"):
        assert 4 not in ids(triage.list_findings(lab, "demo", view=view))
        assert 4 not in ids(triage.list_findings(lab, "demo", view=view, untriaged=True))


def test_severity_filter_and_limit(lab):
    data = triage.list_findings(lab, "demo", view="open", severities=["Critical", "High"], limit=2)
    assert ids(data) == [1, 2] and data["total"] == 3 and data["returned"] == 2
    text = triage.render_findings_text(data)
    assert "1 more" in text


def test_compact_item_has_the_whitelisted_fields_and_no_description(lab):
    data = triage.list_findings(lab, "demo", view="blocking")
    item = data["findings"][0]
    assert list(item) == ["id", "severity", "title", "file", "line", "cwe", "rule", "tool", "status", "triage", "url"]
    assert item["url"] == "http://dd.test/finding/1"
    assert item["tool"] == "opengrep"
    for rendered in (json.dumps(data), triage.render_findings_text(data)):
        assert "EXPLOIT-PAYLOAD" not in rendered


def test_text_line_has_location_cwe_tool_and_triage(lab):
    line = triage.render_findings_text(triage.list_findings(lab, "demo", view="blocking")).splitlines()[1]
    assert line.startswith("#1 Critical Api/Repo.cs:10 SQL built by concatenation [opengrep, CWE-89] triage=untriaged")


def test_unknown_product_and_severity_are_usage_errors(lab):
    with pytest.raises(UsageError):
        triage.list_findings(lab, "nope")
    with pytest.raises(UsageError):
        triage.parse_severities("urgent")
    assert triage.parse_severities("Critical, high") == ["Critical", "High"]


# ----------------------------------------------------------------------------- mark false positive
def test_mark_fp_sets_flags_tag_and_note_with_reason():
    d = dojo_with(finding(1, verified=True, tags=["other"]))
    result = triage.mark_false_positive(d, 1, GOOD_REASON)
    stored = d.store[1]
    assert stored["false_p"] is True and stored["active"] is False and stored["verified"] is False
    assert stored["tags"] == ["other", TAG_FP]
    assert GOOD_REASON in d.notes_store[1][0]["entry"] and "unmark-fp 1" in d.notes_store[1][0]["entry"]
    assert result["changed"] and result["finding"]["triage"] == "false-positive"
    # the note is written before the status changes: a false positive without a reason can never exist
    order = [(m, p) for m, p, _ in d.writes()]
    assert order == [("POST", "/api/v2/findings/1/notes/"), ("PATCH", "/api/v2/findings/1/")]
    assert "risk" not in json.dumps(d.writes())


def test_mark_fp_without_valid_reason_changes_nothing():
    d = dojo_with(finding(1))
    for reason in (None, "not exploitable", "Api/Repo.cs:10"):
        with pytest.raises(UsageError):
            triage.mark_false_positive(d, 1, reason)
    assert d.writes() == [] and d.store[1]["false_p"] is False and d.store[1]["active"] is True


def test_mark_fp_is_idempotent_and_adds_no_second_note():
    d = dojo_with(finding(1))
    triage.mark_false_positive(d, 1, GOOD_REASON)
    again = triage.mark_false_positive(d, 1, GOOD_REASON)
    assert again["changed"] is False and len(d.notes_store[1]) == 1


def test_mark_fp_unknown_finding():
    with pytest.raises(UsageError) as error:
        triage.mark_false_positive(dojo_with(), 99, GOOD_REASON)
    assert "does not exist" in str(error.value)


def test_mark_fp_never_touches_a_risk_accepted_finding():
    d = dojo_with(finding(1, risk_accepted=True, active=False))
    with pytest.raises(UsageError) as error:
        triage.mark_false_positive(d, 1, GOOD_REASON)
    assert "risk-accepted by a human reviewer" in str(error.value)
    assert d.writes() == []


def test_mark_fp_replaces_a_previous_verdict_tag():
    d = dojo_with(finding(1, tags=[TAG_TP]))
    triage.mark_false_positive(d, 1, GOOD_REASON)
    assert d.store[1]["tags"] == [TAG_FP]


# ----------------------------------------------------------------------------- unmark
def test_unmark_fp_reverts_only_what_labsecurity_marked():
    d = dojo_with(finding(1))
    triage.mark_false_positive(d, 1, GOOD_REASON)
    result = triage.unmark_false_positive(d, 1)
    stored = d.store[1]
    assert stored["false_p"] is False and stored["active"] is True and TAG_FP not in stored["tags"]
    assert result["changed"] and result["finding"]["triage"] == "untriaged"
    assert "reverted" in d.notes_store[1][-1]["entry"]


def test_unmark_fp_refuses_a_false_positive_a_human_set_in_the_ui():
    d = dojo_with(finding(1, false_p=True, active=False))
    with pytest.raises(UsageError) as error:
        triage.unmark_false_positive(d, 1)
    assert "not marked by LabSecurity" in str(error.value)
    assert d.writes() == []


def test_unmark_fp_reopens_even_though_defectdojo_flagged_it_mitigated():
    d = dojo_with(finding(1, false_p=True, active=False, is_mitigated=True, tags=[TAG_FP]))
    triage.unmark_false_positive(d, 1)
    assert d.store[1]["false_p"] is False and d.store[1]["active"] is True and d.store[1]["is_mitigated"] is False


def test_marking_false_positive_then_unmarking_never_reads_as_mitigated():
    d = dojo_with(finding(1))
    triage.mark_false_positive(d, 1, GOOD_REASON)
    assert d.store[1]["is_mitigated"] is True  # what DefectDojo does on deactivation
    triage.unmark_false_positive(d, 1)
    assert tasks.verify_one(d, 1)["state"] == "open"


def test_reverted_false_positive_returns_to_the_lists_and_is_classified():
    d = dojo_with(finding(1))
    triage.mark_false_positive(d, 1, GOOD_REASON)
    assert triage.list_findings(d, "demo", view="open")["total"] == 0
    triage.unmark_false_positive(d, 1)
    assert triage.list_findings(d, "demo", view="blocking")["total"] == 1


# ----------------------------------------------------------------------------- true positive / to confirm
def test_mark_true_positive_adds_tag_and_note_without_changing_status():
    d = dojo_with(finding(1, tags=[TAG_CONFIRM]))
    result = triage.mark_true_positive(d, 1, "reachable from the public endpoint")
    assert d.store[1]["tags"] == [TAG_TP]
    assert d.store[1]["active"] is True and d.store[1]["false_p"] is False
    assert "TRUE POSITIVE" in d.notes_store[1][0]["entry"] and "reachable" in d.notes_store[1][0]["entry"]
    assert result["finding"]["triage"] == "true-positive"
    assert triage.mark_true_positive(d, 1)["changed"] is False


def test_mark_to_confirm_is_tag_only():
    d = dojo_with(finding(1))
    result = triage.mark_to_confirm(d, 1)
    assert d.store[1]["tags"] == [TAG_CONFIRM]
    assert d.writes() == [("PATCH", "/api/v2/findings/1/", {"tags": [TAG_CONFIRM]})]
    assert result["finding"]["triage"] == "to-confirm"
    assert d.notes_store == {}


@pytest.mark.parametrize("fn", [triage.mark_true_positive, triage.mark_to_confirm])
def test_marks_refuse_false_positives_and_risk_accepted(fn):
    with pytest.raises(UsageError):
        fn(dojo_with(finding(1, false_p=True)), 1)
    with pytest.raises(UsageError):
        fn(dojo_with(finding(1, risk_accepted=True)), 1)


def test_to_confirm_findings_stay_listed_but_count_as_classified():
    d = dojo_with(finding(1))
    triage.mark_to_confirm(d, 1)
    assert triage.list_findings(d, "demo", view="open")["total"] == 1
    assert triage.list_findings(d, "demo", view="open", untriaged=True)["total"] == 0


def test_render_mark_text_has_reason_and_revert_hint():
    d = dojo_with(finding(1))
    text = triage.render_mark_text(triage.mark_false_positive(d, 1, GOOD_REASON))
    assert "marked FALSE POSITIVE: #1 High Api/Repo.cs:10" in text
    assert GOOD_REASON in text and "labsec unmark-fp 1" in text
    again = triage.render_mark_text(triage.mark_false_positive(d, 1, GOOD_REASON))
    assert again.startswith("no change")


def test_reason_of_reads_back_the_stored_reason():
    d = dojo_with(finding(1))
    triage.mark_false_positive(d, 1, GOOD_REASON)
    assert triage.reason_of(d, 1) == GOOD_REASON
    assert triage.reason_of(dojo_with(finding(2)), 2) is None
