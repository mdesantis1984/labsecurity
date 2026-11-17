"""Policy: accepting a risk is a human decision; an agent never accepts one on its own.

No command or code path may create a risk acceptance or set `risk_accepted`.
"""

import ast
import json
from pathlib import Path

import pytest
from fake_dojo import FakeDojo, finding

from labsec import tasks, triage
from labsec.dojo import DojoClient, DojoError, guard_no_risk_acceptance

PACKAGE = Path(__file__).resolve().parents[2] / "labsec"
SOURCES = sorted(PACKAGE.glob("*.py"))


def _is_false_literal(node) -> bool:
    return isinstance(node, ast.Constant) and (node.value is False or str(node.value).lower() == "false")


def _is_read(node) -> bool:
    """`bool(finding.get("risk_accepted"))`: a projection of what DefectDojo says, not a write."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "bool"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Call)
        and isinstance(node.args[0].func, ast.Attribute)
        and node.args[0].func.attr == "get"
    )


def test_source_never_writes_risk_acceptance_fields_or_endpoints():
    offenders = []
    for source in SOURCES:
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values):
                    if isinstance(key, ast.Constant) and str(key.value).startswith("risk_accept") and not _is_false_literal(value) and not _is_read(value):
                        offenders.append(f"{source.name}:{node.lineno} dict key {key.value!r}")
            if isinstance(node, ast.keyword) and node.arg and node.arg.startswith("risk_accept") and not _is_false_literal(node.value):
                offenders.append(f"{source.name}:{node.value.lineno} keyword {node.arg}")
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                text = node.value.lower()
                if "risk_acceptance" in text or "accept_risks" in text or "/risk_accept" in text:
                    offenders.append(f"{source.name}:{node.lineno} string {node.value!r}")
            if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and str(node.slice.value).startswith("risk_accept"):
                if isinstance(node.ctx, ast.Store):
                    offenders.append(f"{source.name}:{node.lineno} subscript assignment")
    assert offenders == []


def test_source_exposes_no_command_that_accepts_risk():
    from labsec.commands import SUBCOMMANDS, build_parser

    assert not [name for name in SUBCOMMANDS if "risk" in name or "accept" in name]
    help_text = build_parser().format_help().lower()
    assert "accept-risk" not in help_text and "risk-accept" not in help_text.replace("risk accepted", "")


@pytest.mark.parametrize("method", ["POST", "PATCH", "PUT", "DELETE"])
def test_client_refuses_risk_acceptance_endpoints_before_any_network_call(method):
    client = DojoClient("http://127.0.0.1:1", "t")  # nothing listens here: the guard must fire first
    with pytest.raises(DojoError) as error:
        client._request(method, "/api/v2/risk_acceptance/", json={})
    assert "never creates or changes risk acceptances" in str(error.value)
    with pytest.raises(DojoError):
        client._request(method, "/api/v2/findings/5/accept_risks/", json={})


@pytest.mark.parametrize("payload", [{"risk_accepted": True}, {"risk_accepted": False}, {"risk_acceptance": 1}])
def test_client_refuses_to_write_risk_fields(payload):
    client = DojoClient("http://127.0.0.1:1", "t")
    with pytest.raises(DojoError):
        client.update_finding(1, payload)
    with pytest.raises(DojoError):
        client._request("PATCH", "/api/v2/findings/1/", json=payload)
    with pytest.raises(DojoError):
        guard_no_risk_acceptance("POST", "/api/v2/findings/", payload)


def test_update_finding_only_allows_triage_fields():
    client = DojoClient("http://127.0.0.1:1", "t")
    with pytest.raises(DojoError) as error:
        client.update_finding(1, {"severity": "Info"})
    assert "not part of LabSecurity triage" in str(error.value)


def test_reads_may_mention_risk_accepted():
    guard_no_risk_acceptance("GET", "/api/v2/findings/", {"risk_accepted": "false"})


def test_every_triage_and_task_operation_leaves_risk_accepted_untouched():
    d = FakeDojo([finding(1), finding(2), finding(3, tags=[triage.TAG_TP]), finding(4, false_p=True, active=False, tags=[triage.TAG_FP])])
    reason = "Api/Repo.cs:10 - the value is a compile-time constant, never user input"
    triage.mark_false_positive(d, 1, reason)
    triage.unmark_false_positive(d, 1)
    triage.mark_true_positive(d, 2, "confirmed")
    triage.mark_to_confirm(d, 1)
    triage.unmark_false_positive(d, 4)
    tasks.generate(d, "demo", None, out=None, dry_run=True)
    tasks.verify_closed(d, "demo", [1, 2, 3])
    assert d.writes(), "the scenario must have written something"
    for method, path, payload in d.writes():
        assert "risk_accept" not in path
        assert "risk_accept" not in json.dumps(payload)
    assert all(f["risk_accepted"] is False for f in d.store.values())


def test_a_risk_accepted_finding_is_never_modified_by_any_command():
    d = FakeDojo([finding(1, risk_accepted=True, active=False)])
    for call in (
        lambda: triage.mark_false_positive(d, 1, "Api/Repo.cs:10 - constant value only"),
        lambda: triage.unmark_false_positive(d, 1),
        lambda: triage.mark_true_positive(d, 1),
        lambda: triage.mark_to_confirm(d, 1),
    ):
        with pytest.raises(Exception):
            call()
    assert d.writes() == [] and d.store[1]["risk_accepted"] is True
