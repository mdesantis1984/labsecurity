import json

import pytest
from fake_dojo import FakeDojo, finding

from labsec import cli, commands
from labsec.project import resolve_project
from labsec.triage import TAG_FP, TAG_TP

REASON = "Api/Repo.cs:10 - the value is a compile-time constant, never user input"


@pytest.fixture
def dd(monkeypatch, tmp_path):
    monkeypatch.setenv("LABSEC_HOME", str(tmp_path / "labsec-home"))  # reports never touch the real data root
    fake = FakeDojo(
        [
            finding(1, "Critical", "Hard-coded token", cwe=798, test=2, file="deploy/s.txt", line=1),
            finding(2, "High", "SQL built by concatenation", file="Api/Program.cs", line=14),
            finding(3, "High", "Possible SQL injection", file="Api/Repo.cs", line=10, tags=[TAG_TP]),
            finding(4, "Medium", "Missing header", cwe=693),
        ],
        tests={1: {"title": "opengrep", "engagement": 10}, 2: {"title": "gitleaks", "engagement": 10}},
    )
    monkeypatch.setattr(commands, "connect", lambda: fake)
    return fake


def run(capsys, *argv):
    code = cli.main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_findings_text_and_json(dd, capsys):
    code, out, _ = run(capsys, "findings", "demo", "--blocking")
    assert code == 0 and out.splitlines()[0] == "demo: 3 blocking finding(s)"
    code, out, _ = run(capsys, "findings", "demo", "--new", "--untriaged", "--severity", "high,critical", "--json")
    data = json.loads(out)
    assert code == 0 and data["schema"] == "labsec.findings/v1"
    assert [f["id"] for f in data["findings"]] == [1, 2]
    assert data["filter"] == {"view": "new", "severity": ["high", "critical"], "untriaged": True, "limit": 50}


def test_findings_views_are_mutually_exclusive(dd, capsys):
    with pytest.raises(SystemExit) as error:
        cli.main(["findings", "demo", "--new", "--blocking"])
    assert error.value.code == 2


def test_unknown_product_is_exit_1_with_a_message(dd, capsys):
    code, out, err = run(capsys, "findings", "ghost")
    assert code == 1 and out == "" and "no DefectDojo product named 'ghost'" in err
    code, out, _ = run(capsys, "findings", "ghost", "--json")
    assert code == 1 and json.loads(out) == {"schema": "labsec.error/v1", "error": out and json.loads(out)["error"], "exit_code": 1}


def test_report_markdown_json_and_pr_body(dd, capsys):
    code, out, _ = run(capsys, "report", "demo")
    assert code == 0 and out.startswith("## LabSecurity report: demo @ main") and "**BLOCKED**" in out
    code, out, _ = run(capsys, "report", "demo", "--pr-body")
    assert "### Security (LabSecurity)" in out and "deploy/s.txt" not in out
    code, out, _ = run(capsys, "report", "demo", "--json")
    data = json.loads(out)
    assert data["schema"] == "labsec.report/v1" and data["markdown"].startswith("## LabSecurity report")


def test_mark_fp_requires_a_valid_reason_and_confirms(dd, capsys):
    code, out, err = run(capsys, "mark-fp", "2", "--reason", "looks fine")
    assert code == 1 and "file:line" in err and dd.writes() == []
    code, out, _ = run(capsys, "mark-fp", "2", "--reason", REASON)
    assert code == 0 and "marked FALSE POSITIVE: #2 High Api/Program.cs:14" in out and "labsec unmark-fp 2" in out
    assert dd.store[2]["false_p"] is True and TAG_FP in dd.store[2]["tags"]
    code, out, _ = run(capsys, "unmark-fp", "2")
    assert code == 0 and "REVERTED" in out and dd.store[2]["false_p"] is False


def test_mark_fp_has_no_way_to_omit_the_reason(dd, capsys):
    with pytest.raises(SystemExit) as error:
        cli.main(["mark-fp", "2"])
    assert error.value.code == 2 and dd.writes() == []


def test_mark_true_positive_and_to_confirm(dd, capsys):
    code, out, _ = run(capsys, "mark", "2", "--true-positive", "--note", "reachable from the API", "--json")
    data = json.loads(out)
    assert code == 0 and data["schema"] == "labsec.mark/v1" and data["finding"]["triage"] == "true-positive"
    code, out, _ = run(capsys, "mark", "4", "--to-confirm")
    assert code == 0 and "marked TO CONFIRM" in out and dd.store[4]["active"] is True
    with pytest.raises(SystemExit):
        cli.main(["mark", "4"])
    with pytest.raises(SystemExit):
        cli.main(["mark", "4", "--true-positive", "--to-confirm"])


def test_mark_unknown_finding_is_exit_1(dd, capsys):
    code, _, err = run(capsys, "mark", "999", "--true-positive")
    assert code == 1 and "does not exist" in err


def test_verify_closed_exit_codes(dd, capsys):
    dd.store[2].update(active=False, is_mitigated=True)
    code, out, _ = run(capsys, "verify-closed", "demo", "2")
    assert code == 0 and "all findings are mitigated" in out
    code, out, _ = run(capsys, "verify-closed", "demo", "2", "3", "--json")
    assert code == 2 and json.loads(out)["all_mitigated"] is False


def test_tasks_default_is_a_dry_run_in_the_cli(dd, capsys, tmp_path):
    (tmp_path / "demo").mkdir()
    code, out, _ = run(capsys, "tasks", str(tmp_path / "demo"))
    assert code == 0 and "dry-run" in out and "SEC-3" in out
    assert not (tmp_path / "demo" / "odd").exists()


def test_tasks_out_writes_and_close_flow(dd, capsys, tmp_path):
    target = tmp_path / "demo" / "odd" / "tasks" / "security-findings.md"
    (tmp_path / "demo").mkdir()
    code, out, _ = run(capsys, "tasks", str(tmp_path / "demo"), "--out", str(target))
    assert code == 0 and out.startswith("written:") and "SEC-3" in target.read_text()
    code, _, err = run(capsys, "tasks", str(tmp_path / "demo"), "--close", "3", "--commit", "abc1234", "--out", str(target))
    assert code == 2 and "not mitigated" in err and "- [ ] SEC-3" in target.read_text()
    dd.store[3].update(active=False, is_mitigated=True)
    code, out, _ = run(capsys, "tasks", str(tmp_path / "demo"), "--close", "3", "--commit", "abc1234", "--out", str(target))
    assert code == 0 and "task marked done: SEC-3" in out and "- [x] SEC-3" in target.read_text()
    code, _, err = run(capsys, "tasks", str(tmp_path / "demo"), "--close", "3", "--out", str(target))
    assert code == 1 and "--commit" in err


def test_tasks_with_a_slug_needs_an_explicit_file(dd, capsys):
    code, _, err = run(capsys, "tasks", "demo")
    assert code == 1 and "--out" in err


def test_lab_not_configured_is_exit_3(monkeypatch, capsys):
    from labsec.project import LabNotReady

    def broken():
        raise LabNotReady("lab is not configured: run `bin/scan --bootstrap` first")

    monkeypatch.setattr(commands, "connect", broken)
    code, _, err = run(capsys, "findings", "demo")
    assert code == 3 and "lab failure: lab is not configured" in err


def test_dojo_error_is_exit_3(monkeypatch, capsys, dd):
    from labsec.dojo import DojoError

    def down(**filters):
        raise DojoError("DefectDojo unreachable at http://dd.test: ConnectionError")

    dd.findings = down
    code, _, err = run(capsys, "findings", "demo")
    assert code == 3 and "unreachable" in err


# ----------------------------------------------------------------------------- compatibility and resolution
def test_scan_arguments_still_reach_the_scan_parser(capsys):
    with pytest.raises(SystemExit) as error:
        cli.main(["--version"])
    assert error.value.code == 0
    assert capsys.readouterr().out.startswith("labsec ")
    parser = cli.build_parser()
    args = parser.parse_args(["some/path", "--json", "--branch", "main"])
    assert (args.path, args.json, args.branch) == ("some/path", True, "main")


def test_gate_subcommand_is_routed(monkeypatch, capsys):
    import labsec.gate as gate_module

    seen = {}
    monkeypatch.setattr(gate_module, "run_gate", lambda project, as_json, branch: seen.update(p=project, j=as_json, b=branch) or 2)
    assert cli.main(["gate", "my-proj", "--branch", "x", "--json"]) == 2
    assert seen == {"p": "my-proj", "j": True, "b": "x"}


def test_resolve_project_uses_appsec_name_for_directories(tmp_path):
    (tmp_path / "My App").mkdir()
    assert resolve_project(str(tmp_path / "My App")).slug == "my-app"
    (tmp_path / "My App" / ".appsec.yml").write_text("name: Custom Name\n")
    assert resolve_project(str(tmp_path / "My App")).slug == "custom-name"
    assert resolve_project("plain-slug").path is None
    with pytest.raises(Exception):
        resolve_project("../not a slug!")


def test_help_lists_every_subcommand(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    text = capsys.readouterr().out
    for name in commands.SUBCOMMANDS:
        assert name in text
    with pytest.raises(SystemExit):
        commands.build_parser().parse_args(["--help"])
    assert "pre-PR gate" in capsys.readouterr().out
