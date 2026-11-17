import pytest
from fake_dojo import FakeDojo, finding

from labsec import knowledge, tasks, triage
from labsec.project import UsageError
from labsec.triage import TAG_TP

TP = [TAG_TP]


@pytest.fixture
def lab():
    return FakeDojo(
        [
            finding(1, "Low", "Weak hash", file="Api/Hash.cs", line=3, cwe=327, tags=TP),
            finding(2, "Critical", "Hard-coded token", file="deploy/s.txt", line=1, cwe=798, tags=TP, test=2),
            finding(3, "High", "SQL built by concatenation", file="Api/Program.cs", line=14, cwe=89, tags=TP),
            finding(4, "High", "innerHTML assignment", file="web/app.ts", line=8, cwe=79, tags=TP),
            finding(5, "Medium", "CVE-2020-8203 lodash", file="web/package-lock.json", line=None, cwe=1104, tags=TP, test=3,
                    mitigation="Upgrade lodash to 4.17.21"),
            finding(6, "High", "Not confirmed yet"),
            finding(7, "High", "Already fixed", tags=TP, active=False, is_mitigated=True),
            finding(8, "High", "Dup", tags=TP, duplicate=True),
            finding(9, "High", "Marked fp", tags=TP, false_p=True, active=False),
        ],
        tests={
            1: {"title": "opengrep", "engagement": 10},
            2: {"title": "gitleaks", "engagement": 10},
            3: {"title": "trivy", "engagement": 10},
        },
    )


def task_ids(text):
    return [int(i) for i in __import__("re").findall(r"<!-- labsec:task id=(\d+) ", text)]


# ----------------------------------------------------------------------------- selection and order
def test_only_active_confirmed_true_positives_become_tasks_ordered_critical_first(lab):
    views = tasks.true_positives(lab, "demo")
    assert [v["id"] for v in views] == [2, 3, 4, 5, 1]
    assert [v["severity"] for v in views] == ["Critical", "High", "High", "Medium", "Low"]


def test_document_orders_critical_high_medium_low(lab):
    text, added, kept = tasks.merge_document(None, tasks.true_positives(lab, "demo"))
    assert task_ids(text) == [2, 3, 4, 5, 1] and added == [2, 3, 4, 5, 1] and kept == []


# ----------------------------------------------------------------------------- task content (S14)
def render(lab, fid):
    return tasks.render_task(next(v for v in tasks.true_positives(lab, "demo") if v["id"] == fid))


def test_task_carries_every_field_s14_requires(lab):
    text = render(lab, 3)
    assert text.startswith("- [ ] SEC-3 - High - SQL built by concatenation - SQL injection - `Api/Program.cs:14`")
    assert "DefectDojo finding: #3 <http://dd.test/finding/3>" in text
    assert "Severity: High (blocks the PR)" in text
    assert "Location: `Api/Program.cs:14` (opengrep)" in text
    assert "Rule / CWE: CWE-89 (SQL injection)" in text
    assert "FromSqlInterpolated" in text and "NpgsqlParameter" in text
    assert "first write a test that fails and reproduces the problem, then apply the fix" in text
    assert "Authorization: check project rules before fixing (e.g. backend changes may need owner approval)." in text
    assert "/bin/scan <project>`" in text and "labsec verify-closed <project> 3" in text
    assert "--close 3 --commit <sha> --out <this file>" in text


def test_fix_templates_per_class(lab):
    assert "innerHTML" in render(lab, 4) and "sanitize" in render(lab, 4)
    secret = render(lab, 2)
    assert "rotate" in secret.lower() and "history" in secret
    dep = render(lab, 5)
    assert "Upgrade the component to the fixed version" in dep and "Reported remediation: Upgrade lodash to 4.17.21" in dep
    assert "Severity: Medium" in dep and "blocks the PR" not in dep


def test_description_and_payloads_never_reach_a_task(lab):
    text, _, _ = tasks.merge_document(None, tasks.true_positives(lab, "demo"))
    assert "EXPLOIT-PAYLOAD" not in text


@pytest.mark.parametrize(
    "view, expected",
    [
        ({"tool": "opengrep", "cwe": 79, "title": "x"}, "xss"),
        ({"tool": "opengrep", "cwe": None, "rule": "angular-innerhtml", "title": "x"}, "xss"),
        ({"tool": "opengrep", "cwe": None, "title": "Use of eval"}, "eval"),
        ({"tool": "dotnet-analyzers", "cwe": None, "rule": "CA3001", "title": "Review code for SQL injection"}, "sql"),
        ({"tool": "gitleaks", "cwe": None, "title": "github-pat"}, "secret"),
        ({"tool": "sonarqube", "cwe": 798, "title": "Hard-coded"}, "secret"),
        ({"tool": "trivy", "cwe": 1104, "title": "CVE-2021-1 lib"}, "dependency"),
        ({"tool": "trivy", "cwe": None, "title": "AVD-DS-0002 Image user should not be root"}, "misconfig"),
        ({"tool": "opengrep", "cwe": None, "title": "something odd"}, "generic"),
    ],
)
def test_category_selection(view, expected):
    assert knowledge.category(view) == expected


# ----------------------------------------------------------------------------- idempotency and human edits
def test_merge_is_idempotent_and_never_duplicates(lab):
    views = tasks.true_positives(lab, "demo")
    once, _, _ = tasks.merge_document(None, views)
    twice, added, kept = tasks.merge_document(once, views)
    assert twice == once and added == [] and sorted(kept) == [1, 2, 3, 4, 5]
    assert once.count("<!-- labsec:task id=3 ") == 1


def test_new_findings_are_added_in_order_and_existing_text_is_kept(lab):
    views = tasks.true_positives(lab, "demo")
    first, _, _ = tasks.merge_document(None, views[1:])  # without the critical one
    edited = first.replace("- [ ] SEC-3", "- [ ] SEC-3 (owner: ask Marco before touching)")
    edited = edited.replace("# Security findings", "# Security findings\n\nMy own intro paragraph.")
    edited += "\n## Notes\nhuman notes outside the markers\n"
    merged, added, kept = tasks.merge_document(edited, views)
    assert added == [2] and sorted(kept) == [1, 3, 4, 5]
    assert "(owner: ask Marco before touching)" in merged
    assert "My own intro paragraph." in merged and "human notes outside the markers" in merged
    assert task_ids(merged) == [2, 3, 4, 5, 1]
    assert tasks.merge_document(merged, views)[0] == merged


def test_a_ticked_task_stays_ticked_on_regeneration(lab):
    views = tasks.true_positives(lab, "demo")
    text, _, _ = tasks.merge_document(None, views)
    ticked, changed = tasks.close_in_document(text, 3, "abcdef1", "2026-11-17")
    assert changed
    again, _, _ = tasks.merge_document(ticked, views)
    assert again == ticked and "- [x] SEC-3" in again


def test_block_goes_before_the_log_of_an_odd_feature_doc(lab):
    doc = "# Feature\n\n## Specs\nS1\n\n## Tasks\n- [ ] T1\n\n## Log\nL1 something\n"
    merged, _, _ = tasks.merge_document(doc, tasks.true_positives(lab, "demo"))
    assert merged.index("labsec:tasks:begin") < merged.index("## Log") and merged.endswith("L1 something\n")
    assert merged.startswith("# Feature\n\n## Specs")


def test_file_without_log_gets_the_block_appended(lab):
    merged, _, _ = tasks.merge_document("# Notes\ntext\n", tasks.true_positives(lab, "demo"))
    assert merged.startswith("# Notes\ntext\n\n<!-- labsec:tasks:begin")


# ----------------------------------------------------------------------------- writing policy
def test_default_is_a_dry_run_that_writes_nothing(lab, tmp_path):
    result = tasks.generate(lab, "demo", tmp_path)
    assert result["mode"] == "dry-run" and result["target"] == str(tmp_path / "odd/tasks/security-findings.md")
    assert not (tmp_path / "odd").exists()
    assert "labsec:task id=3" in result["content"]
    assert "nothing written" in tasks.render_generate_text(result, with_content=False)


def test_out_writes_and_dry_run_flag_still_wins(lab, tmp_path):
    out = tmp_path / "odd" / "tasks" / "security-findings.md"
    dry = tasks.generate(lab, "demo", tmp_path, out=str(out), dry_run=True)
    assert dry["mode"] == "dry-run" and not out.exists()
    written = tasks.generate(lab, "demo", tmp_path, out=str(out))
    assert written["mode"] == "written" and out.read_text() == written["content"]
    again = tasks.generate(lab, "demo", tmp_path, out=str(out))
    assert again["added"] == [] and again["changed"] is False and out.read_text() == written["content"]


def test_default_path_is_read_for_the_dry_run_but_never_written(lab, tmp_path):
    default = tmp_path / "odd" / "tasks" / "security-findings.md"
    default.parent.mkdir(parents=True)
    default.write_text("# mine\n")
    result = tasks.generate(lab, "demo", tmp_path)
    assert result["content"].startswith("# mine\n") and default.read_text() == "# mine\n"


def test_feature_doc_is_an_explicit_target(lab, tmp_path):
    doc = tmp_path / "feature.md"
    doc.write_text("# F\n\n## Log\nL1\n")
    result = tasks.generate(lab, "demo", None, feature_doc=str(doc))
    assert result["mode"] == "written" and doc.read_text().count("<!-- labsec:task id=") == 5
    with pytest.raises(UsageError):
        tasks.generate(lab, "demo", None, feature_doc=str(tmp_path / "missing.md"))


# ----------------------------------------------------------------------------- closing the cycle (S15)
def seeded_doc(lab, tmp_path):
    path = tmp_path / "tasks.md"
    tasks.generate(lab, "demo", tmp_path, out=str(path))
    return path


def test_close_refuses_while_the_finding_is_not_mitigated(lab, tmp_path):
    path = seeded_doc(lab, tmp_path)
    before = path.read_text()
    with pytest.raises(tasks.TaskNotClosable) as error:
        tasks.close_task(lab, "demo", 3, "abcdef1", path, dry_run=False, explicit=True)
    assert "is open in DefectDojo, not mitigated" in str(error.value)
    assert path.read_text() == before


@pytest.mark.parametrize("fid, state", [(9, "false-positive"), (99, "not-found")])
def test_close_refuses_other_states(lab, tmp_path, fid, state):
    with pytest.raises(tasks.TaskNotClosable) as error:
        tasks.close_task(lab, "demo", fid, "abcdef1", seeded_doc(lab, tmp_path), dry_run=False, explicit=True)
    assert state in str(error.value)


def test_close_ticks_the_task_with_the_commit_once_mitigated(lab, tmp_path):
    path = seeded_doc(lab, tmp_path)
    lab.store[3].update(active=False, is_mitigated=True, mitigated="2026-11-17T12:00:00Z")
    result = tasks.close_task(lab, "demo", 3, "ABCDEF1234", path, dry_run=False, explicit=True)
    text = path.read_text()
    assert result["closed"] == 3 and result["commit"] == "abcdef1234"
    assert "- [x] SEC-3 - High" in text and "- [ ] SEC-4" in text
    assert "Done: fix commit abcdef1234; DefectDojo shows the finding as mitigated" in text
    again = tasks.close_task(lab, "demo", 3, "abcdef1234", path, dry_run=False, explicit=True)
    assert again["already_closed"] and path.read_text() == text


def test_close_without_explicit_target_or_with_dry_run_writes_nothing(lab, tmp_path):
    path = seeded_doc(lab, tmp_path)
    before = path.read_text()
    lab.store[3].update(active=False, is_mitigated=True)
    assert tasks.close_task(lab, "demo", 3, "abcdef1", path, dry_run=True, explicit=True)["mode"] == "dry-run"
    assert tasks.close_task(lab, "demo", 3, "abcdef1", path, dry_run=False, explicit=False)["mode"] == "dry-run"
    assert path.read_text() == before


@pytest.mark.parametrize("sha", ["", "zzzzzzz", "abc", "abcdef1; rm", None])
def test_close_validates_the_commit(lab, tmp_path, sha):
    with pytest.raises(UsageError):
        tasks.close_task(lab, "demo", 3, sha, seeded_doc(lab, tmp_path), dry_run=False, explicit=True)


def test_close_unknown_task_in_document(lab, tmp_path):
    path = seeded_doc(lab, tmp_path)
    lab.store[6].update(active=False, is_mitigated=True)
    with pytest.raises(UsageError) as error:
        tasks.close_task(lab, "demo", 6, "abcdef1", path, dry_run=False, explicit=True)
    assert "no LabSecurity task for DefectDojo finding 6" in str(error.value)


def test_verify_closed_reports_each_state(lab):
    lab.store[3].update(active=False, is_mitigated=True, mitigated="2026-11-17T12:00:00Z")
    data = tasks.verify_closed(lab, "demo", [3, 4, 9, 99])
    assert data["schema"] == "labsec.verify/v1" and data["all_mitigated"] is False
    assert [(r["id"], r["state"]) for r in data["results"]] == [(3, "mitigated"), (4, "open"), (9, "false-positive"), (99, "not-found")]
    assert tasks.verify_closed(lab, "demo", [3])["all_mitigated"] is True
    text = tasks.render_verify_text(data)
    assert "NOT all findings are mitigated" in text and "#3 mitigated Api/Program.cs:14 (High)" in text
