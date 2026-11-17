"""Data layout (decisions A7/A8): one data root per user, per-OS defaults, LABSEC_HOME, report folders."""

import json
import os
import re
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fake_dojo import FakeDojo, finding

from labsec import cli, commands
from labsec.config import Paths, default_dirs, repo_folder

HOME = Path("/srv/users/ana")
ROOT = Path(__file__).resolve().parents[2]


# -- per-OS defaults ---------------------------------------------------------------------------------------------
def test_linux_defaults_keep_the_locations_earlier_versions_used():
    dirs = default_dirs({}, HOME, "linux")
    assert dirs == {
        "data": HOME / ".local/share/labsecurity",
        "config": HOME / ".config/labsecurity",
        "cache": HOME / ".cache/labsecurity",
        "state": HOME / ".local/state/labsecurity",
    }


def test_xdg_variables_move_the_linux_directories_and_relative_values_are_ignored():
    env = {"XDG_DATA_HOME": "/srv/data", "XDG_CONFIG_HOME": "/srv/cfg", "XDG_CACHE_HOME": "relative/cache", "XDG_STATE_HOME": ""}
    dirs = default_dirs(env, HOME, "linux")
    assert dirs["data"] == Path("/srv/data/labsecurity") and dirs["config"] == Path("/srv/cfg/labsecurity")
    assert dirs["cache"] == HOME / ".cache/labsecurity" and dirs["state"] == HOME / ".local/state/labsecurity"


def test_macos_keeps_everything_under_application_support():
    base = Path("/Users/ana/Library/Application Support/LabSecurity")
    dirs = default_dirs({"XDG_DATA_HOME": "/ignored"}, Path("/Users/ana"), "darwin")
    assert dirs == {"data": base, "config": base / "config", "cache": base / "cache", "state": base / "state"}


def test_labsec_home_wins_on_every_os_and_expands_the_tilde():
    for system in ("linux", "darwin"):
        dirs = default_dirs({"LABSEC_HOME": "~/lab"}, HOME, system)
        assert dirs["data"] == HOME / "lab"
        assert dirs["config"] == dirs["data"] / "config" and dirs["state"] == dirs["data"] / "state"


def test_explicit_directory_variables_still_override_the_defaults():
    paths = Paths.from_env({"LABSEC_HOME": "/lab", "LABSEC_CONFIG_DIR": "/cfg-dir"}, HOME, "linux")
    assert paths.config_dir == Path("/cfg-dir") and paths.data_dir == Path("/lab")
    assert paths.reports_dir == Path("/lab/reports") and paths.backups_dir == Path("/lab/backups")
    assert paths.lock_path == Path("/lab/state/heavy.lock") and paths.work_dir("api") == Path("/lab/cache/work/api")
    assert paths.run_dir("api", "r1") == Path("/lab/runs/api/r1")


@pytest.mark.parametrize(
    "env,system",
    [({}, "Linux"), ({"XDG_DATA_HOME": "/x/d", "XDG_STATE_HOME": "/x/s"}, "Linux"), ({"LABSEC_HOME": "~/lab"}, "Linux"), ({}, "Darwin")],
)
def test_the_shell_helper_and_the_python_defaults_agree(tmp_path, env, system):
    """scripts/lib/paths.sh (init.sh, backup.sh) must resolve the same directories as labsec.config."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    uname = fake_bin / "uname"
    uname.write_text(f"#!/bin/sh\necho {system}\n")
    uname.chmod(0o755)
    full_env = {"PATH": f"{fake_bin}:{os.environ['PATH']}", "HOME": str(tmp_path / "home"), **env}
    script = '. "$1"; labsec_resolve_paths; printf "%s\\n" "$LABSEC_DATA_DIR" "$LABSEC_CONFIG_DIR" "$LABSEC_CACHE_DIR" "$LABSEC_STATE_DIR"'
    out = subprocess.run(["bash", "-c", script, "x", str(ROOT / "scripts/lib/paths.sh")], env=full_env, capture_output=True, text=True, check=True)
    expected = default_dirs(full_env, tmp_path / "home", system.lower())
    assert out.stdout.splitlines() == [str(expected[k]) for k in ("data", "config", "cache", "state")]


# -- report folders ----------------------------------------------------------------------------------------------
def test_repo_folder_is_name_plus_six_hex_chars_of_the_absolute_path(tmp_path):
    a, b = tmp_path / "one" / "api", tmp_path / "two" / "api"
    a.mkdir(parents=True), b.mkdir(parents=True)
    fa, fb = repo_folder("api", a), repo_folder("api", b)
    assert re.fullmatch(r"api-[0-9a-f]{6}", fa) and re.fullmatch(r"api-[0-9a-f]{6}", fb)
    assert fa != fb and fa == repo_folder("api", a)


def test_new_report_dir_is_private_and_uses_the_utc_timestamp(tmp_path):
    paths = Paths.from_env({"LABSEC_HOME": str(tmp_path / "home")}, HOME, "linux")
    repo = tmp_path / "api"
    repo.mkdir()
    target = paths.new_report_dir("api", repo, datetime(2026, 11, 17, 9, 8, 7, tzinfo=timezone.utc))
    assert target == tmp_path / "home" / "reports" / repo_folder("api", repo) / "20261117T090807Z"
    assert stat.S_IMODE(target.stat().st_mode) == 0o700 and stat.S_IMODE(target.parent.stat().st_mode) == 0o700


def test_a_slug_alone_reuses_the_single_existing_folder_of_that_repo(tmp_path):
    paths = Paths.from_env({"LABSEC_HOME": str(tmp_path / "home")}, HOME, "linux")
    repo = tmp_path / "api"
    repo.mkdir()
    first = paths.new_report_dir("api", repo)
    assert paths.repo_reports_dir("api", None) == first.parent
    assert paths.repo_reports_dir("other", None) == paths.reports_dir / repo_folder("other", None)


# -- the report command ------------------------------------------------------------------------------------------
@pytest.fixture
def lab(monkeypatch, tmp_path):
    monkeypatch.setenv("LABSEC_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("LABSEC_ROOT", str(tmp_path / "labsec-checkout"))
    fake = FakeDojo([finding(1, "High", "SQL built by concatenation", file="Api/Program.cs", line=14)], tests={1: {"title": "opengrep", "engagement": 10}})
    monkeypatch.setattr(commands, "connect", lambda: fake)
    return tmp_path


def run(capsys, *argv):
    code = cli.main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_report_prints_as_before_saves_three_private_files_and_prints_the_path(lab, capsys):
    repo = lab / "demo"
    repo.mkdir()
    code, out, err = run(capsys, "report", str(repo))
    assert code == 0 and out.startswith("## LabSecurity report: demo @ main")
    folder = Paths.from_env().repo_reports_dir("demo", repo)
    (saved,) = list(folder.iterdir())
    assert f"report saved to {saved}" in err
    assert sorted(p.name for p in saved.iterdir()) == ["pr-body.md", "report.json", "report.md"]
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in saved.iterdir())
    assert (saved / "report.md").read_text().startswith("## LabSecurity report: demo @ main")
    assert json.loads((saved / "report.json").read_text())["schema"] == "labsec.report/v1"
    assert not list(repo.iterdir()), "the scanned repository must stay untouched"


def test_report_json_carries_the_saved_path(lab, capsys):
    code, out, _ = run(capsys, "report", "demo", "--json")
    data = json.loads(out)
    assert code == 0 and Path(data["saved_to"]).is_dir() and data["saved_to"].startswith(str(lab / "home" / "reports" / "demo-"))


def test_report_no_save_writes_nothing(lab, capsys):
    code, out, err = run(capsys, "report", "demo", "--no-save")
    assert code == 0 and out.startswith("## LabSecurity report") and "saved" not in err
    assert not (lab / "home" / "reports").exists()


def test_report_out_writes_to_the_given_directory(lab, capsys):
    target = lab / "elsewhere"
    code, _, err = run(capsys, "report", "demo", "--out", str(target))
    assert code == 0 and f"report saved to {target}" in err and (target / "report.md").is_file()


def test_report_out_inside_the_scanned_repo_or_the_labsecurity_repo_is_refused(lab, capsys):
    repo = lab / "demo"
    repo.mkdir()
    code, out, err = run(capsys, "report", str(repo), "--out", str(repo / "reports"))
    assert code == 1 and out == "" and "must not be inside the scanned repository" in err and not (repo / "reports").exists()
    code, _, err = run(capsys, "report", "demo", "--out", str(lab / "labsec-checkout" / "reports"))
    assert code == 1 and "must not be inside the LabSecurity repository" in err


def test_report_out_and_no_save_contradict_each_other(lab, capsys):
    code, _, err = run(capsys, "report", "demo", "--no-save", "--out", str(lab / "x"))
    assert code == 1 and "contradict" in err and not (lab / "x").exists()
