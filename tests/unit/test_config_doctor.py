import os
import stat

from labsec.config import Paths, read_vars, secret_values, update_vars
from labsec.doctor import check_modes, check_ports, check_services


def make_paths(tmp_path):
    return Paths(
        root=tmp_path / "root",
        config_dir=tmp_path / "config",
        data_dir=tmp_path / "data",
        cache_dir=tmp_path / "cache",
        state_dir=tmp_path / "state",
    )


def test_update_vars_keeps_comments_order_and_mode(tmp_path):
    path = tmp_path / "cli.vars"
    path.write_text("# header\nDD_URL=http://x\nDD_API_TOKEN=\nOTHER=1\n")
    os.chmod(path, 0o644)
    update_vars(path, {"DD_API_TOKEN": "abc123token", "NEW_KEY": "v"})
    assert path.read_text().splitlines() == ["# header", "DD_URL=http://x", "DD_API_TOKEN=abc123token", "OTHER=1", "NEW_KEY=v"]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert read_vars(path)["DD_API_TOKEN"] == "abc123token"
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".vars-")]


def test_secret_values_picks_only_secret_looking_keys():
    values = secret_values({"DD_URL": "http://x", "DD_API_TOKEN": "t0k3n", "SONAR_ADMIN_PASSWORD": "pw", "EMPTY_TOKEN": ""})
    assert sorted(values) == ["pw", "t0k3n"]


def row(service, state="running", health="healthy", exit_code=0, publishers=None):
    return {"Service": service, "State": state, "Health": health, "ExitCode": exit_code, "Publishers": publishers or []}


def healthy_rows():
    names = ["sonar-db", "sonarqube", "dd-db", "valkey", "dd-uwsgi", "dd-celerybeat", "dd-celeryworker", "dd-nginx"]
    return [row(n) for n in names] + [row("dd-initializer", state="exited", health="", exit_code=0)]


def test_services_all_healthy():
    results = check_services(healthy_rows())
    assert all(r["status"] == "ok" for r in results)
    assert len(results) == 9


def test_services_report_missing_unhealthy_and_failed_initializer():
    rows = [r for r in healthy_rows() if r["Service"] != "valkey"]
    rows = [row("sonarqube", health="starting") if r["Service"] == "sonarqube" else r for r in rows]
    rows = [row("dd-initializer", state="exited", health="", exit_code=1) if r["Service"] == "dd-initializer" else r for r in rows]
    failed = {r["name"]: r["detail"] for r in check_services(rows) if r["status"] == "fail"}
    assert set(failed) == {"service:valkey", "service:sonarqube", "service:dd-initializer"}
    assert "not found" in failed["service:valkey"]
    assert "starting" in failed["service:sonarqube"]
    assert "exit code 1" in failed["service:dd-initializer"]


def test_ports_must_be_loopback_only():
    good = [row("sonarqube", publishers=[{"URL": "127.0.0.1", "TargetPort": 9000, "PublishedPort": 19000}])]
    assert check_ports(good)["status"] == "ok"
    bad = good + [row("dd-nginx", publishers=[{"URL": "0.0.0.0", "TargetPort": 8080, "PublishedPort": 19080}])]
    result = check_ports(bad)
    assert result["status"] == "fail" and "dd-nginx" in result["detail"]
    unpublished = [row("dd-db", publishers=[{"URL": "", "TargetPort": 5432, "PublishedPort": 0}])]
    assert check_ports(unpublished)["status"] == "ok"


def test_secret_file_modes(tmp_path):
    paths = make_paths(tmp_path)
    paths.config_dir.mkdir(mode=0o700)
    os.chmod(paths.config_dir, 0o700)
    good = paths.config_dir / "cli.vars"
    good.write_text("A=1\n")
    os.chmod(good, 0o600)
    assert check_modes(paths)["status"] == "ok"
    os.chmod(good, 0o644)
    result = check_modes(paths)
    assert result["status"] == "fail" and "cli.vars" in result["detail"]
    os.chmod(good, 0o600)
    os.chmod(paths.config_dir, 0o755)
    assert check_modes(paths)["status"] == "fail"
