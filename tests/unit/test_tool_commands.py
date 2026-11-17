from types import SimpleNamespace

from labsec.tools import RULE_DIRS, trivy_command, zap_command


def target(url="http://127.0.0.1:5000", openapi=None):
    return SimpleNamespace(target_url=url, openapi_url=openapi)


def test_zap_baseline_runs_silent_so_only_the_pinned_addons_load():
    command = zap_command(target())
    assert command[0] == "zap-baseline.py"
    # `-silent` stops the stock script from running `-addonupdate -addoninstall pscanrulesBeta` (unpinned downloads).
    assert command[command.index("-z") + 1] == "-silent"
    assert command[command.index("-t") + 1] == "http://127.0.0.1:5000"


def test_zap_api_scan_runs_silent_too():
    command = zap_command(target(openapi="http://127.0.0.1:5000/openapi.json"))
    assert command[0] == "zap-api-scan.py"
    assert command[command.index("-f") + 1] == "openapi"
    assert command[command.index("-z") + 1] == "-silent"


def test_terraform_files_load_the_terraform_rule_directory():
    assert RULE_DIRS["terraform"] == ["terraform"]


def test_trivy_scans_vulnerabilities_and_misconfigurations_but_leaves_secrets_to_gitleaks():
    command = trivy_command()
    assert command[:3] == ["fs", "--scanners", "vuln,misconfig"]
    assert command[-1] == "/src"
