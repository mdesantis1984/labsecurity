"""`bin/scan --doctor`: confirm the whole lab responds. Exit non-zero on any failed check."""

from __future__ import annotations

import json
import stat
import sys

from labsec.config import Paths, read_vars, secret_values
from labsec.docker import Compose
from labsec.dojo import DojoClient, DojoError
from labsec.profiles import PROFILE_NAME, inspect_profiles, profile_report
from labsec.redact import redact
from labsec.sonar import SonarClient, SonarError

SCHEMA = "labsec.doctor/v1"
HEALTHY_SERVICES = (
    "sonar-db",
    "sonarqube",
    "dd-db",
    "valkey",
    "dd-uwsgi",
    "dd-celerybeat",
    "dd-celeryworker",
    "dd-nginx",
)
LOOPBACK_BINDINGS = ("127.0.0.1", "::1")


def check(name: str, status: str, detail: str) -> dict:
    return {"name": name, "status": status, "detail": detail}


def check_services(rows: list[dict]) -> list[dict]:
    by_service = {row.get("Service"): row for row in rows}
    results = []
    for service in HEALTHY_SERVICES:
        row = by_service.get(service)
        if row is None:
            results.append(check(f"service:{service}", "fail", "container not found (run `docker compose up -d`)"))
        elif row.get("State") != "running":
            results.append(check(f"service:{service}", "fail", f"state is {row.get('State')!r}, expected running"))
        elif row.get("Health") != "healthy":
            results.append(check(f"service:{service}", "fail", f"health is {row.get('Health') or 'none'!r}, expected healthy"))
        else:
            results.append(check(f"service:{service}", "ok", "running, healthy"))
    init = by_service.get("dd-initializer")
    if init is None:
        results.append(check("service:dd-initializer", "fail", "container not found"))
    elif init.get("State") == "exited" and init.get("ExitCode") == 0:
        results.append(check("service:dd-initializer", "ok", "exited with code 0"))
    else:
        results.append(
            check("service:dd-initializer", "fail", f"state {init.get('State')!r}, exit code {init.get('ExitCode')}, expected exited 0")
        )
    return results


def check_ports(rows: list[dict]) -> dict:
    exposed = []
    for row in rows:
        for pub in row.get("Publishers") or []:
            if pub.get("PublishedPort") and pub.get("URL") not in LOOPBACK_BINDINGS:
                exposed.append(f"{row.get('Service')}:{pub.get('PublishedPort')} bound to {pub.get('URL') or 'all interfaces'}")
    if exposed:
        return check("ports", "fail", "published beyond loopback: " + "; ".join(exposed))
    return check("ports", "ok", "every published port is bound to 127.0.0.1")


def check_modes(paths: Paths) -> dict:
    problems = []
    if not paths.config_dir.is_dir():
        return check("secret-files", "fail", f"{paths.config_dir} does not exist (run scripts/init.sh)")
    if stat.S_IMODE(paths.config_dir.stat().st_mode) != 0o700:
        problems.append(f"{paths.config_dir} is not mode 700")
    files = sorted(paths.config_dir.glob("*.vars")) + sorted((paths.config_dir / "projects").glob("*.vars"))
    for file in files:
        if stat.S_IMODE(file.stat().st_mode) != 0o600:
            problems.append(f"{file} is not mode 600")
    if not files:
        problems.append("no .vars files found (run scripts/init.sh)")
    if problems:
        return check("secret-files", "fail", "; ".join(problems))
    return check("secret-files", "ok", f"{len(files)} secret file(s) mode 600, directory mode 700")


def check_profiles(sonar) -> dict:
    """Every language with rules must use the `LabSecurity` profile as default, with every rule active."""
    try:
        rows = inspect_profiles(sonar)
    except SonarError as exc:
        return check("sonarqube:profiles", "fail", str(exc))
    problems = []
    for row in rows:
        if not row["present"]:
            problems.append(f"{row['language']}: profile {PROFILE_NAME} missing")
        elif not row["default"]:
            problems.append(f"{row['language']}: {PROFILE_NAME} is not the default")
        elif row["active"] < row["total"]:
            problems.append(f"{row['language']} {row['active']}/{row['total']} rules active")
    if problems or not rows:
        return check("sonarqube:profiles", "fail", "; ".join(problems) + " (run `bin/scan --bootstrap`)" if problems else "no languages with rules")
    return check("sonarqube:profiles", "ok", f"{PROFILE_NAME} is default and fully active: {profile_report(rows)}")


def check_images(compose: Compose) -> list[dict]:
    results = []
    try:
        images = compose.images()
    except RuntimeError as exc:
        return [check("images", "fail", str(exc))]
    stack_services = {"sonarqube", "postgres", "defectdojo", "valkey"}
    for image in images:
        if any(part in image for part in stack_services):
            continue
        short = image.split("@")[0]
        if compose.image_present(image):
            results.append(check(f"image:{short}", "ok", "present"))
        else:
            results.append(check(f"image:{short}", "warn", "not present locally; pulled or built on first scan"))
    return results


def run_checks(paths: Paths) -> list[dict]:
    compose = Compose(paths)
    cli_vars = read_vars(paths.cli_vars)
    known = secret_values(cli_vars)
    results: list[dict] = []
    try:
        rows = compose.ps()
    except (RuntimeError, OSError) as exc:
        results.append(check("docker", "fail", redact(str(exc), known)))
        rows = []
    else:
        results.extend(check_services(rows))
        results.append(check_ports(rows))

    sonar_url, dd_url = cli_vars.get("SONAR_URL"), cli_vars.get("DD_URL")
    if not sonar_url or not dd_url:
        results.append(check("cli-config", "fail", f"{paths.cli_vars} missing SONAR_URL/DD_URL (run scripts/init.sh)"))
    else:
        try:
            status = SonarClient(sonar_url).status()
            results.append(check("sonarqube:status", "ok" if status == "UP" else "fail", f"/api/system/status is {status}"))
        except SonarError as exc:
            results.append(check("sonarqube:status", "fail", str(exc)))
        token = cli_vars.get("SONAR_TOKEN", "")
        if not token:
            results.append(check("sonarqube:token", "fail", "SONAR_TOKEN is empty (run `bin/scan --bootstrap`)"))
        else:
            try:
                valid = SonarClient(sonar_url, token=token).token_valid()
                results.append(check("sonarqube:token", "ok" if valid else "fail", "token valid" if valid else "token rejected"))
                if valid:
                    results.append(check_profiles(SonarClient(sonar_url, token=token)))
            except SonarError as exc:
                results.append(check("sonarqube:token", "fail", redact(str(exc), known)))
        dd_token = cli_vars.get("DD_API_TOKEN", "")
        if not dd_token:
            results.append(check("defectdojo:api", "fail", "DD_API_TOKEN is empty (run `bin/scan --bootstrap`)"))
        else:
            try:
                DojoClient(dd_url, dd_token, timeout=30).check()
                results.append(check("defectdojo:api", "ok", "API reachable, token accepted"))
            except DojoError as exc:
                results.append(check("defectdojo:api", "fail", redact(str(exc), known)))
    results.append(check_modes(paths))
    results.extend(check_images(compose))
    return results


def doctor(paths: Paths | None = None, as_json: bool = False) -> int:
    paths = paths or Paths.from_env()
    results = run_checks(paths)
    ok = all(r["status"] != "fail" for r in results)
    if as_json:
        print(json.dumps({"schema": SCHEMA, "ok": ok, "checks": results}, indent=2))
    else:
        marks = {"ok": "ok  ", "warn": "warn", "fail": "FAIL"}
        for r in results:
            print(f"[{marks[r['status']]}] {r['name']}: {r['detail']}")
        print("lab is healthy" if ok else "lab has failing checks", file=sys.stdout)
    return 0 if ok else 3
