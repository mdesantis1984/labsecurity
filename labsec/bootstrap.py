"""`bin/scan --bootstrap`: obtain the API tokens once. Idempotent; token values are never printed."""

from __future__ import annotations

import sys

import requests

from labsec.config import Paths, read_vars, secret_values, update_vars
from labsec.dojo import DojoClient, DojoError
from labsec.profiles import sync_profiles
from labsec.redact import redact
from labsec.sonar import SonarClient, SonarError

TOKEN_NAME = "labsec-cli"
SONAR_DEFAULT_PASSWORD = "admin"


def _say(message: str) -> None:
    print(f"[bootstrap] {message}")


def _dojo_token(vars_: dict, updates: dict) -> None:
    url, existing = vars_["DD_URL"], vars_.get("DD_API_TOKEN", "")
    if existing:
        try:
            DojoClient(url, existing, timeout=30).check()
            _say("DefectDojo API token: kept (still valid)")
            return
        except DojoError:
            _say("DefectDojo API token: stored token rejected, requesting a new one")
    response = requests.post(
        f"{url.rstrip('/')}/api/v2/api-token-auth/",
        json={"username": vars_["DD_ADMIN_USER"], "password": vars_["DD_ADMIN_PASSWORD"]},
        timeout=30,
    )
    if response.status_code != 200 or "token" not in response.json():
        raise RuntimeError(f"DefectDojo token request failed: HTTP {response.status_code}")
    updates["DD_API_TOKEN"] = response.json()["token"]
    _say("DefectDojo API token: created")


def _sonar_password(vars_: dict) -> None:
    url, wanted = vars_["SONAR_URL"], vars_["SONAR_ADMIN_PASSWORD"]
    try:
        if SonarClient(url, auth=("admin", wanted)).token_valid():
            _say("SonarQube admin password: already set")
            return
    except SonarError:
        pass
    default = SonarClient(url, auth=("admin", SONAR_DEFAULT_PASSWORD))
    if not default.token_valid():
        raise RuntimeError("SonarQube admin accepts neither the configured nor the default password")
    response = requests.post(
        f"{url.rstrip('/')}/api/users/change_password",
        auth=("admin", SONAR_DEFAULT_PASSWORD),
        data={"login": "admin", "previousPassword": SONAR_DEFAULT_PASSWORD, "password": wanted},
        timeout=30,
    )
    if response.status_code >= 300:
        raise RuntimeError(f"SonarQube password change failed: HTTP {response.status_code}")
    _say("SonarQube admin password: changed from the default")


def _dojo_dedup(vars_: dict, updates: dict) -> None:
    """DefectDojo ships with deduplication disabled; without it every run re-reports the same findings."""
    token = updates.get("DD_API_TOKEN") or vars_.get("DD_API_TOKEN", "")
    base = vars_["DD_URL"].rstrip("/")
    headers = {"Authorization": f"Token {token}"}
    response = requests.get(f"{base}/api/v2/system_settings/", headers=headers, timeout=30)
    response.raise_for_status()
    settings = response.json()["results"][0]
    if settings.get("enable_deduplication"):
        _say("DefectDojo deduplication: already enabled")
        return
    patched = requests.patch(
        f"{base}/api/v2/system_settings/{settings['id']}/",
        headers=headers,
        json={"enable_deduplication": True},
        timeout=30,
    )
    if patched.status_code >= 300:
        raise RuntimeError(f"enabling DefectDojo deduplication failed: HTTP {patched.status_code}")
    _say("DefectDojo deduplication: enabled")


def _sonar_token(vars_: dict, updates: dict) -> None:
    url, existing = vars_["SONAR_URL"], vars_.get("SONAR_TOKEN", "")
    if existing:
        try:
            if SonarClient(url, token=existing).token_valid():
                _say("SonarQube token: kept (still valid)")
                return
        except SonarError:
            pass
        _say("SonarQube token: stored token rejected, generating a new one")
    auth = ("admin", vars_["SONAR_ADMIN_PASSWORD"])
    base = url.rstrip("/")
    # Names are unique per user: drop a stale token of ours before generating.
    requests.post(f"{base}/api/user_tokens/revoke", auth=auth, data={"name": TOKEN_NAME}, timeout=30)
    response = requests.post(
        f"{base}/api/user_tokens/generate", auth=auth, data={"name": TOKEN_NAME, "type": "USER_TOKEN"}, timeout=30
    )
    if response.status_code >= 300 or "token" not in response.json():
        raise RuntimeError(f"SonarQube token generation failed: HTTP {response.status_code}")
    updates["SONAR_TOKEN"] = response.json()["token"]
    _say("SonarQube token: created")


def _sonar_profiles(vars_: dict, updates: dict) -> None:
    """Every available rule active, per language (the built-in "Sonar way" profiles activate only part of them)."""
    token = updates.get("SONAR_TOKEN") or vars_.get("SONAR_TOKEN", "")
    sonar = SonarClient(vars_["SONAR_URL"], token=token)
    rows = sync_profiles(sonar, _say)
    incomplete = [r for r in rows if r["active"] < r["total"]]
    if incomplete:
        _say("warning: not every rule could be activated: " + ", ".join(f"{r['language']} {r['active']}/{r['total']}" for r in incomplete))


def bootstrap(paths: Paths | None = None) -> int:
    paths = paths or Paths.from_env()
    vars_ = read_vars(paths.cli_vars)
    required = ("DD_URL", "DD_ADMIN_USER", "DD_ADMIN_PASSWORD", "SONAR_URL", "SONAR_ADMIN_PASSWORD")
    missing = [key for key in required if not vars_.get(key)]
    if missing:
        print(f"{paths.cli_vars} is missing {', '.join(missing)}: run scripts/init.sh first", file=sys.stderr)
        return 3
    known = secret_values(vars_)
    updates: dict[str, str] = {}
    try:
        _dojo_token(vars_, updates)
        _dojo_dedup(vars_, updates)
        _sonar_password(vars_)
        _sonar_token(vars_, updates)
        _sonar_profiles(vars_, updates)
    except (RuntimeError, requests.RequestException, SonarError, DojoError) as exc:
        print(f"[bootstrap] failed: {redact(str(exc), known)}", file=sys.stderr)
        if updates:
            update_vars(paths.cli_vars, updates)  # keep what was obtained so far
        return 3
    if updates:
        update_vars(paths.cli_vars, updates)
    _say(f"done; tokens are stored in {paths.cli_vars} (mode 600)")
    return 0
