"""SonarQube REST client, and the export in the format DefectDojo's `SonarQube Scan` parser accepts."""

from __future__ import annotations

import time
from datetime import datetime, timezone

import requests


class SonarError(RuntimeError):
    pass


class SonarClient:
    def __init__(self, url: str, token: str | None = None, auth: tuple[str, str] | None = None, timeout: int = 60):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        # A user token goes in the basic-auth username with an empty password.
        self.session.auth = auth if auth else (token or "", "")

    def _request(self, method: str, path: str, **kwargs):
        try:
            response = self.session.request(method, f"{self.url}{path}", timeout=self.timeout, **kwargs)
        except requests.RequestException as exc:
            raise SonarError(f"SonarQube unreachable at {self.url}: {type(exc).__name__}") from exc
        if response.status_code >= 400:
            raise SonarError(f"SonarQube {method} {path} -> HTTP {response.status_code}: {response.text[:300]}")
        return response.json() if response.content else {}

    def status(self) -> str:
        return str(self._request("GET", "/api/system/status").get("status"))

    def token_valid(self) -> bool:
        return bool(self._request("GET", "/api/authentication/validate").get("valid"))

    # -- quality profiles ("all rules", see labsec/profiles.py)
    def language_keys(self) -> list[str]:
        return [item["key"] for item in self._request("GET", "/api/languages/list").get("languages", [])]

    def rule_total(self, language: str) -> int:
        """Rules that can be activated for a language: every status except REMOVED, without rule templates.

        Templates (for example `java:S124`, `xml:XPathCheck`) are only patterns for custom rules: they cannot be
        activated in a profile, so counting them would make "fully active" unreachable.
        """
        data = self._request("GET", "/api/rules/search", params={"languages": language, "ps": 1, "is_template": "false"})
        return int(data["paging"]["total"])

    def quality_profiles(self, language: str) -> list[dict]:
        return self._request("GET", "/api/qualityprofiles/search", params={"language": language}).get("profiles", [])

    def create_profile(self, language: str, name: str) -> dict:
        return self._request("POST", "/api/qualityprofiles/create", data={"language": language, "name": name})["profile"]

    def activate_all_rules(self, profile_key: str, language: str) -> dict:
        """Bulk-activate every rule of `language` in the profile; returns the succeeded/failed counts."""
        return self._request("POST", "/api/qualityprofiles/activate_rules", data={"targetKey": profile_key, "languages": language})

    def set_default_profile(self, language: str, name: str) -> None:
        self._request("POST", "/api/qualityprofiles/set_default", data={"language": language, "qualityProfile": name})

    def wait_for_analysis(self, project_key: str, since: datetime, timeout: float = 900.0) -> None:
        """Wait for the Compute Engine task of this run (submitted at or after `since`)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            data = self._request("GET", "/api/ce/component", params={"component": project_key})
            current = data.get("current") or {}
            submitted = _parse_time(current.get("submittedAt"))
            if not data.get("queue") and current and submitted and submitted >= since:
                status = current.get("status")
                if status == "SUCCESS":
                    return
                if status in ("FAILED", "CANCELED"):
                    raise SonarError(f"SonarQube background task ended with status {status}")
            time.sleep(3)
        raise SonarError("timed out waiting for the SonarQube background task")

    def _paged(self, path: str, key: str, params: dict, page_size: int = 500, max_pages: int = 20):
        items, components = [], {}
        for page in range(1, max_pages + 1):
            data = self._request("GET", path, params={**params, "ps": page_size, "p": page})
            items.extend(data.get(key, []))
            for component in data.get("components", []):
                components[component["key"]] = component
            paging = data.get("paging", {})
            if page * page_size >= paging.get("total", 0):
                break
        return items, components

    def export_for_dojo(self, project_key: str) -> dict:
        issues, components = self._paged(
            "/api/issues/search", "issues", {"componentKeys": project_key, "resolved": "false"}
        )
        hotspots, hotspot_components = self._paged(
            "/api/hotspots/search", "hotspots", {"project": project_key, "status": "TO_REVIEW"}
        )
        components.update(hotspot_components)
        return to_dojo_export(project_key, issues, hotspots, components)


def _parse_time(value):
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S%z").astimezone(timezone.utc)
    except ValueError:
        return None


# The DefectDojo parser maps BLOCKER->High, MAJOR->Medium, MINOR->Low and otherwise Title-cases the value.
# These inputs make it produce the severity we want.
_DD_INPUT = {"Critical": "CRITICAL", "High": "BLOCKER", "Medium": "MAJOR", "Low": "MINOR", "Info": "INFO"}
_VULN_BUG = {"BLOCKER": "Critical", "CRITICAL": "High", "MAJOR": "Medium", "MINOR": "Low", "INFO": "Info"}
# Hotspots need human review: capped at Medium for the same reason.
_HOTSPOT = {"HIGH": "Medium", "MEDIUM": "Medium", "LOW": "Low"}
_IMPACT_TO_LEGACY = {"BLOCKER": "BLOCKER", "HIGH": "CRITICAL", "MEDIUM": "MAJOR", "LOW": "MINOR", "INFO": "INFO"}


def _legacy_severity(issue: dict) -> str:
    if issue.get("severity"):
        return str(issue["severity"]).upper()
    order = ["BLOCKER", "HIGH", "MEDIUM", "LOW", "INFO"]
    impacts = [str(i.get("severity", "")).upper() for i in issue.get("impacts", [])]
    for level in order:
        if level in impacts:
            return _IMPACT_TO_LEGACY[level]
    return "INFO"


def is_security_issue(issue: dict) -> bool:
    """Only security issues of SonarQube's own rules go to DefectDojo (it feeds the PR gate).

    Bugs, code smells and every external issue (Roslyn analyzers, ESLint: they reach DefectDojo through their own
    security-only reports) stay in SonarQube. With "all rules" active this keeps the gate signal clean.
    """
    if str(issue.get("rule", "")).startswith("external_"):
        return False
    if issue.get("type") == "VULNERABILITY":
        return True
    return any(i.get("softwareQuality") == "SECURITY" for i in issue.get("impacts", []))


def _path_of(component: str, project_key: str) -> str:
    prefix = f"{project_key}:"
    return component[len(prefix):] if component.startswith(prefix) else component


def to_dojo_export(project_key: str, issues: list, hotspots: list, components: dict) -> dict:
    """Build the JSON document `dojo.tools.sonarqube` reads (paging + components + issues + hotspots)."""
    out_issues = []
    for issue in issues:
        if not is_security_issue(issue):
            continue
        kind = "VULNERABILITY"
        wanted = _VULN_BUG.get(_legacy_severity(issue), "Low")
        out_issues.append(
            {
                "key": issue["key"],
                "rule": issue.get("rule", ""),
                "component": _path_of(issue.get("component", ""), project_key),
                "project": project_key,
                "line": issue.get("line"),
                "textRange": issue.get("textRange", {}),
                "flows": [],
                "status": issue.get("status", "OPEN"),
                "message": issue.get("message", ""),
                "tags": issue.get("tags", []),
                "type": kind,
                "scope": issue.get("scope", "MAIN"),
                "severity": _DD_INPUT[wanted],
                "creationDate": issue.get("creationDate", ""),
                "quickFixAvailable": issue.get("quickFixAvailable", False),
                "codeVariants": issue.get("codeVariants", []),
            }
        )
    out_hotspots = []
    for hotspot in hotspots:
        probability = str(hotspot.get("vulnerabilityProbability", "LOW")).upper()
        out_hotspots.append(
            {
                "key": hotspot["key"],
                "component": _path_of(hotspot.get("component", ""), project_key),
                "project": project_key,
                "securityCategory": hotspot.get("securityCategory", ""),
                "vulnerabilityProbability": _HOTSPOT.get(probability, "Low").upper(),
                "status": hotspot.get("status", "TO_REVIEW"),
                "line": hotspot.get("line"),
                "message": hotspot.get("message", ""),
                "textRange": hotspot.get("textRange", {}),
                "flows": [],
                "ruleKey": hotspot.get("ruleKey", ""),
                "creationDate": hotspot.get("creationDate", ""),
            }
        )
    out_components = [
        {**component, "key": _path_of(key, project_key)} for key, component in sorted(components.items())
    ]
    # The parser ignores documents without a non-empty `components` list.
    out_components.append({"key": project_key, "name": project_key, "qualifier": "TRK"})
    total = len(out_issues) + len(out_hotspots)
    return {
        "paging": {"pageIndex": 1, "pageSize": max(total, 1), "total": total},
        "components": out_components,
        "issues": out_issues,
        "hotspots": out_hotspots,
    }
