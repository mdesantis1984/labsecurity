"""DefectDojo REST client (import, counts, stability wait)."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path

import requests

PRODUCT_TYPE = "LabSecurity"
SEVERITY_BLOCKING = ("Critical", "High")


class DojoError(RuntimeError):
    pass


class DojoNotFound(DojoError):
    pass


# The agent never accepts a risk: the client refuses every write that would touch it.
_RISK_PREFIX = "risk_accept"
# The only finding fields LabSecurity ever changes (triage: false positive flag, status, tags).
FINDING_UPDATE_FIELDS = frozenset({"false_p", "active", "verified", "tags"})


def guard_no_risk_acceptance(method: str, path: str, payload) -> None:
    """Raise when a write would create a risk acceptance or set `risk_accepted`."""
    if method.upper() in ("GET", "HEAD", "OPTIONS"):
        return
    if _RISK_PREFIX in path.lower():
        raise DojoError("refused: LabSecurity never creates or changes risk acceptances")
    if isinstance(payload, dict) and any(str(key).lower().startswith(_RISK_PREFIX) for key in payload):
        raise DojoError("refused: LabSecurity never sets risk_accepted")


class DojoClient:
    def __init__(self, url: str, token: str, timeout: int = 300):
        self.url = url.rstrip("/")
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Token {token}"
        self.timeout = timeout

    # -- plumbing
    def _request(self, method: str, path: str, **kwargs):
        guard_no_risk_acceptance(method, path, kwargs.get("json") if "json" in kwargs else kwargs.get("data"))
        try:
            response = self.session.request(method, f"{self.url}{path}", timeout=self.timeout, **kwargs)
        except requests.RequestException as exc:
            raise DojoError(f"DefectDojo unreachable at {self.url}: {type(exc).__name__}") from exc
        if response.status_code >= 400:
            error = DojoNotFound if response.status_code == 404 else DojoError
            raise error(f"DefectDojo {method} {path} -> HTTP {response.status_code}: {response.text[:300]}")
        return response.json() if response.content else {}

    def check(self) -> None:
        self._request("GET", "/api/v2/user_profile/")

    def engagement_url(self, engagement_id: int) -> str:
        return f"{self.url}/engagement/{engagement_id}"

    # -- import
    def import_scan(self, *, scan_type, file_path, product, engagement, test_title, branch, commit, build_id) -> dict:
        data = {
            "scan_type": scan_type,
            "product_type_name": PRODUCT_TYPE,
            "product_name": product,
            "engagement_name": engagement,
            "auto_create_context": "true",
            "close_old_findings": "true",
            "close_old_findings_product_scope": "true",
            "branch_tag": branch,
            "build_id": build_id,
            "test_title": test_title,
            "active": "true",
            "minimum_severity": "Info",
        }
        if commit:
            data["commit_hash"] = commit
        with open(file_path, "rb") as handle:
            files = {"file": (Path(file_path).name, handle)}
            result = self._request("POST", "/api/v2/import-scan/", data=data, files=files)
        test_id = result.get("test") or result.get("test_id")
        engagement_id = result.get("engagement_id")
        if not test_id or not engagement_id:
            raise DojoError(f"unexpected import response keys: {sorted(result)}")
        return {"test_id": int(test_id), "engagement_id": int(engagement_id), "product_id": result.get("product_id")}

    # -- queries
    def count(self, **filters) -> int:
        return int(self._request("GET", "/api/v2/findings/", params={"limit": 1, **filters})["count"])

    def _paged(self, path: str, **filters) -> list[dict]:
        out: list[dict] = []
        params = {"limit": 200, "offset": 0, **filters}
        while True:
            page = self._request("GET", path, params=params)
            out.extend(page["results"])
            if not page.get("next"):
                return out
            params["offset"] += params["limit"]

    def findings(self, **filters) -> list[dict]:
        return self._paged("/api/v2/findings/", **filters)

    # -- triage helpers (read the API, change only the triage fields)
    def finding_url(self, finding_id: int) -> str:
        return f"{self.url}/finding/{finding_id}"

    def find_product(self, name: str) -> dict | None:
        for product in self._paged("/api/v2/products/", name=name):
            if product.get("name") == name:
                return product
        return None

    def engagements(self, product_id: int) -> list[dict]:
        return self._paged("/api/v2/engagements/", product=product_id)

    def tests_of(self, engagement_id: int) -> list[dict]:
        return self._paged("/api/v2/tests/", engagement=engagement_id)

    def get_finding(self, finding_id: int) -> dict:
        return self._request("GET", f"/api/v2/findings/{int(finding_id)}/")

    def update_finding(self, finding_id: int, payload: dict) -> dict:
        extra = set(payload) - FINDING_UPDATE_FIELDS
        if extra:
            raise DojoError(f"refused: fields {sorted(extra)} are not part of LabSecurity triage")
        return self._request("PATCH", f"/api/v2/findings/{int(finding_id)}/", json=payload)

    def add_note(self, finding_id: int, entry: str) -> dict:
        return self._request("POST", f"/api/v2/findings/{int(finding_id)}/notes/", json={"entry": entry, "private": False})

    def notes(self, finding_id: int) -> list[dict]:
        data = self._request("GET", f"/api/v2/findings/{int(finding_id)}/notes/")
        if isinstance(data, dict):
            data = data.get("notes", data.get("results", []))
        return list(data or [])

    def test_title(self, test_id) -> str:
        cache = self.__dict__.setdefault("_test_titles", {})
        return self._tool_of(test_id, cache)

    def _tool_of(self, test_id, known: dict[int, str]) -> str:
        if test_id in known:
            return known[test_id]
        try:
            known[test_id] = self._request("GET", f"/api/v2/tests/{test_id}/").get("title") or "unknown"
        except DojoError:
            known[test_id] = "unknown"
        return known[test_id]

    def product_id_of(self, engagement_id: int) -> int:
        return int(self._request("GET", f"/api/v2/engagements/{engagement_id}/")["product"])

    def _fingerprint(self, engagement_id: int, product_id: int):
        return (
            self.count(test__engagement=engagement_id),
            self.count(test__engagement=engagement_id, duplicate="true"),
            self.count(test__engagement=engagement_id, active="true", duplicate="false"),
            self.count(test__engagement__product=product_id, is_mitigated="true"),
            self.count(test__engagement__product=product_id, active="true", duplicate="false"),
        )

    def wait_stable(self, engagement_id: int, product_id: int, *, interval=2.0, rounds=3, max_wait=180.0) -> bool:
        """Deduplication and closing run in Celery after the import returns: wait until counts stop moving."""
        deadline = time.monotonic() + max_wait
        last, stable = None, 0
        while time.monotonic() < deadline:
            current = self._fingerprint(engagement_id, product_id)
            stable = stable + 1 if current == last else 1
            if stable >= rounds:
                return True
            last = current
            time.sleep(interval)
        return False

    def summarize(self, engagement_id: int, product_id: int, run_started: datetime, test_tools: dict[int, str]) -> dict:
        new = self.findings(test__engagement=engagement_id, active="true", duplicate="false")
        open_findings = self.findings(test__engagement__product=product_id, active="true", duplicate="false")
        open_count = len(open_findings)
        mitigated = self.findings(test__engagement__product=product_id, is_mitigated="true", ordering="-mitigated")
        closed = 0
        for finding in mitigated:
            stamp = _parse_time(finding.get("mitigated"))
            if stamp is None or stamp < run_started:
                break
            closed += 1
        # The gate looks at everything still open in the product, not only at what this run introduced.
        blocking = [
            f
            for f in open_findings
            if f["severity"] in SEVERITY_BLOCKING and not f.get("false_p") and not f.get("risk_accepted")
        ]
        per_tool: dict[int, int] = {}
        for test_id in test_tools:
            per_tool[test_id] = self.count(test=test_id)
        counts_by_sev = {sev.lower(): 0 for sev in ("Critical", "High", "Medium", "Low", "Info")}
        for finding in blocking:
            counts_by_sev[finding["severity"].lower()] += 1
        return {
            "new": len(new),
            "open": open_count,
            "closed": closed,
            "blocking": counts_by_sev,
            "blocking_findings": [
                {
                    "id": f["id"],
                    "severity": f["severity"],
                    "title": f["title"],
                    "file": f.get("file_path"),
                    "line": f.get("line"),
                    "cwe": f.get("cwe"),
                    "tool": self._tool_of(f.get("test"), test_tools),
                }
                for f in blocking
            ],
            "per_test": per_tool,
        }


def _parse_time(value) -> datetime | None:
    if not value:
        return None
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)
