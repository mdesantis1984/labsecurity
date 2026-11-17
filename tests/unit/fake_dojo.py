"""In-memory DefectDojo: the real `DojoClient` code (guard, paging, whitelist) over a fake transport."""

from __future__ import annotations

from labsec.dojo import DojoClient, DojoError, DojoNotFound, guard_no_risk_acceptance

URL = "http://dd.test"


def finding(fid, severity="High", title="SQL built by concatenation", file="Api/Repo.cs", line=10, **overrides):
    base = {
        "id": fid,
        "severity": severity,
        "title": title,
        "file_path": file,
        "line": line,
        "cwe": 89,
        "vuln_id_from_tool": None,
        "test": 1,
        "active": True,
        "duplicate": False,
        "false_p": False,
        "risk_accepted": False,
        "is_mitigated": False,
        "mitigated": None,
        "verified": False,
        "tags": [],
        "description": "EXPLOIT-PAYLOAD ' OR 1=1 --",
        "mitigation": None,
    }
    base.update(overrides)
    return base


def _truthy(value) -> bool:
    return str(value).lower() == "true"


class FakeDojo(DojoClient):
    """Findings, tests (id -> title, engagement) and engagements live in plain dicts; every call is recorded."""

    def __init__(self, findings=(), tests=None, engagements=None, product="demo", product_id=1):
        super().__init__(URL, "token-not-real")
        self.store = {f["id"]: dict(f) for f in findings}
        self.tests = tests or {1: {"title": "opengrep", "engagement": 10}}
        self.engagement_rows = engagements or [
            {"id": 10, "product": product_id, "name": "main 20261117T100000Z", "branch_tag": "main"}
        ]
        self.product = {"id": product_id, "name": product}
        self.notes_store: dict[int, list[dict]] = {}
        self.calls: list[tuple[str, str, object]] = []

    # -- transport
    def _request(self, method, path, **kwargs):
        payload = kwargs.get("json") if "json" in kwargs else kwargs.get("data")
        guard_no_risk_acceptance(method, path, payload)
        params = kwargs.get("params") or {}
        self.calls.append((method, path, payload if method != "GET" else params))
        if method == "GET" and path == "/api/v2/products/":
            return self._page([self.product] if params.get("name") in (None, self.product["name"]) else [], params)
        if method == "GET" and path == "/api/v2/engagements/":
            return self._page([e for e in self.engagement_rows if e["product"] == params.get("product")], params)
        if method == "GET" and path == "/api/v2/tests/":
            rows = [{"id": i, **t} for i, t in self.tests.items() if t["engagement"] == params.get("engagement")]
            return self._page(rows, params)
        if method == "GET" and path.startswith("/api/v2/tests/"):
            test_id = int(path.strip("/").split("/")[-1])
            if test_id not in self.tests:
                raise DojoNotFound("no test")
            return {"id": test_id, **self.tests[test_id]}
        if path == "/api/v2/findings/" and method == "GET":
            return self._page(self._filter(params), params)
        parts = path.strip("/").split("/")  # api v2 findings <id> [notes]
        if len(parts) >= 4 and parts[2] == "findings":
            fid = int(parts[3])
            if fid not in self.store:
                raise DojoNotFound(f"DefectDojo {method} {path} -> HTTP 404")
            if len(parts) == 5 and parts[4] == "notes":
                if method == "POST":
                    note = {"id": len(self.notes_store.get(fid, [])) + 1, "entry": payload["entry"]}
                    self.notes_store.setdefault(fid, []).append(note)
                    return note
                return {"notes": self.notes_store.get(fid, [])}
            if method == "GET":
                return dict(self.store[fid])
            if method == "PATCH":
                self.store[fid].update(payload)
                # Real DefectDojo behaviour (observed live): deactivating flags the finding mitigated, activating clears it.
                if "active" in payload:
                    self.store[fid]["is_mitigated"] = not payload["active"]
                return dict(self.store[fid])
        raise DojoError(f"fake: unsupported {method} {path}")

    @staticmethod
    def _page(rows, params):
        limit, offset = int(params.get("limit", 100)), int(params.get("offset", 0))
        chunk = rows[offset : offset + limit]
        more = offset + limit < len(rows)
        return {"count": len(rows), "next": "more" if more else None, "results": chunk}

    def _filter(self, params):
        rows = list(self.store.values())
        engagement_of = {i: t["engagement"] for i, t in self.tests.items()}
        for key, value in params.items():
            if key in ("limit", "offset", "ordering"):
                continue
            if key in ("active", "duplicate", "false_p", "risk_accepted", "is_mitigated"):
                rows = [f for f in rows if bool(f[key]) == _truthy(value)]
            elif key == "test__engagement":
                rows = [f for f in rows if engagement_of.get(f["test"]) == value]
            elif key == "test__engagement__product":
                ids = {e["id"] for e in self.engagement_rows if e["product"] == value}
                rows = [f for f in rows if engagement_of.get(f["test"]) in ids]
            elif key == "tags":
                rows = [f for f in rows if value in f["tags"]]
            elif key == "severity":
                rows = [f for f in rows if f["severity"] == value]
            else:
                raise AssertionError(f"fake: unsupported filter {key}")
        return sorted(rows, key=lambda f: f["id"])

    # -- helpers for assertions
    def writes(self):
        return [c for c in self.calls if c[0] != "GET"]
