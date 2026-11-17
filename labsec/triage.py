"""Triage over the DefectDojo API: list findings compactly, classify, mark false positives (with a reason).

Rules: the agent can mark a false positive only with a verifiable file:line reason, can
revert its own marks, and NEVER accepts a risk. Nothing here reads raw reports or prints descriptions/payloads.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from labsec.dojo import SEVERITY_BLOCKING, DojoClient, DojoNotFound
from labsec.knowledge import explanation  # noqa: F401  (re-exported for callers)
from labsec.project import UsageError
from labsec.redact import redact

TAG_FP = "labsec-fp"
TAG_TP = "labsec-triaged-tp"
TAG_CONFIRM = "labsec-to-confirm"
LABSEC_TAGS = (TAG_FP, TAG_TP, TAG_CONFIRM)

SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
_SEV_RANK = {name: index for index, name in enumerate(SEVERITIES)}
VIEWS = ("open", "new", "blocking")
STATES = ("untriaged", "true-positive", "to-confirm", "false-positive", "risk-accepted")

FINDINGS_SCHEMA = "labsec.findings/v1"
MARK_SCHEMA = "labsec.mark/v1"

# `path/to/file.ext:42` (or `File.cs:42-50`): the verifiable location a false-positive reason must carry.
FILE_LINE = re.compile(r"(?<![\w./\\-])(?P<path>[\w./\\-]*[A-Za-z][\w./\\-]*):(?P<line>\d+)(?:-\d+)?(?!\d)")
MIN_EXPLANATION = 10
MAX_REASON = 500


def normalize_severity(value: str) -> str:
    for name in SEVERITIES:
        if name.lower() == value.strip().lower():
            return name
    raise UsageError(f"unknown severity {value!r} (use: {', '.join(s.lower() for s in SEVERITIES)})")


def parse_severities(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [normalize_severity(part) for part in raw.split(",") if part.strip()]


# ----------------------------------------------------------------------------- classification
def triage_state(finding: dict) -> str:
    tags = set(finding.get("tags") or [])
    if finding.get("risk_accepted"):
        return "risk-accepted"
    if finding.get("false_p"):
        return "false-positive"
    if TAG_TP in tags:
        return "true-positive"
    # A human cleared the false-positive flag of an agent mark: that is a disagreement, not a new finding.
    if TAG_CONFIRM in tags or TAG_FP in tags:
        return "to-confirm"
    return "untriaged"


def is_classified(finding: dict) -> bool:
    return triage_state(finding) != "untriaged"


def is_blocking(finding: dict) -> bool:
    return (
        bool(finding.get("active"))
        and not finding.get("duplicate")
        and finding.get("severity") in SEVERITY_BLOCKING
        and not finding.get("false_p")
        and not finding.get("risk_accepted")
    )


_TRAILING_UUID = re.compile(r"_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


def view_of(dojo, finding: dict) -> dict:
    """Whitelisted, redacted projection of a finding. Descriptions and references never leave the API client."""
    flags = {
        "active": bool(finding.get("active")),
        "false_p": bool(finding.get("false_p")),
        "risk_accepted": bool(finding.get("risk_accepted")),
        "mitigated": bool(finding.get("is_mitigated")),
        "duplicate": bool(finding.get("duplicate")),
    }
    rule = finding.get("vuln_id_from_tool") or None
    return {
        "id": finding["id"],
        "severity": finding.get("severity"),
        "title": redact(_TRAILING_UUID.sub("", str(finding.get("title") or "")))[:200],
        "file": finding.get("file_path"),
        "line": finding.get("line"),
        "cwe": finding.get("cwe") or None,
        "rule": redact(str(rule))[:120] if rule else None,
        "tool": dojo.test_title(finding.get("test")),
        "status": flags,
        "triage": triage_state(finding),
        "url": dojo.finding_url(finding["id"]),
    }


def where(view: dict) -> str:
    location = view.get("file") or "?"
    if view.get("line"):
        location += f":{view['line']}"
    return location


def sort_key(item: dict):
    return (_SEV_RANK.get(item.get("severity"), 99), item.get("id", 0))


# ----------------------------------------------------------------------------- listing
class ProductNotFound(UsageError):
    pass


def product_of(dojo: DojoClient, slug: str) -> dict:
    product = dojo.find_product(slug)
    if product is None:
        raise ProductNotFound(f"no DefectDojo product named {slug!r}: run `bin/scan <project>` first")
    return product


def engagement_run_id(engagement: dict) -> str:
    return str(engagement.get("name", "")).rsplit(" ", 1)[-1]


def select_engagement(dojo: DojoClient, product_id: int, run: str = "latest") -> dict:
    engagements = dojo.engagements(product_id)
    if not engagements:
        raise UsageError("this product has no engagement yet: run `bin/scan <project>` first")
    if run == "latest":
        return max(engagements, key=lambda e: e["id"])
    for engagement in engagements:
        if str(engagement["id"]) == run or engagement_run_id(engagement) == run:
            return engagement
    raise UsageError(f"no engagement matches run {run!r}")


def fetch(dojo: DojoClient, product_id: int, view: str, engagement_id: int | None = None) -> list[dict]:
    """Raw findings for one view: `open` (active, non-duplicate), `new` (the latest run's) or `blocking`."""
    if view not in VIEWS:
        raise UsageError(f"unknown view {view!r}")
    filters = {"active": "true", "duplicate": "false"}
    if view == "new":
        if engagement_id is None:
            raise UsageError("the `new` view needs an engagement")
        filters["test__engagement"] = engagement_id
    else:
        filters["test__engagement__product"] = product_id
    found = dojo.findings(**filters)
    if view == "blocking":
        found = [f for f in found if is_blocking(f)]
    return found


def list_findings(
    dojo: DojoClient,
    slug: str,
    *,
    view: str = "open",
    severities=(),
    untriaged: bool = False,
    limit: int | None = None,
    run: str = "latest",
) -> dict:
    product = product_of(dojo, slug)
    engagement_id = select_engagement(dojo, product["id"], run)["id"] if view == "new" else None
    raw = fetch(dojo, product["id"], view, engagement_id)
    wanted = set(severities)
    if wanted:
        raw = [f for f in raw if f.get("severity") in wanted]
    if untriaged:
        raw = [f for f in raw if not is_classified(f)]
    raw.sort(key=sort_key)
    total = len(raw)
    if limit is not None:
        raw = raw[: max(limit, 0)]
    items = [view_of(dojo, f) for f in raw]
    return {
        "schema": FINDINGS_SCHEMA,
        "project": slug,
        "filter": {"view": view, "severity": [s.lower() for s in severities], "untriaged": untriaged, "limit": limit},
        "total": total,
        "returned": len(items),
        "findings": items,
    }


def render_findings_text(data: dict) -> str:
    f = data["filter"]
    head = f"{data['project']}: {data['total']} {f['view']} finding(s)"
    extras = []
    if f["severity"]:
        extras.append("severity " + ",".join(f["severity"]))
    if f["untriaged"]:
        extras.append("untriaged only")
    if extras:
        head += " (" + "; ".join(extras) + ")"
    lines = [head]
    for item in data["findings"]:
        meta = [item["tool"]]
        if item["cwe"]:
            meta.append(f"CWE-{item['cwe']}")
        if item["rule"] and item["rule"] != item["title"]:
            meta.append(item["rule"])
        flags = [name for name, on in item["status"].items() if on and name in ("false_p", "risk_accepted", "mitigated")]
        flags += [] if item["status"]["active"] else ["inactive"]
        lines.append(
            f"#{item['id']} {item['severity']} {where(item)} {item['title']} [{', '.join(meta)}] "
            f"triage={item['triage']}" + (f" flags={','.join(flags)}" if flags else "")
        )
    if data["returned"] < data["total"]:
        lines.append(f"... {data['total'] - data['returned']} more (raise --limit or narrow the filter)")
    return "\n".join(lines)


# ----------------------------------------------------------------------------- marking
def validate_reason(reason: str | None) -> str:
    """A false-positive reason must name a file:line and say why it is not exploitable. Returns the cleaned text."""
    text = " ".join((reason or "").split())
    if not text:
        raise UsageError("a reason is required: --reason \"<file:line - why it is not exploitable>\"")
    match = FILE_LINE.search(text)
    if not match:
        raise UsageError("the reason must contain a file:line reference (e.g. Api/Program.cs:42 - value is a constant)")
    rest = (text[: match.start()] + " " + text[match.end():]).strip(" -:;,.()[]")
    if len(rest) < MIN_EXPLANATION:
        raise UsageError("the reason must also explain why the finding is not exploitable, not just point at file:line")
    if len(text) > MAX_REASON:
        raise UsageError(f"the reason is too long ({len(text)} > {MAX_REASON} characters)")
    return redact(text)


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _tags_after(finding: dict, add=(), remove=()) -> list[str]:
    tags = [t for t in (finding.get("tags") or []) if t not in remove]
    for tag in add:
        if tag not in tags:
            tags.append(tag)
    return tags


def _load(dojo: DojoClient, finding_id: int) -> dict:
    try:
        return dojo.get_finding(finding_id)
    except DojoNotFound as exc:
        raise UsageError(f"finding {finding_id} does not exist in DefectDojo") from exc


def _result(dojo, finding: dict, action: str, changed: bool, **extra) -> dict:
    out = {"schema": MARK_SCHEMA, "action": action, "changed": changed, **extra}
    out["finding"] = view_of(dojo, finding)
    return out


def _refuse_if_risk_accepted(finding: dict) -> None:
    if finding.get("risk_accepted"):
        raise UsageError(f"finding {finding['id']} is risk-accepted by a human reviewer: LabSecurity does not touch it")


def mark_false_positive(dojo: DojoClient, finding_id: int, reason: str | None) -> dict:
    clean = validate_reason(reason)
    finding = _load(dojo, finding_id)
    _refuse_if_risk_accepted(finding)
    if finding.get("false_p") and TAG_FP in (finding.get("tags") or []):
        return _result(dojo, finding, "mark-fp", False, reason=clean)
    # Note first: a false positive without its reason would break "verifiable reason".
    dojo.add_note(
        finding_id,
        f"LabSecurity {_today()}: marked FALSE POSITIVE by the agent. Reason: {clean} "
        f"Revert with: labsec unmark-fp {finding_id}",
    )
    payload = {"false_p": True, "active": False, "tags": _tags_after(finding, add=[TAG_FP], remove=[TAG_TP, TAG_CONFIRM])}
    if finding.get("verified"):
        payload["verified"] = False  # DefectDojo rejects verified false positives
    dojo.update_finding(finding_id, payload)
    updated = {**finding, "false_p": True, "active": False, "tags": payload["tags"]}
    return _result(dojo, updated, "mark-fp", True, reason=clean)


def unmark_false_positive(dojo: DojoClient, finding_id: int) -> dict:
    finding = _load(dojo, finding_id)
    _refuse_if_risk_accepted(finding)
    if TAG_FP not in (finding.get("tags") or []):
        raise UsageError(
            f"finding {finding_id} was not marked by LabSecurity (no {TAG_FP} tag): change it in the DefectDojo UI"
        )
    if not finding.get("false_p"):
        return _result(dojo, finding, "unmark-fp", False)
    dojo.add_note(finding_id, f"LabSecurity {_today()}: false-positive mark reverted. The finding is open again.")
    # DefectDojo sets is_mitigated when a finding is deactivated as a false positive, so `is_mitigated` is not
    # evidence of a fix here: the next re-scan closes the finding again if the code was really fixed.
    payload = {"false_p": False, "active": True, "tags": _tags_after(finding, remove=[TAG_FP])}
    dojo.update_finding(finding_id, payload)
    updated = {**finding, "false_p": False, "active": True, "is_mitigated": False, "tags": payload["tags"]}
    return _result(dojo, updated, "unmark-fp", True)


def _guard_markable(finding: dict) -> None:
    _refuse_if_risk_accepted(finding)
    if finding.get("false_p"):
        raise UsageError(f"finding {finding['id']} is a false positive: run `labsec unmark-fp {finding['id']}` first")


def mark_true_positive(dojo: DojoClient, finding_id: int, note: str | None = None) -> dict:
    finding = _load(dojo, finding_id)
    _guard_markable(finding)
    if TAG_TP in (finding.get("tags") or []):
        return _result(dojo, finding, "mark-tp", False)
    text = f"LabSecurity {_today()}: confirmed TRUE POSITIVE against the real code."
    if note:
        text += f" {redact(' '.join(note.split()))[:MAX_REASON]}"
    dojo.add_note(finding_id, text)
    tags = _tags_after(finding, add=[TAG_TP], remove=[TAG_CONFIRM])
    dojo.update_finding(finding_id, {"tags": tags})
    return _result(dojo, {**finding, "tags": tags}, "mark-tp", True)


def mark_to_confirm(dojo: DojoClient, finding_id: int, note: str | None = None) -> dict:
    finding = _load(dojo, finding_id)
    _guard_markable(finding)
    if TAG_CONFIRM in (finding.get("tags") or []):
        return _result(dojo, finding, "mark-to-confirm", False)
    if note:
        dojo.add_note(finding_id, f"LabSecurity {_today()}: TO CONFIRM. {redact(' '.join(note.split()))[:MAX_REASON]}")
    tags = _tags_after(finding, add=[TAG_CONFIRM], remove=[TAG_TP])
    dojo.update_finding(finding_id, {"tags": tags})  # tag only: no status change
    return _result(dojo, {**finding, "tags": tags}, "mark-to-confirm", True)


def render_mark_text(result: dict) -> str:
    item = result["finding"]
    base = f"#{item['id']} {item['severity']} {where(item)} {item['title']}"
    verbs = {
        "mark-fp": "marked FALSE POSITIVE",
        "unmark-fp": "false-positive mark REVERTED",
        "mark-tp": "marked TRUE POSITIVE",
        "mark-to-confirm": "marked TO CONFIRM",
    }
    verb = verbs[result["action"]] if result["changed"] else f"no change ({verbs[result['action']]} already applied)"
    lines = [f"{verb}: {base}", f"triage={item['triage']} | {item['url']}"]
    if result.get("reason") and result["changed"]:
        lines.append(f"reason: {result['reason']}")
        lines.append(f"revert: labsec unmark-fp {item['id']}")
    return "\n".join(lines)


def reason_of(dojo: DojoClient, finding_id: int) -> str | None:
    """The reason stored in the LabSecurity note of a false positive (read from DefectDojo notes)."""
    try:
        notes = dojo.notes(finding_id)
    except Exception:  # noqa: BLE001 - the report must still render without the note
        return None
    for note in reversed(notes):
        entry = str(note.get("entry", ""))
        marker = "Reason: "
        if "marked FALSE POSITIVE" in entry and marker in entry:
            reason = entry.split(marker, 1)[1].split(" Revert with:", 1)[0]
            return redact(reason)[:MAX_REASON]
    return None
