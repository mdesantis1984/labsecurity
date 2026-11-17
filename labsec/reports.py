"""Post-processing of raw tool reports before they are imported into DefectDojo."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

# Rules that are always security rules, whatever the SARIF says (see docker/dotnet/labsec.globalconfig): the SDK taint
# and SQL injection analyzers (CA2100, CA3001-CA3012) plus the SecurityCodeScan ids (SCS####).
CA_RULE_IDS = frozenset({"CA2100"} | {f"CA30{n:02d}" for n in range(1, 13)})
SCS_RULE = re.compile(r"^SCS\d{4}$")

# DefectDojo severity per rule (the SARIF parser maps error -> High, warning -> Medium, note -> Low):
# * High (blocks the PR): injection, unsafe deserialization, XXE, disabled TLS validation, hard-coded keys and certificates.
# * Low: findings that are usually not exploitable alone (insecure randomness, DllImport search paths).
# * Medium: every other security-category rule.
HIGH_RULES = frozenset(
    CA_RULE_IDS
    | {"CA2300", "CA2301", "CA2302", "CA2305", "CA2310", "CA2311", "CA2312", "CA2315", "CA2321", "CA2322"}
    | {f"CA23{n}" for n in (26, 27, 28, 29, 30, 50, 51, 52, 53, 54, 55, 56, 61, 62)}
    | {"CA3075", "CA3076", "CA5359", "CA5389", "CA5390", "CA5403"}
    | {"SCS0001", "SCS0002", "SCS0003", "SCS0004", "SCS0007", "SCS0015", "SCS0018", "SCS0020", "SCS0025", "SCS0026", "SCS0028", "SCS0029", "SCS0031"}
)
LOW_RULES = frozenset({"CA5392", "CA5393", "CA5394", "SCS0005"})
_CONTAINER_PREFIXES = ("file:///work/", "/work/", "file:///src/", "/src/", "file:///repo/", "/repo/", "./")


def relativize(value: str) -> str:
    for prefix in _CONTAINER_PREFIXES:
        if value.startswith(prefix):
            return value[len(prefix):]
    return value


def _write_json(path: Path, data) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")
    os.chmod(path, 0o600)


def normalize_opengrep(path: Path) -> int:
    """Make `path` entries relative to the project root; return the number of results."""
    data = json.loads(path.read_text(encoding="utf-8"))
    results = data.get("results", [])
    for result in results:
        if isinstance(result.get("path"), str):
            result["path"] = relativize(result["path"])
    _write_json(path, data)
    return len(results)


def normalize_gitleaks(path: Path) -> int:
    findings = json.loads(path.read_text(encoding="utf-8") or "[]") or []
    for finding in findings:
        if isinstance(finding.get("File"), str):
            finding["File"] = relativize(finding["File"])
    _write_json(path, findings)
    return len(findings)


def sarif_level(rule_id: str) -> str:
    """SARIF level (and so DefectDojo severity) of a security rule: error=High, warning=Medium, note=Low."""
    if rule_id in HIGH_RULES:
        return "error"
    if rule_id in LOW_RULES:
        return "note"
    return "warning"


def _is_security(rule_id: str | None, category: str | None) -> bool:
    return category == "Security" or rule_id in CA_RULE_IDS or bool(rule_id and SCS_RULE.match(rule_id))


def merge_sarif(sources: list[Path], target: Path) -> int:
    """Merge Roslyn SARIF logs into one file keeping only the security rules; return the result count.

    A rule is security when its descriptor has the `Security` category (any analyzer: SDK, SecurityCodeScan,
    Meziantou) or it is one of the fixed ids above. Quality rules (CA1xxx, Meziantou design rules, Roslynator...) are
    dropped here: they reach SonarQube as external issues, never DefectDojo. DefectDojo closes old findings per import,
    so a single merged file avoids one project closing the findings of another.
    """
    runs, total = [], 0
    for source in sorted(sources):
        data = json.loads(source.read_text(encoding="utf-8"))
        for run in data.get("runs", []):
            rules = run.get("tool", {}).get("driver", {}).get("rules", []) or []
            category = {r.get("id"): (r.get("properties") or {}).get("category") for r in rules}
            kept, used = [], []
            for result in run.get("results", []):
                rule_id = result.get("ruleId")
                if not _is_security(rule_id, category.get(rule_id)):
                    continue
                result["level"] = sarif_level(rule_id)
                for location in result.get("locations", []):
                    artifact = location.get("physicalLocation", {}).get("artifactLocation", {})
                    if isinstance(artifact.get("uri"), str):
                        artifact["uri"] = relativize(artifact["uri"])
                if rule_id not in used:
                    used.append(rule_id)
                kept.append(result)
            run["results"] = kept
            if rules:
                by_id = {r.get("id"): r for r in rules}
                run["tool"]["driver"]["rules"] = [by_id[i] for i in used if i in by_id]
                for result in kept:
                    result["ruleIndex"] = used.index(result["ruleId"]) if result["ruleId"] in by_id else result.get("ruleIndex")
            total += len(kept)
            runs.append(run)
    if not runs:
        raise ValueError("no SARIF logs to merge")
    _write_json(
        target,
        {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": runs,
        },
    )
    return total


# ----------------------------------------------------------------------------- ESLint
ESLINT_SECURITY_PREFIXES = ("security/", "no-unsanitized/")
_SONAR_SEVERITY = {2: "MEDIUM", 1: "LOW"}
_SONAR_SECURITY_SEVERITY = {2: "HIGH", 1: "MEDIUM"}


def is_eslint_security_rule(rule_id: str | None) -> bool:
    return bool(rule_id) and rule_id.startswith(ESLINT_SECURITY_PREFIXES)


def _text_range(message: dict) -> dict:
    start_line = int(message.get("line") or 1)
    start_col = max(int(message.get("column") or 1) - 1, 0)
    end_line = int(message.get("endLine") or start_line)
    end_col = max(int(message.get("endColumn") or 0) - 1, 0)
    if end_line == start_line and end_col <= start_col:
        end_col = start_col + 1  # SonarQube rejects empty ranges
    return {"startLine": start_line, "endLine": end_line, "startColumn": start_col, "endColumn": end_col}


def split_eslint(raw: Path, dojo_out: Path, sonar_out: Path) -> dict[str, int]:
    """Split one ESLint JSON report by destination; return the number of security and quality findings.

    * `dojo_out`: only the security-plugin rules, in ESLint's own JSON shape (DefectDojo `ESLint Scan` parser).
    * `sonar_out`: every rule, in SonarQube's Generic Issue Format (`sonar.externalIssuesReportPaths`).
    Messages without a rule id (parse errors) are dropped: they are not findings.
    """
    files = json.loads(raw.read_text(encoding="utf-8") or "[]") or []
    dojo_files: list[dict] = []
    rules: dict[str, dict] = {}
    issues: list[dict] = []
    counts = {"security": 0, "quality": 0}
    for entry in files:
        path = relativize(entry.get("filePath", ""))
        security_messages = []
        for message in entry.get("messages", []):
            rule_id = message.get("ruleId")
            if not rule_id:
                continue
            security = is_eslint_security_rule(rule_id)
            severity = int(message.get("severity") or 1)
            counts["security" if security else "quality"] += 1
            if security:
                security_messages.append(message)
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": rule_id,
                    "description": f"ESLint rule {rule_id}.",
                    "engineId": "eslint",
                    "cleanCodeAttribute": "TRUSTWORTHY" if security else "CONVENTIONAL",
                    "type": "VULNERABILITY" if security else "CODE_SMELL",
                    "severity": "MAJOR",
                    "impacts": [
                        {
                            "softwareQuality": "SECURITY" if security else "MAINTAINABILITY",
                            "severity": (_SONAR_SECURITY_SEVERITY if security else _SONAR_SEVERITY).get(severity, "MEDIUM"),
                        }
                    ],
                }
            issues.append(
                {
                    "ruleId": rule_id,
                    "primaryLocation": {
                        "message": str(message.get("message") or rule_id),
                        "filePath": path,
                        "textRange": _text_range(message),
                    },
                }
            )
        if security_messages:
            dojo_files.append({**entry, "filePath": path, "messages": security_messages})
    _write_json(dojo_out, dojo_files)
    _write_json(sonar_out, {"rules": list(rules.values()), "issues": issues})
    return counts
