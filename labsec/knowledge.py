"""Static remediation knowledge: CWE labels, fix templates and test-first proofs (no payloads, no exploit details)."""

from __future__ import annotations

CWE_LABELS = {
    22: "path traversal",
    78: "OS command injection",
    79: "cross-site scripting (XSS)",
    89: "SQL injection",
    94: "code injection",
    95: "eval injection",
    259: "hard-coded password",
    295: "improper certificate validation",
    327: "weak cryptography",
    352: "cross-site request forgery",
    502: "unsafe deserialization",
    532: "sensitive data in logs",
    601: "open redirect",
    611: "XML external entity",
    693: "weak protection mechanism (headers/CSP)",
    798: "hard-coded credentials",
    918: "server-side request forgery",
    1104: "unmaintained or vulnerable component",
}

# .NET security analyzers shipped with the lab (CA2100, CA3001-CA3012) -> closest CWE.
CA_RULE_CWE = {
    "CA2100": 89,
    "CA3001": 89,
    "CA3002": 79,
    "CA3003": 22,
    "CA3006": 78,
    "CA3007": 601,
    "CA3009": 611,
}

SECRET_CWES = frozenset({259, 321, 540, 798})
_SECRET_WORDS = ("secret", "token", "credential", "password", "private key", "api key", "api-key")

CWE_CATEGORY = {
    22: "path",
    78: "command",
    79: "xss",
    89: "sql",
    94: "eval",
    95: "eval",
    259: "secret",
    321: "secret",
    327: "crypto",
    352: "csrf",
    502: "deserialization",
    540: "secret",
    601: "redirect",
    611: "xxe",
    693: "headers",
    798: "secret",
    918: "ssrf",
    1104: "dependency",
}

FIXES = {
    "sql": (
        "Stop building SQL text from input. Use parameters: EF Core `FromSqlInterpolated`/`ExecuteSqlInterpolated`, "
        "or `NpgsqlParameter`/`command.Parameters` with a constant command text."
    ),
    "xss": (
        "Remove `innerHTML`/`document.write`/`bypassSecurityTrust*`. Use text binding (`{{ }}` or `[textContent]`); "
        "if HTML is unavoidable, pass it through Angular's `DomSanitizer.sanitize` or a vetted sanitizer."
    ),
    "secret": (
        "Treat the credential as leaked: rotate it first, remove it from the code and load it from configuration or a "
        "secret store, then purge it from the git history (needs the owner's approval; never force-push without it)."
    ),
    "dependency": (
        "Upgrade the component to the fixed version reported by Trivy (see the DefectDojo finding), update the lockfile "
        "and run the project's test suite."
    ),
    "misconfig": "Apply the configuration recommendation reported by Trivy (see the DefectDojo finding) and re-run the lab.",
    "path": "Canonicalize the path and check it stays inside an allowed base directory; reject anything else.",
    "command": "Do not go through a shell: call the program with an argument array and an allow-list of values.",
    "eval": "Remove the dynamic code evaluation; replace it with a lookup table, a parser or a configured strategy.",
    "crypto": "Replace the weak algorithm with a current one (AES-GCM, SHA-256 or stronger, bcrypt/Argon2 for passwords).",
    "csrf": "Require an anti-forgery token (or SameSite cookies plus an origin check) on state-changing requests.",
    "deserialization": "Do not deserialize untrusted data into arbitrary types; use a strict schema with an allow-list of types.",
    "redirect": "Redirect only to relative paths or to an allow-list of hosts.",
    "xxe": "Disable DTD and external entity resolution in the XML parser.",
    "ssrf": "Resolve outbound targets from an allow-list; never fetch a URL taken straight from input.",
    "headers": "Set the missing security header or tighten the CSP in the server configuration, then verify the response.",
    "generic": (
        "Apply the project's secure coding convention for this rule and document the decision in the test; "
        "see the rule or CWE referenced above."
    ),
}

# What the failing test should demonstrate, without any payload.
PROOFS = {
    "sql": "a test that sends a quote character through the entry point and asserts the value is handled as data",
    "xss": "a test that renders markup-like text and asserts it appears as plain text, not as elements",
    "secret": "a test (or CI check) that fails while the secret pattern is present in the sources or the configuration",
    "dependency": "a test or lockfile check that fails while the vulnerable version is resolved",
    "misconfig": "a check that fails while the insecure setting is present",
    "path": "a test that passes a parent-directory segment and asserts the request is rejected",
    "command": "a test that passes a shell metacharacter and asserts it is treated as a literal argument",
}

TEST_FIRST = (
    "first write a test that fails and reproduces the problem, then apply the fix and show the test passing"
)
AUTHORIZATION = "check project rules before fixing (e.g. backend changes may need owner approval)"


def is_secret(view: dict) -> bool:
    if view.get("tool") == "gitleaks" or view.get("cwe") in SECRET_CWES:
        return True
    title = (view.get("title") or "").lower()
    return any(word in title for word in _SECRET_WORDS)


def effective_cwe(view: dict) -> int | None:
    if view.get("cwe"):
        return int(view["cwe"])
    rule = (view.get("rule") or "").upper()
    return CA_RULE_CWE.get(rule)


def category(view: dict) -> str:
    if is_secret(view):
        return "secret"
    rule = (view.get("rule") or "").lower()
    title = (view.get("title") or "").lower()
    if view.get("tool") == "trivy":
        ident = rule or title
        if ident.startswith(("cve-", "ghsa-")) or title.startswith(("cve-", "ghsa-")) or view.get("cwe") in (1104, 937):
            return "dependency"
        return "misconfig"
    cwe = effective_cwe(view)
    if cwe in CWE_CATEGORY:
        return CWE_CATEGORY[cwe]
    text = f"{rule} {title}"
    if any(word in text for word in ("innerhtml", "bypasssecuritytrust", "document.write")):
        return "xss"
    if "eval" in text:
        return "eval"
    if "sql" in text:
        return "sql"
    return "generic"


def _humanize(title: str) -> str:
    """Rule ids (`rules.custom.labsec.csharp.sql-raw-built-text`) become short words (`sql raw built text`)."""
    if " " in title or not ("." in title or "-" in title or "_" in title):
        return title
    last = title.rsplit(".", 1)[-1]
    return last.replace("-", " ").replace("_", " ")


def explanation(view: dict) -> str:
    """One line: the finding title plus the CWE label when known. Never description text or payloads."""
    title = _humanize((view.get("title") or "finding").strip())
    if len(title) > 110:
        title = title[:107].rstrip() + "..."
    cwe = effective_cwe(view)
    label = CWE_LABELS.get(cwe) if cwe else None
    if label and label.split(" (")[0].lower() not in title.lower():
        return f"{title} - {label}"
    return title
