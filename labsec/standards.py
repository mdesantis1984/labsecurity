"""Standards checks that Opengrep rules cannot express: absence of files and structured JSON/.npmrc content.

Each check returns findings in the Opengrep JSON result shape, so `augment_report` can append them to
`opengrep.json` and DefectDojo imports them with the "Semgrep JSON Report" parser, like every other own rule.
Rule ids follow `labsec.<area>.<name>`; every id is described in `RULES` (standard, CWE, severity, confidence).
Opt-in checks have severity INFO (imported as Low) and run only when `optin=True`.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from labsec.langs import SKIP_DIRS

_OPENSSF_NPM = "https://github.com/ossf/package-manager-best-practices/blob/main/published/npm.md"
_OWASP_NPM = "https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html"
_ANGULAR_SECURITY = "https://angular.dev/best-practices/security"
_ANGULAR_WORKSPACE = "https://angular.dev/reference/configs/workspace-config"
_CLOUDFLARE_WORKERS_CONFIG = "https://developers.cloudflare.com/workers/configuration/"
OWASP_TOP10_2025 = {
    "A01:2025 - Broken Access Control",
    "A02:2025 - Security Misconfiguration",
    "A03:2025 - Software Supply Chain Failures",
    "A04:2025 - Cryptographic Failures",
    "A05:2025 - Injection",
    "A06:2025 - Insecure Design",
    "A07:2025 - Authentication Failures",
    "A08:2025 - Software or Data Integrity Failures",
    "A09:2025 - Security Logging and Alerting Failures",
    "A10:2025 - Mishandling of Exceptional Conditions",
}  # https://owasp.org/Top10/2025/
_OWASP_SUPPLY_CHAIN = "A03:2025 - Software Supply Chain Failures"
_OWASP_INTEGRITY = "A08:2025 - Software or Data Integrity Failures"
_OWASP_MISCONFIG = "A02:2025 - Security Misconfiguration"
_OWASP_CRYPTO = "A04:2025 - Cryptographic Failures"
_OWASP_AUTH = "A07:2025 - Authentication Failures"

# Opengrep prefixes the ids of the rules it loads from the mounted custom directory (/rules/custom) with the dotted
# directory path; findings from this module carry the same prefix so every own rule looks alike in DefectDojo.
REPORT_PREFIX = "rules.custom."

LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb")
_JSON_LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json")

RULES: dict[str, dict] = {
    "labsec.npm.no-lockfile": {
        "severity": "WARNING",
        "confidence": "MEDIUM",
        "cwe": "CWE-1357: Reliance on Insufficiently Trustworthy Component",
        "owasp": _OWASP_SUPPLY_CHAIN,
        "standard": "OpenSSF Package Manager Best Practices, npm, Use a Lockfile; OWASP NPM Security Cheat Sheet, Enforce the lockfile",
        "references": [_OPENSSF_NPM, _OWASP_NPM],
        "message": (
            "package.json declares dependencies but no lockfile is committed in this directory or above it. Without a "
            "lockfile every install can resolve different versions. Commit package-lock.json, pnpm-lock.yaml or "
            "yarn.lock and install with `npm ci` (libraries may choose differently)."
        ),
    },
    "labsec.npm.lockfile-insecure-source": {
        "severity": "WARNING",
        "confidence": "HIGH",
        "cwe": "CWE-829: Inclusion of Functionality from Untrusted Control Sphere",
        "owasp": _OWASP_INTEGRITY,
        "standard": "OpenSSF Package Manager Best Practices, npm, package-lock.json; OWASP ASVS 5.0.0 V15.2.4",
        "asvs": ["V15.2.4"],
        "references": [_OPENSSF_NPM, "https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x24-V15-Secure-Coding-and-Architecture.md"],
        "message": (
            "The npm lockfile resolves packages over plain HTTP (http:// or git+http://). A network attacker can swap "
            "the tarball. Use an HTTPS registry and regenerate the lockfile."
        ),
    },
    "labsec.npm.lockfile-no-integrity": {
        "severity": "WARNING",
        "confidence": "HIGH",
        "cwe": "CWE-494: Download of Code Without Integrity Check",
        "owasp": _OWASP_INTEGRITY,
        "standard": "OpenSSF Package Manager Best Practices, npm, package-lock.json (integrity field)",
        "references": [_OPENSSF_NPM],
        "message": (
            "The npm lockfile has resolved packages without an integrity hash, so the installed tarball is not "
            "verified against the lockfile. Regenerate the lockfile with a current npm and commit it."
        ),
    },
    "labsec.npm.npmrc-strict-ssl-disabled": {
        "severity": "WARNING",
        "confidence": "HIGH",
        "cwe": "CWE-295: Improper Certificate Validation",
        "owasp": _OWASP_AUTH,
        "standard": "npm docs, config: strict-ssl; OWASP ASVS 5.0.0 V12.3.2",
        "asvs": ["V12.3.2"],
        "references": ["https://docs.npmjs.com/cli/v11/using-npm/config", "https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x21-V12-Secure-Communication.md"],
        "message": ".npmrc sets strict-ssl=false, so npm accepts any TLS certificate from the registry. Remove it and trust the proper CA instead.",
    },
    "labsec.npm.npmrc-http-registry": {
        "severity": "WARNING",
        "confidence": "HIGH",
        "cwe": "CWE-319: Cleartext Transmission of Sensitive Information",
        "owasp": _OWASP_CRYPTO,
        "standard": "npm docs, config: registry; OWASP ASVS 5.0.0 V12.3.1",
        "asvs": ["V12.3.1"],
        "references": ["https://docs.npmjs.com/cli/v11/using-npm/config", "https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x21-V12-Secure-Communication.md"],
        "message": ".npmrc points a registry at a plain http:// URL, so packages and credentials travel unencrypted. Use https://.",
    },
    "labsec.npm.npmrc-literal-auth-token": {
        "severity": "ERROR",
        "confidence": "HIGH",
        "cwe": "CWE-798: Use of Hard-coded Credentials",
        "owasp": _OWASP_AUTH,
        "standard": "OpenSSF Package Manager Best Practices, npm (do not commit ~/.npmrc credentials)",
        "references": [_OPENSSF_NPM],
        "message": (
            ".npmrc contains a literal _authToken or _auth value. Reference an environment variable "
            "(_authToken=${NPM_TOKEN}) and rotate the committed token."
        ),
    },
    "labsec.angular.allowed-hosts-wildcard": {
        "severity": "WARNING",
        "confidence": "MEDIUM",
        "cwe": "CWE-918: Server-Side Request Forgery (SSRF)",
        "owasp": "A01:2025 - Broken Access Control",
        "standard": "angular.dev security guide, Configuring allowed hosts (a bare * 'presents a security risk')",
        "references": [_ANGULAR_SECURITY, _ANGULAR_WORKSPACE],
        "message": (
            'angular.json lists "*" in security.allowedHosts, which accepts any Host header and exposes server-side '
            "rendering to host header injection and SSRF. List the real hostnames, unless a proxy validates the header."
        ),
    },
    # Opt-in checks (INFO): often legitimate, reviewed by a human.
    "labsec.npm.npmrc-ignore-scripts-absent": {
        "severity": "INFO",
        "confidence": "LOW",
        "cwe": "CWE-829: Inclusion of Functionality from Untrusted Control Sphere",
        "owasp": _OWASP_INTEGRITY,
        "standard": "OWASP NPM Security Cheat Sheet, Minimize attack surfaces by ignoring run-scripts",
        "references": [_OWASP_NPM],
        "message": "No .npmrc sets ignore-scripts=true, so lifecycle scripts of every dependency run on install. Consider ignore-scripts=true with an allowlist.",
    },
    "labsec.npm.npmrc-min-release-age-absent": {
        "severity": "INFO",
        "confidence": "LOW",
        "cwe": "CWE-829: Inclusion of Functionality from Untrusted Control Sphere",
        "owasp": _OWASP_INTEGRITY,
        "standard": "npm docs, config: min-release-age (npm v11.10.0 and later)",
        "references": ["https://docs.npmjs.com/cli/v11/using-npm/config"],
        "message": "No .npmrc sets min-release-age, so a freshly published malicious version can be installed immediately. Consider min-release-age=1 (days).",
    },
    "labsec.angular.autocsp-unsafe-eval": {
        "severity": "INFO",
        "confidence": "HIGH",
        "cwe": "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "owasp": "A05:2025 - Injection",
        "standard": "angular.dev workspace configuration, Security configuration (autoCsp unsafeEval)",
        "references": [_ANGULAR_WORKSPACE],
        "message": "security.autoCsp enables unsafeEval, so the generated Content Security Policy allows eval. Remove unsafeEval if the application does not need it.",
    },
    "labsec.cloudflare.dev-vars-committed": {
        "severity": "ERROR",
        "confidence": "HIGH",
        "cwe": "CWE-798: Use of Hard-coded Credentials",
        "cwe_secondary": "CWE-312: Cleartext Storage of Sensitive Information",
        "owasp": _OWASP_AUTH,
        "standard": "Cloudflare Workers configuration docs: local development variables files are not for version control (add them to .gitignore); sensitive values belong in encrypted values or store bindings",
        "references": [_CLOUDFLARE_WORKERS_CONFIG],
        "message": (
            "A Cloudflare Workers local variables file (.dev.vars or .dev.vars.<environment>) is committed to the "
            "repository. It holds the values `wrangler dev` injects, usually real credentials. Remove it from the "
            "index (`git rm --cached`), add `.dev.vars*` to .gitignore, rotate every value it contains because the history "
            "keeps it, and commit a `.dev.vars.example` with empty values instead."
        ),
    },
    "labsec.angular.production-source-map": {
        "severity": "INFO",
        "confidence": "LOW",
        "cwe": "CWE-540: Inclusion of Sensitive Information in Source Code",
        "owasp": _OWASP_MISCONFIG,
        "standard": "angular.dev workspace configuration, build options (sourceMap, hidden, sourcesContent)",
        "references": [_ANGULAR_WORKSPACE],
        "message": "The production configuration emits visible script source maps, which publish the original source. Use hidden maps that are not deployed, or disable them.",
    },
}


# ----------------------------------------------------------------------------- helpers
def _finding(rule_id: str, rel_path: str, line: int, extra_message: str = "", snippet: str = "") -> dict:
    spec = RULES[rule_id]
    metadata = {
        "category": "security",
        "cwe": spec["cwe"],
        "owasp": spec["owasp"],
        "standard": spec["standard"],
        "confidence": spec["confidence"],
        "references": list(spec["references"]),
        "source": "labsec.standards",
    }
    if "asvs" in spec:
        metadata["asvs"] = list(spec["asvs"])
    if "cwe_secondary" in spec:
        metadata["cwe_secondary"] = spec["cwe_secondary"]
    return {
        "check_id": REPORT_PREFIX + rule_id,
        "path": rel_path,
        "start": {"line": line, "col": 1, "offset": 0},
        "end": {"line": line, "col": 1, "offset": 0},
        "extra": {
            "message": f"{spec['message']} {extra_message}".strip(),
            "severity": spec["severity"],
            "metadata": metadata,
            "lines": snippet,
        },
    }


def _walk(root: Path, names: set[str]):
    """Yield (relative POSIX path, absolute path) of files with one of `names`, skipping dependency/build dirs."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if name in names:
                full = Path(dirpath) / name
                yield full.relative_to(root).as_posix(), full


def _line_of(text: str, needle: str) -> int:
    index = text.find(needle)
    return text.count("\n", 0, index) + 1 if index >= 0 else 1


def strip_json_comments(text: str) -> str:
    """Remove // and /* */ comments outside strings (angular.json accepts them)."""
    out, i, n, in_string = [], 0, len(text), False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
            out.append(ch)
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 1
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def _load_json(path: Path):
    try:
        return json.loads(strip_json_comments(path.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return None


# ----------------------------------------------------------------------------- npm
def _has_lockfile(root: Path, directory: Path) -> bool:
    current = directory
    while True:
        if any((current / name).is_file() for name in LOCKFILES):
            return True
        if current == root or root not in current.parents:
            return False
        current = current.parent


def _declares_dependencies(data) -> bool:
    return isinstance(data, dict) and any(
        isinstance(data.get(key), dict) and data[key] for key in ("dependencies", "devDependencies", "optionalDependencies")
    )


def _lock_entries(data: dict):
    """Yield (name, entry) for every locked package of lockfile v1, v2 and v3."""
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, entry in packages.items():
            if key and isinstance(entry, dict):
                yield key.rsplit("node_modules/", 1)[-1], entry
    else:

        def visit(deps):
            for name, entry in (deps or {}).items():
                if isinstance(entry, dict):
                    yield name, entry
                    yield from visit(entry.get("dependencies"))

        yield from visit(data.get("dependencies"))


def _summary(names: list[str]) -> str:
    shown = ", ".join(names[:3]) + (", ..." if len(names) > 3 else "")
    return f"Affected: {len(names)} package(s), for example {shown}."


def check_npm(root: Path, optin: bool = False) -> list[dict]:
    findings: list[dict] = []
    package_dirs: list[Path] = []
    for rel, path in _walk(root, {"package.json"}):
        if _declares_dependencies(_load_json(path)):
            package_dirs.append(path.parent)
            if not _has_lockfile(root, path.parent):
                findings.append(_finding("labsec.npm.no-lockfile", rel, 1, snippet="package.json"))

    for rel, path in _walk(root, set(_JSON_LOCKFILES)):
        data = _load_json(path)
        if not isinstance(data, dict):
            continue
        text = path.read_text(encoding="utf-8")
        insecure, no_integrity = [], []
        for name, entry in _lock_entries(data):
            resolved = entry.get("resolved")
            if not isinstance(resolved, str) or entry.get("link"):
                continue
            if resolved.startswith(("http://", "git+http://")):
                insecure.append((name, resolved))
            if "integrity" not in entry and not resolved.startswith(("file:", "git+", "github:")):
                no_integrity.append((name, resolved))
        if insecure:
            findings.append(_finding("labsec.npm.lockfile-insecure-source", rel, _line_of(text, insecure[0][1]), _summary([n for n, _ in insecure])))
        if no_integrity:
            findings.append(_finding("labsec.npm.lockfile-no-integrity", rel, _line_of(text, f'"resolved": "{no_integrity[0][1]}"'), _summary([n for n, _ in no_integrity])))

    npmrc_with_scripts_off = False
    npmrc_with_release_age = False
    for rel, path in _walk(root, {".npmrc"}):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for number, raw in enumerate(lines, start=1):
            line = raw.strip()
            if not line or line.startswith((";", "#")) or "=" not in line:
                continue
            key, _, value = (part.strip() for part in line.partition("="))
            lowered = value.lower()
            if key == "strict-ssl" and lowered == "false":
                findings.append(_finding("labsec.npm.npmrc-strict-ssl-disabled", rel, number, snippet=line))
            elif (key == "registry" or key.endswith(":registry")) and lowered.startswith("http://") and not re.match(r"http://(localhost|127\.0\.0\.1|\[::1\])(:|/|$)", lowered):
                findings.append(_finding("labsec.npm.npmrc-http-registry", rel, number, snippet=line.split("=", 1)[0] + "=<redacted>"))
            elif key.endswith(("_authToken", "_auth", "_password")) and value and "${" not in value:
                findings.append(_finding("labsec.npm.npmrc-literal-auth-token", rel, number, snippet=key + "=<redacted>"))
            if key == "ignore-scripts" and lowered == "true":
                npmrc_with_scripts_off = True
            if key == "min-release-age":
                npmrc_with_release_age = True
    if optin and package_dirs:
        top = min(package_dirs, key=lambda p: len(p.parts))
        rel = (top / "package.json").relative_to(root).as_posix()
        if not npmrc_with_scripts_off:
            findings.append(_finding("labsec.npm.npmrc-ignore-scripts-absent", rel, 1, snippet="package.json"))
        if not npmrc_with_release_age:
            findings.append(_finding("labsec.npm.npmrc-min-release-age-absent", rel, 1, snippet="package.json"))
    return findings


# ----------------------------------------------------------------------------- Angular workspace
def _find_key(node, key: str):
    if isinstance(node, dict):
        for name, value in node.items():
            if name == key:
                yield value
            yield from _find_key(value, key)
    elif isinstance(node, list):
        for item in node:
            yield from _find_key(item, key)


def _source_map_visible(value) -> bool:
    if value is True:
        return True
    return isinstance(value, dict) and value.get("scripts", True) is not False and value.get("hidden", False) is not True


def check_angular(root: Path, optin: bool = False) -> list[dict]:
    findings: list[dict] = []
    for rel, path in _walk(root, {"angular.json"}):
        data = _load_json(path)
        if not isinstance(data, dict):
            continue
        text = path.read_text(encoding="utf-8")
        for hosts in _find_key(data, "allowedHosts"):
            if isinstance(hosts, list) and "*" in hosts:
                findings.append(_finding("labsec.angular.allowed-hosts-wildcard", rel, _line_of(text, '"allowedHosts"'), snippet='"allowedHosts"'))
        if not optin:
            continue
        for csp in _find_key(data, "autoCsp"):
            if isinstance(csp, dict) and csp.get("unsafeEval") is True:
                findings.append(_finding("labsec.angular.autocsp-unsafe-eval", rel, _line_of(text, '"unsafeEval"'), snippet='"unsafeEval"'))
        for project in (data.get("projects") or {}).values():
            for target in ((project or {}).get("architect") or {}).values():
                production = ((target or {}).get("configurations") or {}).get("production")
                if isinstance(production, dict) and _source_map_visible(production.get("sourceMap")):
                    findings.append(_finding("labsec.angular.production-source-map", rel, _line_of(text, '"sourceMap"'), snippet='"sourceMap"'))
    return findings


# ----------------------------------------------------------------------------- Cloudflare Workers
DEV_VARS = re.compile(r"^\.dev\.vars(\.[A-Za-z0-9_-]+)?$")
_TEMPLATE_SUFFIXES = {"example", "sample", "template", "dist", "tpl"}


def _is_dev_vars(name: str) -> bool:
    match = DEV_VARS.match(name)
    return bool(match) and (match.group(1) or "").lstrip(".").lower() not in _TEMPLATE_SUFFIXES


def check_cloudflare(root: Path, optin: bool = False, tracked: set[str] | None = None) -> list[dict]:
    """Flag committed `.dev.vars` and `.dev.vars.<env>` files (templates such as `.dev.vars.example` are fine).

    `tracked` is the set of paths git tracks (relative to `root`). When it is given, only tracked files count, so a file
    that .gitignore keeps out of the repository is not reported. Without git information every such file counts.
    The finding never includes the file's content.
    """
    findings: list[dict] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if not _is_dev_vars(name):
                continue
            rel = (Path(dirpath) / name).relative_to(root).as_posix()
            if tracked is None or rel in tracked:
                findings.append(_finding("labsec.cloudflare.dev-vars-committed", rel, 1, snippet=name))
    return findings


# ----------------------------------------------------------------------------- entry points
def run_checks(root: Path, optin: bool = False, tracked: set[str] | None = None) -> list[dict]:
    root = Path(root).resolve()
    return check_npm(root, optin) + check_angular(root, optin) + check_cloudflare(root, optin, tracked)


def augment_report(report: Path, root: Path, optin: bool = False, tracked: set[str] | None = None) -> int:
    """Append the standards findings to an Opengrep JSON report (written 0600 like the rest); return how many."""
    data = json.loads(report.read_text(encoding="utf-8"))
    findings = run_checks(root, optin, tracked)
    data.setdefault("results", []).extend(findings)
    report.write_text(json.dumps(data), encoding="utf-8")
    os.chmod(report, 0o600)
    return len(findings)
