"""SonarQube "all rules": one `LabSecurity` quality profile per language, every available rule active, set as default.

SonarQube's built-in "Sonar way" profiles activate only part of the rules (for example C# 121 of 456). The lab wants every
rule, so `--bootstrap` creates the profiles and `--doctor` checks them. Quality-only findings stay in SonarQube: the DefectDojo
export (labsec/sonar.py) carries only the security ones.
"""

from __future__ import annotations

PROFILE_NAME = "LabSecurity"


def _find(profiles: list[dict], name: str) -> dict | None:
    return next((p for p in profiles if p.get("name") == name), None)


def sync_profiles(sonar, say=lambda message: None) -> list[dict]:
    """Create/complete the profile of every language that has rules and make it the default. Idempotent."""
    rows = []
    for language in sorted(sonar.language_keys()):
        total = sonar.rule_total(language)
        if total == 0:
            continue
        profile = _find(sonar.quality_profiles(language), PROFILE_NAME)
        if profile is None:
            profile = sonar.create_profile(language, PROFILE_NAME)
            profile = {**profile, "activeRuleCount": 0}
        failed = 0
        if int(profile.get("activeRuleCount", 0)) < total:
            result = sonar.activate_all_rules(profile["key"], language)
            failed = int(result.get("failed", 0))
        if not profile.get("isDefault"):
            sonar.set_default_profile(language, PROFILE_NAME)
        current = _find(sonar.quality_profiles(language), PROFILE_NAME) or {}
        rows.append(
            {
                "language": language,
                "active": int(current.get("activeRuleCount", 0)),
                "total": total,
                "default": bool(current.get("isDefault")),
                "failed": failed,
            }
        )
        say(f"SonarQube profile {PROFILE_NAME} [{language}]: {rows[-1]['active']}/{total} rules active, default={rows[-1]['default']}")
    return rows


def profile_report(rows: list[dict]) -> str:
    return ", ".join(f"{row['language']} {row['active']}/{row['total']}" for row in rows)


def inspect_profiles(sonar) -> list[dict]:
    """Current state per language with rules (read-only): used by `--doctor`."""
    rows = []
    for language in sorted(sonar.language_keys()):
        total = sonar.rule_total(language)
        if total == 0:
            continue
        profile = _find(sonar.quality_profiles(language), PROFILE_NAME)
        rows.append(
            {
                "language": language,
                "total": total,
                "present": profile is not None,
                "active": int((profile or {}).get("activeRuleCount", 0)),
                "default": bool((profile or {}).get("isDefault")),
            }
        )
    return rows
