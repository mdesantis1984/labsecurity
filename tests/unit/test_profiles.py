from labsec.doctor import check_profiles
from labsec.profiles import PROFILE_NAME, profile_report, sync_profiles


class FakeSonar:
    """In-memory SonarQube: one language list, rule totals and quality profiles."""

    def __init__(self, totals, failed=None):
        self.totals = dict(totals)
        self.failed = failed or {}
        self.profiles = {lang: [{"key": f"{lang}-core", "name": "Sonar way core", "isDefault": True, "activeRuleCount": 5}] for lang in totals}
        self.calls = []

    def language_keys(self):
        return sorted(self.totals) + ["empty"]

    def rule_total(self, language):
        return self.totals.get(language, 0)

    def quality_profiles(self, language):
        return list(self.profiles.get(language, []))

    def create_profile(self, language, name):
        self.calls.append(("create", language, name))
        profile = {"key": f"{language}-ls", "name": name, "isDefault": False, "activeRuleCount": 0}
        self.profiles[language].append(profile)
        return profile

    def activate_all_rules(self, key, language):
        self.calls.append(("activate", language))
        failed = self.failed.get(language, 0)
        for profile in self.profiles[language]:
            if profile["key"] == key:
                profile["activeRuleCount"] = self.totals[language] - failed
        return {"succeeded": self.totals[language] - failed, "failed": failed}

    def set_default_profile(self, language, name):
        self.calls.append(("default", language, name))
        for profile in self.profiles[language]:
            profile["isDefault"] = profile["name"] == name


def test_sync_creates_activates_and_defaults_one_profile_per_language_with_rules():
    sonar = FakeSonar({"cs": 456, "ts": 553})
    rows = sync_profiles(sonar)
    assert [r["language"] for r in rows] == ["cs", "ts"]  # "empty" has no rules: no profile
    assert [(r["active"], r["total"], r["default"]) for r in rows] == [(456, 456, True), (553, 553, True)]
    assert ("create", "cs", PROFILE_NAME) in sonar.calls
    assert not any(call[1] == "empty" for call in sonar.calls)


def test_sync_is_idempotent_and_does_not_touch_a_complete_default_profile():
    sonar = FakeSonar({"cs": 456})
    sync_profiles(sonar)
    sonar.calls.clear()
    rows = sync_profiles(sonar)
    assert sonar.calls == []
    assert rows[0]["active"] == rows[0]["total"] == 456


def test_sync_reactivates_when_new_rules_appear_after_an_upgrade():
    sonar = FakeSonar({"cs": 456})
    sync_profiles(sonar)
    sonar.totals["cs"] = 460
    sonar.calls.clear()
    rows = sync_profiles(sonar)
    assert sonar.calls == [("activate", "cs")]
    assert rows[0]["active"] == 460


def test_rules_that_cannot_be_activated_are_reported_not_hidden():
    sonar = FakeSonar({"py": 453}, failed={"py": 2})
    row = sync_profiles(sonar)[0]
    assert (row["active"], row["total"], row["failed"]) == (451, 453, 2)


def test_doctor_check_ok_when_every_profile_is_default_and_complete():
    sonar = FakeSonar({"cs": 456, "ts": 553})
    sync_profiles(sonar)
    result = check_profiles(sonar)
    assert result["status"] == "ok"
    assert "cs 456/456" in result["detail"] and "ts 553/553" in result["detail"]


def test_doctor_check_fails_when_the_default_is_not_labsecurity():
    sonar = FakeSonar({"cs": 456})
    sync_profiles(sonar)
    sonar.set_default_profile("cs", "Sonar way core")
    result = check_profiles(sonar)
    assert result["status"] == "fail" and "cs" in result["detail"] and "not the default" in result["detail"]


def test_doctor_check_fails_when_the_profile_is_missing_or_incomplete():
    sonar = FakeSonar({"cs": 456, "ts": 553})
    assert check_profiles(sonar)["status"] == "fail"  # never bootstrapped
    sync_profiles(sonar)
    for profile in sonar.profiles["ts"]:
        if profile["name"] == PROFILE_NAME:
            profile["activeRuleCount"] = 500
    result = check_profiles(sonar)
    assert result["status"] == "fail" and "ts 500/553" in result["detail"]


def test_profile_report_is_a_compact_active_over_total_line():
    rows = [{"language": "cs", "active": 456, "total": 456, "default": True, "failed": 0}]
    assert profile_report(rows) == "cs 456/456"


def test_rule_total_excludes_templates_which_cannot_be_activated(monkeypatch):
    from labsec.sonar import SonarClient

    seen = {}

    def fake_request(self, method, path, **kwargs):
        seen.update(path=path, params=kwargs["params"])
        return {"paging": {"total": 440}}

    monkeypatch.setattr(SonarClient, "_request", fake_request)
    assert SonarClient("http://sonar.invalid", token="x").rule_total("py") == 440
    assert seen["path"] == "/api/rules/search"
    assert seen["params"]["is_template"] == "false" and seen["params"]["languages"] == "py"
