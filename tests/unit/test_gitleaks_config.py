"""config/gitleaks.toml: structure plus positive/negative cases. Every fake credential is generated here at test time."""

import random
import re
import string
import tomllib
from pathlib import Path

import pytest

CONFIG = Path(__file__).resolve().parents[2] / "config" / "gitleaks.toml"
CUSTOM_IDS = {
    "labsec-connection-string-password",
    "labsec-connection-string-password-first",
    "labsec-appsettings-secret",
    "labsec-keycloak-realm-client-secret",
    "labsec-keycloak-client-secret-setting",
}
_RNG = random.SystemRandom()


@pytest.fixture(scope="module")
def config():
    return tomllib.loads(CONFIG.read_text())


@pytest.fixture(scope="module")
def rules(config):
    return {r["id"]: r for r in config["rules"]}


def fake(length=24):
    return "".join(_RNG.choice(string.ascii_letters + string.digits) for _ in range(length))


def found(rule, text, path=None):
    """Mimic Gitleaks: path filter, regex, secret group, then the rule's allowlists applied to the secret."""
    if "path" in rule and path is not None and not re.search(rule["path"], path):
        return None
    match = re.search(rule["regex"], text)
    if not match:
        return None
    value = match.group(rule["secretGroup"])
    for allow in rule.get("allowlists", []):
        if any(re.search(rx, value) for rx in allow.get("regexes", [])):
            return None
    return value


def test_it_extends_the_default_ruleset(config):
    assert config["extend"] == {"useDefault": True}


def test_it_defines_exactly_the_documented_custom_rules(rules):
    assert set(rules) == CUSTOM_IDS


def test_every_rule_has_keywords_and_a_compilable_regex(rules):
    for rule in rules.values():
        assert rule["keywords"] and rule["secretGroup"] == 1
        re.compile(rule["regex"])
        for allow in rule.get("allowlists", []):
            for rx in allow["regexes"]:
                re.compile(rx)


@pytest.mark.parametrize(
    "text",
    [
        "Server=db.internal;Database=app;User Id=app;Password={pw};",  # gitleaks:allow (template, value generated at runtime)
        "Host=localhost;Port=5432;Database=app;Username=app;Password={pw}",  # gitleaks:allow (template, value generated at runtime)
        '"DefaultConnection": "Host=pg;Database=app;Username=app;Password={pw};SSL Mode=Require"',  # gitleaks:allow (template, value generated at runtime)
        "Data Source=sql01;Initial Catalog=app;uid=sa;pwd={pw}",  # gitleaks:allow (template, value generated at runtime)
    ],
)
def test_connection_string_with_password_after_the_server_is_found(rules, text):
    pw = fake()
    assert found(rules["labsec-connection-string-password"], text.format(pw=pw)) == pw


def test_connection_string_with_password_first_is_found(rules):
    pw = fake()
    assert found(rules["labsec-connection-string-password-first"], f"Password={pw};Host=localhost;Database=app") == pw  # gitleaks:allow (template)


@pytest.mark.parametrize(
    "text",
    [
        "Server=db;Database=app;User Id=app;Password=${DB_PASSWORD};",
        "Server=db;Database=app;User Id=app;Password=<your-password>;",
        "Host=db;Username=app;Password=changeme",
        "Host=db;Username=app;Password=placeholder;",  # gitleaks:allow (placeholder)
        "Host=db;Username=app;Password=dummy;",  # gitleaks:allow (placeholder)
        "Host=db;Username=app;Password=%DB_PASSWORD%;",
        "Server=db;Database=app;Integrated Security=true",  # no password at all
        "the password = hunter22 appears in a sentence",  # not a connection string
    ],
)
def test_placeholders_and_non_connection_strings_are_ignored(rules, text):
    for rule_id in ("labsec-connection-string-password", "labsec-connection-string-password-first"):
        assert found(rules[rule_id], text) is None


@pytest.mark.parametrize("key", ["ClientSecret", "Authentication:Google:ClientSecret", "ApiKey", "JwtKey", "SigningKey", "Jwt:SecretKey"])
def test_appsettings_keys_are_found_only_in_appsettings_files(rules, key):
    value = fake(32)
    text = f'  "{key}": "{value}",'
    rule = rules["labsec-appsettings-secret"]
    assert found(rule, text, "Api/appsettings.json") == value
    assert found(rule, text, "Api/appsettings.Production.json") == value
    assert found(rule, text, "Api/other.json") is None


@pytest.mark.parametrize("value", ["", "short", "<your-client-secret>", "${KEYCLOAK_SECRET}", "changeme", "xxxxxxxxxxxx", "set-via-user-store"])
def test_appsettings_placeholders_are_ignored(rules, value):
    assert found(rules["labsec-appsettings-secret"], f'"ClientSecret": "{value}"', "appsettings.json") is None


def test_keycloak_realm_secret_is_found_and_masked_one_is_not(rules):
    value = fake(32)
    rule = rules["labsec-keycloak-realm-client-secret"]
    assert found(rule, f'"secret": "{value}",', "keycloak/realm-export.json") == value
    assert found(rule, f'"secret": "{"*" * 20}",', "keycloak/realm-export.json") is None
    assert found(rule, f'"secret": "{value}",', "src/data.json") is None


@pytest.mark.parametrize(
    "template",
    [
        "KEYCLOAK_CLIENT_SECRET={v}",
        "keycloak.credentials.secret: {v}",
        'Keycloak__ClientSecret = "{v}"',
        "quarkus.oidc.keycloak-client-secret={v}",
    ],
)
def test_keycloak_client_secret_settings_are_found(rules, template):
    value = fake(32)
    assert found(rules["labsec-keycloak-client-secret-setting"], template.format(v=value)) == value


def test_keycloak_setting_placeholder_is_ignored(rules):
    assert found(rules["labsec-keycloak-client-secret-setting"], "KEYCLOAK_CLIENT_SECRET=changeme") is None


def test_tests_and_fixtures_are_not_blanket_allowlisted(config):
    paths = config["allowlist"]["paths"]
    for sample in ("tests/fixtures/appsettings.json", "src/Api.Tests/Secrets.cs", "test/data/config.env", "__tests__/a.ts"):
        assert not any(re.search(rx, sample) for rx in paths), sample
