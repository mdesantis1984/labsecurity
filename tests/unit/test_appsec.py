import pytest

from labsec.appsec import AppSecError, load_appsec


def write(root, text):
    (root / ".appsec.yml").write_text(text)


def test_missing_file_uses_defaults(tmp_path):
    cfg = load_appsec(tmp_path)
    assert cfg.name is None
    assert cfg.exclude == []
    assert cfg.zap is None
    assert cfg.rules == []
    assert cfg.source is None


def test_full_file(tmp_path):
    (tmp_path / "rules").mkdir()
    write(
        tmp_path,
        """
name: Demo App
exclude:
  - "tests/**"
  - docs
zap:
  target_url: http://127.0.0.1:18080
  openapi_url: http://127.0.0.1:18080/openapi.json
  test_user: scan-user@example.com
rules:
  - rules
""",
    )
    cfg = load_appsec(tmp_path)
    assert cfg.name == "Demo App"
    assert cfg.exclude == ["tests/**", "docs"]
    assert cfg.zap.target_url == "http://127.0.0.1:18080"
    assert cfg.zap.openapi_url == "http://127.0.0.1:18080/openapi.json"
    assert cfg.zap.test_user == "scan-user@example.com"
    assert cfg.rules == ["rules"]
    assert cfg.source == tmp_path / ".appsec.yml"


@pytest.mark.parametrize(
    "text, message",
    [
        ("- a\n- b\n", "must be a mapping"),
        ("name: 3\n", "'name' must be a non-empty string"),
        ("bogus: 1\n", "unknown key 'bogus'"),
        ("exclude: tests\n", "'exclude' must be a list of strings"),
        ("zap: {openapi_url: http://127.0.0.1/x}\n", "'zap.target_url' is required"),
        ("zap: {target_url: http://127.0.0.1, nope: 1}\n", "unknown key 'zap.nope'"),
        ("zap: {target_url: 5}\n", "'zap.target_url' must be a string"),
        ("rules: [../../etc]\n", "must stay inside the project"),
        ("rules: [/abs/path]\n", "must stay inside the project"),
        ("rules: [missing-dir]\n", "does not exist"),
        ("name: [unclosed\n", "invalid YAML"),
    ],
)
def test_invalid_files_give_clear_errors(tmp_path, text, message):
    write(tmp_path, text)
    with pytest.raises(AppSecError) as exc:
        load_appsec(tmp_path)
    assert message in str(exc.value)
    assert ".appsec.yml" in str(exc.value)


def test_password_keys_are_rejected(tmp_path):
    write(tmp_path, "zap: {target_url: http://127.0.0.1, test_user: u, test_password: hunter2}\n")
    with pytest.raises(AppSecError) as exc:
        load_appsec(tmp_path)
    assert "never stored in .appsec.yml" in str(exc.value)
    assert "hunter2" not in str(exc.value)
