from labsec.redact import redact


def test_known_secret_values_are_replaced():
    out = redact("login with hunter2-abc now", secrets=["hunter2-abc"])
    assert "hunter2-abc" not in out
    assert "***" in out


def test_short_or_empty_secrets_do_not_mangle_text():
    assert redact("a b c", secrets=["", "a"]) == "a b c"


def test_token_shapes_are_redacted_without_knowing_them():
    text = (
        "Authorization: Token 0123456789abcdef0123456789abcdef01234567\n"
        "sonar squ_0123456789abcdef0123456789abcdef01234567 and sqa_deadbeefdeadbeefdeadbeef\n"
        "ghp_" + "A1b2C3d4E5" * 3 + "ABCDEF\n"
        "url http://x/?token=abc123def&password=letmein&ok=1\n"
        "SONAR_TOKEN=secretvalue DD_ADMIN_PASSWORD: s3cr3t\n"
    )
    out = redact(text)
    for leaked in ("0123456789abcdef0123456789abcdef01234567", "squ_", "sqa_", "ghp_", "abc123def", "letmein", "secretvalue", "s3cr3t"):
        assert leaked not in out, leaked
    assert "ok=1" in out


def test_plain_text_is_untouched():
    assert redact("analysis finished: 3 findings") == "analysis finished: 3 findings"
