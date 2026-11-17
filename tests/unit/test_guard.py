import pytest

from labsec.guard import UnsafeTargetError, ensure_loopback


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:18080",
        "http://localhost:18080/openapi.json",
        "https://LOCALHOST/x",
        "http://[::1]:8080/api",
        "http://127.0.0.1",
    ],
)
def test_loopback_targets_pass(url):
    assert ensure_loopback(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "https://app.example.com",
        "http://10.0.0.5:8080",
        "http://192.168.1.10",
        "http://127.0.0.2:80",
        "http://localhost.evil.com",
        "http://127.0.0.1@evil.com/",
        "http://evil.com/?h=127.0.0.1",
        "ftp://127.0.0.1/x",
        "file:///etc/passwd",
        "127.0.0.1:8080",
        "",
        "http://",
        "http://0.0.0.0:80",
    ],
)
def test_non_loopback_targets_are_refused(url):
    with pytest.raises(UnsafeTargetError) as exc:
        ensure_loopback(url)
    assert "loopback" in str(exc.value)
