"""DAST target guard: ZAP may only touch loopback test environments."""

from __future__ import annotations

from urllib.parse import urlsplit

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class UnsafeTargetError(ValueError):
    pass


def ensure_loopback(url: str) -> str:
    """Return `url` unchanged when its host is exactly 127.0.0.1, localhost or ::1 over http(s)."""
    refusal = (
        f"refusing DAST target {url!r}: ZAP only runs against loopback test environments "
        "(127.0.0.1, localhost or ::1), never production or public hosts"
    )
    try:
        parts = urlsplit(url)
        host = parts.hostname
        parts.port  # noqa: B018 - validates the port
    except ValueError as exc:
        raise UnsafeTargetError(f"{refusal} ({exc})") from exc
    if parts.scheme not in ("http", "https") or parts.username is not None or not host:
        raise UnsafeTargetError(refusal)
    if host.lower() not in LOOPBACK_HOSTS:
        raise UnsafeTargetError(refusal)
    return url
