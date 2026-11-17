""".appsec.yml: optional per-project configuration (name, excludes, local ZAP target, custom rules)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

import yaml

FILE_NAME = ".appsec.yml"
_TOP_KEYS = {"name", "exclude", "zap", "rules"}
_ZAP_KEYS = {"target_url", "openapi_url", "test_user"}


class AppSecError(ValueError):
    pass


@dataclass
class ZapConfig:
    target_url: str
    openapi_url: str | None = None
    test_user: str | None = None


@dataclass
class AppSecConfig:
    name: str | None = None
    exclude: list[str] = field(default_factory=list)
    zap: ZapConfig | None = None
    rules: list[str] = field(default_factory=list)
    source: Path | None = None


def _fail(message: str):
    raise AppSecError(f"{FILE_NAME}: {message}")


def _string_list(value, key: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        _fail(f"'{key}' must be a list of strings")
    return list(value)


def load_appsec(project: Path) -> AppSecConfig:
    path = Path(project) / FILE_NAME
    if not path.is_file():
        return AppSecConfig()
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        _fail(f"invalid YAML ({str(exc).splitlines()[0] if str(exc) else 'parse error'})")
    if data is None:
        return AppSecConfig(source=path)
    if not isinstance(data, dict):
        _fail("must be a mapping at the top level")
    for key in data:
        if key not in _TOP_KEYS:
            _fail(f"unknown key '{key}' (allowed: {', '.join(sorted(_TOP_KEYS))})")

    cfg = AppSecConfig(source=path)
    if "name" in data:
        if not isinstance(data["name"], str) or not data["name"].strip():
            _fail("'name' must be a non-empty string")
        cfg.name = data["name"].strip()
    if "exclude" in data:
        cfg.exclude = _string_list(data["exclude"], "exclude")
    if "rules" in data:
        cfg.rules = _string_list(data["rules"], "rules")
        root = Path(project).resolve()
        for rel in cfg.rules:
            pure = PurePosixPath(rel)
            if pure.is_absolute() or ".." in pure.parts:
                _fail(f"rules path '{rel}' must stay inside the project (relative, no '..')")
            if not (root / rel).exists():
                _fail(f"rules path '{rel}' does not exist")
            if not (root / rel).resolve().is_relative_to(root):
                _fail(f"rules path '{rel}' must stay inside the project (relative, no '..')")
    if "zap" in data:
        zap = data["zap"]
        if not isinstance(zap, dict):
            _fail("'zap' must be a mapping")
        for key in zap:
            if "password" in str(key).lower() or "secret" in str(key).lower():
                _fail(
                    f"'zap.{key}': passwords are never stored in .appsec.yml; "
                    "put ZAP_TEST_PASSWORD in ~/.config/labsecurity/projects/<slug>.vars (mode 600)"
                )
            if key not in _ZAP_KEYS:
                _fail(f"unknown key 'zap.{key}' (allowed: {', '.join(sorted(_ZAP_KEYS))})")
        if "target_url" not in zap:
            _fail("'zap.target_url' is required when 'zap' is present")
        for key in _ZAP_KEYS & zap.keys():
            if not isinstance(zap[key], str) or not zap[key].strip():
                _fail(f"'zap.{key}' must be a string")
        cfg.zap = ZapConfig(
            target_url=zap["target_url"].strip(),
            openapi_url=zap.get("openapi_url"),
            test_user=zap.get("test_user"),
        )
    return cfg
