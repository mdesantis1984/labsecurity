"""Resolve a `<project>` argument (path or slug) and connect to the lab (DefectDojo API only)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from labsec.appsec import AppSecError, load_appsec
from labsec.config import Paths, read_vars
from labsec.dojo import DojoClient
from labsec.langs import slugify

SLUG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class UsageError(ValueError):
    """Bad arguments or a missing object (exit code 1)."""


class LabNotReady(RuntimeError):
    """The lab is not configured or unreachable (exit code 3)."""


@dataclass(frozen=True)
class Project:
    slug: str
    path: Path | None  # None when only a slug was given


def resolve_project(arg: str) -> Project:
    candidate = Path(arg).expanduser()
    if candidate.is_dir():
        path = candidate.resolve()
        try:
            cfg = load_appsec(path)
        except AppSecError as exc:
            raise UsageError(str(exc)) from exc
        return Project(slugify(cfg.name or path.name), path)
    if not SLUG.match(arg):
        raise UsageError(f"{arg!r} is neither a directory nor a project slug")
    return Project(arg, None)


def connect(paths: Paths | None = None) -> DojoClient:
    paths = paths or Paths.from_env()
    cli = read_vars(paths.cli_vars)
    if not (cli.get("DD_URL") and cli.get("DD_API_TOKEN")):
        raise LabNotReady("lab is not configured: run `bin/scan --bootstrap` first")
    return DojoClient(cli["DD_URL"], cli["DD_API_TOKEN"], timeout=120)
