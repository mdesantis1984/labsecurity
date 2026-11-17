"""Filesystem layout and the secret `.vars` files (KEY=VALUE, mode 600, never printed)."""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

SECRET_KEY_HINTS = ("TOKEN", "PASSWORD", "SECRET", "KEY")


def _env_path(name: str, default: Path, env=None) -> Path:
    value = (os.environ if env is None else env).get(name)
    return Path(value).expanduser() if value else default


def _xdg(env, home: Path, name: str, fallback: str) -> Path:
    """An XDG base directory: the variable when it is an absolute path, otherwise `~/<fallback>`."""
    value = env.get(name, "")
    return Path(value) if value and os.path.isabs(value) else home / fallback


def default_dirs(env=None, home: Path | None = None, system: str | None = None) -> dict[str, Path]:
    """Where LabSecurity keeps its files. The same rules are implemented in `scripts/lib/paths.sh`.

    - `LABSEC_HOME` set: everything lives under it (`config/`, `cache/`, `state/` and the data itself).
    - macOS: the same layout under `~/Library/Application Support/LabSecurity`.
    - Linux and WSL2: XDG directories (`$XDG_DATA_HOME/labsecurity`, `$XDG_CONFIG_HOME/labsecurity`, ...), which are the
      locations earlier versions already used, so an existing install keeps working without migration.
    """
    env = os.environ if env is None else env
    home = Path.home() if home is None else home
    system = sys.platform if system is None else system
    lab_home = env.get("LABSEC_HOME")
    base: Path | None = None
    if lab_home:
        base = home / lab_home[2:] if lab_home.startswith("~/") else (home if lab_home == "~" else Path(lab_home))
    elif system == "darwin":
        base = home / "Library" / "Application Support" / "LabSecurity"
    if base is not None:
        return {"data": base, "config": base / "config", "cache": base / "cache", "state": base / "state"}
    return {
        "data": _xdg(env, home, "XDG_DATA_HOME", ".local/share") / "labsecurity",
        "config": _xdg(env, home, "XDG_CONFIG_HOME", ".config") / "labsecurity",
        "cache": _xdg(env, home, "XDG_CACHE_HOME", ".cache") / "labsecurity",
        "state": _xdg(env, home, "XDG_STATE_HOME", ".local/state") / "labsecurity",
    }


def repo_folder(name: str, path: Path | None) -> str:
    """`<repo name>-<first 6 hex of SHA-256 of the absolute repo path>`: two repos called `api` never collide.

    Without a path (only a DefectDojo product slug is known) the hash is taken from the slug itself.
    """
    key = str(Path(path).resolve()) if path is not None else name
    return f"{name}-{hashlib.sha256(key.encode('utf-8')).hexdigest()[:6]}"


@dataclass(frozen=True)
class Paths:
    root: Path
    config_dir: Path
    data_dir: Path
    cache_dir: Path
    state_dir: Path

    @classmethod
    def from_env(cls, env=None, home: Path | None = None, system: str | None = None) -> "Paths":
        env = os.environ if env is None else env
        dirs = default_dirs(env, home, system)
        return cls(
            root=_env_path("LABSEC_ROOT", Path(__file__).resolve().parent.parent, env),
            config_dir=_env_path("LABSEC_CONFIG_DIR", dirs["config"], env),
            data_dir=_env_path("LABSEC_DATA_DIR", dirs["data"], env),
            cache_dir=_env_path("LABSEC_CACHE_DIR", dirs["cache"], env),
            state_dir=_env_path("LABSEC_STATE_DIR", dirs["state"], env),
        )

    @property
    def cli_vars(self) -> Path:
        return self.config_dir / "cli.vars"

    @property
    def lock_path(self) -> Path:
        return self.state_dir / "heavy.lock"

    def project_vars(self, slug: str) -> Path:
        return self.config_dir / "projects" / f"{slug}.vars"

    def work_dir(self, slug: str) -> Path:
        return self.cache_dir / "work" / slug

    def run_dir(self, slug: str, run_id: str) -> Path:
        return self.data_dir / "runs" / slug / run_id

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def backups_dir(self) -> Path:
        return self.data_dir / "backups"

    def repo_reports_dir(self, name: str, path: Path | None) -> Path:
        """`reports/<repo>-<hash>/`; with only a slug, reuse the one existing `<slug>-*` folder if there is exactly one."""
        if path is None and self.reports_dir.is_dir():
            known = sorted(p for p in self.reports_dir.glob(f"{name}-??????") if p.is_dir())
            if len(known) == 1:
                return known[0]
        return self.reports_dir / repo_folder(name, path)

    def new_report_dir(self, name: str, path: Path | None, now: datetime | None = None) -> Path:
        """Create (mode 700) `reports/<repo>-<hash>/<UTC timestamp>/` and return it."""
        stamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
        target = self.repo_reports_dir(name, path) / stamp
        private_dir(self.reports_dir)
        private_dir(target.parent)
        return private_dir(target)

    @property
    def tool_cache_dir(self) -> Path:
        return self.cache_dir / "tool-cache"


def private_dir(path: Path) -> Path:
    """Create `path` (and parents) and make sure it is mode 700."""
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def read_vars(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values


def update_vars(path: Path, updates: dict[str, str]) -> None:
    """Rewrite `path` in place, replacing/adding keys, keeping comments and mode 600 (atomic)."""
    lines = path.read_text(encoding="utf-8").splitlines() if path.is_file() else []
    pending = dict(updates)
    out = []
    for raw in lines:
        key = raw.split("=", 1)[0].strip() if "=" in raw and not raw.lstrip().startswith("#") else None
        if key in pending:
            out.append(f"{key}={pending.pop(key)}")
        else:
            out.append(raw)
    out.extend(f"{key}={value}" for key, value in pending.items())
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".vars-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("\n".join(out) + "\n")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    os.chmod(path, 0o600)


def secret_values(*sources: dict[str, str]) -> list[str]:
    """Every value whose key looks secret; used to redact anything we print or log."""
    found = []
    for source in sources:
        for key, value in source.items():
            if value and any(hint in key.upper() for hint in SECRET_KEY_HINTS):
                found.append(value)
    return found
