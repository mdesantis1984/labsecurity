"""Run scanner containers (compose `tools` profile) as the invoking host user."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from labsec.config import Paths
from labsec.redact import redact


@dataclass
class RunResult:
    returncode: int
    output: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def tail(self, lines: int = 12) -> str:
        return "\n".join(self.output.strip().splitlines()[-lines:])


class Compose:
    def __init__(self, paths: Paths, known_values=()):
        self.paths = paths
        self.known_values = list(known_values)  # values to mask in captured output
        self.uid, self.gid = os.getuid(), os.getgid()

    @property
    def base(self) -> list[str]:
        root = str(self.paths.root)
        return ["docker", "compose", "--project-directory", root, "-f", f"{root}/compose.yaml"]

    def env(self, extra: dict | None = None) -> dict:
        env = dict(os.environ)
        env["LABSEC_CONFIG_DIR"] = str(self.paths.config_dir)
        env["LABSEC_CACHE_DIR"] = str(self.paths.cache_dir)
        env.update(extra or {})
        return env

    def run_tool(
        self,
        service: str,
        command: list[str],
        *,
        mounts=(),
        env: dict | None = None,
        credentials: dict | None = None,
        entrypoint: str | None = None,
        workdir: str | None = None,
        timeout: int = 3600,
        log_path: Path | None = None,
        as_host_user: bool = True,
    ) -> RunResult:
        """`docker compose run --rm` one tool container.

        `credentials` are passed to the container by NAME only (`-e NAME`): the value travels in the
        environment of the docker client process, never in an argument list.
        """
        cmd = self.base + ["--profile", "tools", "run", "--rm", "--no-deps", "-T"]
        if as_host_user:
            cmd += ["--user", f"{self.uid}:{self.gid}"]
        for src, dst, mode in mounts:
            cmd += ["-v", f"{src}:{dst}:{mode}"]
        for key, value in (env or {}).items():
            cmd += ["-e", f"{key}={value}"]
        for key in credentials or {}:
            cmd += ["-e", key]
        if entrypoint:
            cmd += ["--entrypoint", entrypoint]
        if workdir:
            cmd += ["-w", workdir]
        cmd += [service, *command]
        try:
            proc = subprocess.run(
                cmd,
                env=self.env(credentials),
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout,
                check=False,
            )
            result = RunResult(proc.returncode, (proc.stdout or "") + (proc.stderr or ""))
        except subprocess.TimeoutExpired as exc:
            partial = exc.stdout or b""
            partial = partial.decode(errors="replace") if isinstance(partial, bytes) else partial
            result = RunResult(124, f"{partial}\ntimed out after {timeout}s")
        result.output = redact(result.output, self.known_values)
        if log_path is not None:
            log_path.write_text(result.output, encoding="utf-8")
            os.chmod(log_path, 0o600)
        return result

    def up(self, timeout: int = 900) -> RunResult:
        """`docker compose up -d --wait`: start what is down and wait for the healthchecks (never recreates healthy services)."""
        try:
            proc = subprocess.run(
                self.base + ["up", "-d", "--wait", "--wait-timeout", str(timeout)],
                env=self.env(),
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout + 120,
                check=False,
            )
            result = RunResult(proc.returncode, (proc.stdout or "") + (proc.stderr or ""))
        except subprocess.TimeoutExpired:
            result = RunResult(124, f"docker compose up timed out after {timeout}s")
        result.output = redact(result.output, self.known_values)
        return result

    # -- inspection used by --doctor
    def ps(self) -> list[dict]:
        proc = subprocess.run(
            self.base + ["ps", "-a", "--format", "json"],
            env=self.env(),
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(redact(proc.stderr.strip()) or "docker compose ps failed")
        text = proc.stdout.strip()
        if not text:
            return []
        if text.startswith("["):
            return json.loads(text)
        return [json.loads(line) for line in text.splitlines() if line.strip()]

    def images(self) -> list[str]:
        proc = subprocess.run(
            self.base + ["--profile", "tools", "config", "--images"],
            env=self.env(),
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(redact(proc.stderr.strip()) or "docker compose config failed")
        return sorted(set(proc.stdout.split()))

    def image_present(self, image: str) -> bool:
        return subprocess.run(["docker", "image", "inspect", image], capture_output=True, check=False).returncode == 0
