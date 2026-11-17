"""Machine-wide lock so two heavy analyses never run at the same time."""

from __future__ import annotations

import fcntl
import os
from pathlib import Path


class LockBusy(RuntimeError):
    pass


class HeavyLock:
    def __init__(self, path: Path, owner: str = "unknown"):
        self.path = Path(path)
        self.owner = owner
        self._fd: int | None = None

    def __enter__(self) -> "HeavyLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        os.chmod(self.path, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            holder = os.pread(fd, 256, 0).decode(errors="replace").strip() or "unknown"
            os.close(fd)
            raise LockBusy(
                f"another heavy analysis is running (held by: {holder}); "
                f"wait for it to finish, then retry. Lock file: {self.path}"
            ) from None
        os.ftruncate(fd, 0)
        os.pwrite(fd, f"{self.owner} pid={os.getpid()}".encode(), 0)
        self._fd = fd
        return self

    def __exit__(self, *exc) -> None:
        if self._fd is not None:
            os.ftruncate(self._fd, 0)
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            os.close(self._fd)
            self._fd = None
