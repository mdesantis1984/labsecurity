import multiprocessing
import time

import pytest

from labsec.lock import HeavyLock, LockBusy


def test_second_holder_fails_fast(tmp_path):
    path = tmp_path / "state" / "heavy.lock"
    with HeavyLock(path, owner="project-a"):
        with pytest.raises(LockBusy) as exc:
            with HeavyLock(path, owner="project-b"):
                pytest.fail("must not enter")
    message = str(exc.value)
    assert "another heavy analysis is running" in message
    assert "project-a" in message


def test_lock_is_released_and_reusable(tmp_path):
    path = tmp_path / "heavy.lock"
    with HeavyLock(path, owner="one"):
        pass
    with HeavyLock(path, owner="two"):
        pass


def _hold(path, ready, release):
    with HeavyLock(path, owner="child"):
        ready.set()
        release.wait(10)


def test_lock_excludes_other_processes(tmp_path):
    path = tmp_path / "heavy.lock"
    ready, release = multiprocessing.Event(), multiprocessing.Event()
    proc = multiprocessing.Process(target=_hold, args=(path, ready, release))
    proc.start()
    try:
        assert ready.wait(10)
        started = time.monotonic()
        with pytest.raises(LockBusy):
            with HeavyLock(path, owner="parent"):
                pass
        assert time.monotonic() - started < 2, "must fail fast, not wait"
    finally:
        release.set()
        proc.join(10)
    with HeavyLock(path, owner="parent"):
        pass


def test_lock_file_is_private(tmp_path):
    path = tmp_path / "s" / "heavy.lock"
    with HeavyLock(path, owner="x"):
        assert oct(path.stat().st_mode & 0o777) == "0o600"
        assert oct(path.parent.stat().st_mode & 0o777) == "0o700"
