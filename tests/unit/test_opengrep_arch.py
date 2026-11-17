"""The Opengrep image picks the binary and checksum of the CPU it is built for (Apple Silicon needs aarch64)."""

import os
import re
import subprocess
from pathlib import Path

import pytest

DOCKER = Path(__file__).resolve().parents[2] / "docker" / "opengrep"
X86, ARM = "a" * 64, "b" * 64


def select(tmp_path, machine):
    fake = tmp_path / f"bin-{machine}"
    fake.mkdir()
    uname = fake / "uname"
    uname.write_text(f"#!/bin/sh\necho {machine}\n")
    uname.chmod(0o755)
    env = {"PATH": f"{fake}:{os.environ['PATH']}"}
    return subprocess.run(["sh", str(DOCKER / "select-asset.sh"), X86, ARM], env=env, capture_output=True, text=True)


@pytest.mark.parametrize("machine,asset,sha", [("x86_64", "opengrep_linux_x86", X86), ("amd64", "opengrep_linux_x86", X86),
                                               ("aarch64", "opengrep_linux_aarch64", ARM), ("arm64", "opengrep_linux_aarch64", ARM)])
def test_each_architecture_gets_its_own_binary_and_checksum(tmp_path, machine, asset, sha):
    result = select(tmp_path, machine)
    assert result.returncode == 0 and result.stdout == f"{asset} {sha}\n" and result.stderr == ""


def test_an_unsupported_architecture_fails_the_build(tmp_path):
    result = select(tmp_path, "riscv64")
    assert result.returncode == 1 and result.stdout == "" and "unsupported architecture riscv64" in result.stderr


def test_the_dockerfile_pins_a_checksum_per_architecture_and_uses_the_selector():
    text = (DOCKER / "Dockerfile").read_text()
    for name in ("OPENGREP_SHA256_X86", "OPENGREP_SHA256_AARCH64"):
        assert re.search(rf"^ARG {name}=[0-9a-f]{{64}}$", text, re.M), name
    assert "select-asset.sh" in text and "opengrep_linux_x86\"" not in text, "the asset must come from the selector, not be hardcoded"
