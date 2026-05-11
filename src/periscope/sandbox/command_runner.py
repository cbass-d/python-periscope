import subprocess
from typing import Protocol

from loguru import logger


class CommandRunner(Protocol):
    """Interface for running commands passed in as list of strings"""

    def run(self, cmd: list[str], *, quiet: bool = False) -> subprocess.CompletedProcess[bytes]: ...


class SubprocessRunner:
    """Implementation used to make real calls using subprocess"""

    def run(self, cmd: list[str], *, quiet: bool = False) -> subprocess.CompletedProcess[bytes]:
        try:
            return subprocess.run(cmd, check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            if quiet:
                raise
            stderr = (e.stderr or b"").decode(errors="replace").strip()
            stdout = (e.stdout or b"").decode(errors="replace").strip()
            logger.error(
                "command failed: {} (exit {}): {}",
                " ".join(cmd),
                e.returncode,
                stderr or stdout or "(no output)",
                cmd=cmd,
                returncode=e.returncode,
                stderr=stderr,
                stdout=stdout,
            )
            raise


class FakeRunner:
    """Mock runner used for tests. Records all calls made for asserts"""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def run(self, cmd: list[str], *, quiet: bool = False) -> subprocess.CompletedProcess[bytes]:
        _ = quiet  # accepted for Protocol conformance; FakeRunner doesn't log
        self.calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, b"", b"")
