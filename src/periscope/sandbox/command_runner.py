import subprocess
from typing import Protocol


class CommandRunner(Protocol):
    """Interface for running commands passed in as list of strings"""

    def run(self, cmd: list[str]) -> subprocess.CompletedProcess[bytes]: ...


class SubprocessRunner:
    """Implementation used to make real calls using subprocess"""

    def run(self, cmd: list[str]) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(cmd, check=True, capture_output=True)


class FakeRunner:
    """Mock runner used for tests. Records all calls made for asserts"""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def run(self, cmd: list[str]) -> subprocess.CompletedProcess[bytes]:
        self.calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, b"", b"")
