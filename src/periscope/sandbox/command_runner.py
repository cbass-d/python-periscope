import subprocess
from typing import Protocol


class CommandRunner(Protocol):
    """Interface for running commands passed in as list of strings"""

    def run(self, cmd: list[str]) -> subprocess.CompletedProcess: ...


class SubprocessRunner:
    """Implemenation used to make real calls using subprocess"""

    def run(self, cmd: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, check=True, capture_output=True)


class FakeRunner:
    """Mock runner used for tests. Records all calls made for asserts"""

    def __init__(self):
        self.calls = []

    def run(self, cmd: list[str]) -> subprocess.CompletedProcess:
        self.calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, b"", b"")
