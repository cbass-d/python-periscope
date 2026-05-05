import subprocess

import pytest

from periscope.sandbox.command_runner import FakeRunner
from periscope.sandbox.network_sandbox import HOST_VETH, NS_VETH, NetworkSandbox


class FailingRunner(FakeRunner):
    """FakeRunner that raises CalledProcessError on the Nth call."""

    def __init__(self, fail_on: int) -> None:
        super().__init__()
        self._fail_on = fail_on

    def run(self, cmd: list[str]) -> subprocess.CompletedProcess:
        result = super().run(cmd)
        if len(self.calls) == self._fail_on:
            raise subprocess.CalledProcessError(1, cmd)
        return result


def test_setup_runs_commands_in_order() -> None:
    runner = FakeRunner()
    with NetworkSandbox("test-ns", "10.0.0.0/24", "wlan0", runner=runner):
        pass
    assert runner.calls == [
        ["ip", "netns", "add", "test-ns"],
        ["ip", "link", "add", HOST_VETH, "type", "veth", "peer", "name", NS_VETH],
        ["ip", "link", "set", NS_VETH, "netns", "test-ns"],
        ["ip", "addr", "add", "10.0.0.1/24", "dev", HOST_VETH],
        ["ip", "-n", "test-ns", "addr", "add", "10.0.0.2/24", "dev", NS_VETH],
        ["ip", "link", "set", HOST_VETH, "up"],
        ["ip", "-n", "test-ns", "link", "set", NS_VETH, "up"],
        ["ip", "-n", "test-ns", "link", "set", "lo", "up"],
        ["ip", "netns", "delete", "test-ns"],
    ]


def test_subnet_assigns_first_two_hosts() -> None:
    runner = FakeRunner()
    with NetworkSandbox("ns", "192.168.50.0/24", "eth0", runner=runner):
        pass
    assert any("192.168.50.1/24" in c for c in runner.calls)
    assert any("192.168.50.2/24" in c for c in runner.calls)


def test_subnet_accepts_host_bits() -> None:
    # CLI passes "10.0.0.1/24" (host bits set); strict=False should normalize.
    runner = FakeRunner()
    with NetworkSandbox("ns", "10.0.0.1/24", "eth0", runner=runner):
        pass
    assert any("10.0.0.1/24" in c for c in runner.calls)
    assert any("10.0.0.2/24" in c for c in runner.calls)


def test_namespace_deleted_on_exit() -> None:
    runner = FakeRunner()
    with NetworkSandbox("ns", "10.0.0.0/24", "eth0", runner=runner):
        pass
    assert ["ip", "netns", "delete", "ns"] in runner.calls


def test_rollback_on_partial_failure() -> None:
    runner = FailingRunner(fail_on=4)  # fail on "ip addr add"
    with pytest.raises(subprocess.CalledProcessError):  # noqa: SIM117
        with NetworkSandbox("ns", "10.0.0.0/24", "eth0", runner=runner):
            pass
    # Teardown attempted after the failure.
    assert ["ip", "netns", "delete", "ns"] in runner.calls


def test_rollback_swallows_teardown_errors() -> None:
    # Fail on the very first call (netns add) — teardown will then also fail,
    # but that must not mask the original exception.
    runner = FailingRunner(fail_on=1)
    with pytest.raises(subprocess.CalledProcessError):  # noqa: SIM117
        with NetworkSandbox("ns", "10.0.0.0/24", "eth0", runner=runner):
            pass
