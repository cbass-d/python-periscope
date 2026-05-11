import subprocess

import pytest

from periscope.sandbox.command_runner import FakeRunner
from periscope.sandbox.egress import NFT_TABLE, Egress

SUBNET = "10.1.0.0/24"
IFACE = "eth0"


class FailingRunner(FakeRunner):
    """FakeRunner that raises CalledProcessError on the Nth call."""

    def __init__(self, fail_on: int) -> None:
        super().__init__()
        self._fail_on = fail_on

    def run(self, cmd: list[str], *, quiet: bool = False) -> subprocess.CompletedProcess[bytes]:
        result = super().run(cmd, quiet=quiet)
        if len(self.calls) == self._fail_on:
            raise subprocess.CalledProcessError(1, cmd)
        return result


def test_setup_runs_commands_in_order() -> None:
    runner = FakeRunner()
    with Egress(subnet=SUBNET, uplink_iface=IFACE, runner=runner):
        pass
    assert runner.calls == [
        ["sysctl", "-w", "net.ipv4.ip_forward=1"],
        ["nft", "delete", "table", "ip", NFT_TABLE],
        ["nft", "add", "table", "ip", NFT_TABLE],
        [
            "nft",
            "add",
            "chain",
            "ip",
            NFT_TABLE,
            "postrouting",
            "{",
            "type",
            "nat",
            "hook",
            "postrouting",
            "priority",
            "100",
            ";",
            "}",
        ],
        [
            "nft",
            "add",
            "rule",
            "ip",
            NFT_TABLE,
            "postrouting",
            "ip",
            "saddr",
            SUBNET,
            "oifname",
            IFACE,
            "masquerade",
        ],
        ["iptables", "-I", "FORWARD", "-s", SUBNET, "-j", "ACCEPT"],
        ["iptables", "-I", "FORWARD", "-d", SUBNET, "-j", "ACCEPT"],
        ["iptables", "-D", "FORWARD", "-s", SUBNET, "-j", "ACCEPT"],
        ["iptables", "-D", "FORWARD", "-d", SUBNET, "-j", "ACCEPT"],
        ["nft", "delete", "table", "ip", NFT_TABLE],
        ["sysctl", "-w", "net.ipv4.ip_forward=0"],
    ]


def test_pre_delete_failure_is_swallowed() -> None:
    # `nft delete table` (the idempotent pre-delete) fails when no leftover
    # table exists. Setup must continue past this — the failure is expected.
    runner = FailingRunner(fail_on=2)  # 2nd call: pre-delete
    with Egress(subnet=SUBNET, uplink_iface=IFACE, runner=runner):
        pass
    # Setup should have completed: add table appears after the failed delete.
    assert ["nft", "add", "table", "ip", NFT_TABLE] in runner.calls
    assert ["iptables", "-I", "FORWARD", "-s", SUBNET, "-j", "ACCEPT"] in runner.calls


def test_rollback_on_partial_failure() -> None:
    # Fail on the masquerade rule (5th call: sysctl, pre-delete, add table,
    # add chain, add rule). Teardown must run and the original error must
    # propagate.
    runner = FailingRunner(fail_on=5)
    with pytest.raises(subprocess.CalledProcessError):  # noqa: SIM117
        with Egress(subnet=SUBNET, uplink_iface=IFACE, runner=runner):
            pass
    # _safe_teardown attempted all four cleanup commands.
    assert ["nft", "delete", "table", "ip", NFT_TABLE] in runner.calls
    assert ["sysctl", "-w", "net.ipv4.ip_forward=0"] in runner.calls


def test_rollback_swallows_teardown_errors() -> None:
    # Fail on the very first call (sysctl set). Teardown will then error too,
    # but the original exception must still propagate.
    runner = FailingRunner(fail_on=1)
    with pytest.raises(subprocess.CalledProcessError):  # noqa: SIM117
        with Egress(subnet=SUBNET, uplink_iface=IFACE, runner=runner):
            pass
