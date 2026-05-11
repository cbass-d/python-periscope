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


def test_subnet_appears_in_nat_rule() -> None:
    runner = FakeRunner()
    with Egress(subnet="192.168.50.0/24", uplink_iface=IFACE, runner=runner):
        pass
    nat_rule = next(c for c in runner.calls if c[:5] == ["nft", "add", "rule", "ip", NFT_TABLE])
    assert "192.168.50.0/24" in nat_rule
    assert IFACE in nat_rule


def test_forward_rules_use_configured_subnet() -> None:
    runner = FakeRunner()
    with Egress(subnet="172.16.5.0/24", uplink_iface=IFACE, runner=runner):
        pass
    assert ["iptables", "-I", "FORWARD", "-s", "172.16.5.0/24", "-j", "ACCEPT"] in runner.calls
    assert ["iptables", "-I", "FORWARD", "-d", "172.16.5.0/24", "-j", "ACCEPT"] in runner.calls


def test_table_deleted_on_exit() -> None:
    runner = FakeRunner()
    with Egress(subnet=SUBNET, uplink_iface=IFACE, runner=runner):
        pass
    # Two `nft delete table` calls expected: pre-delete + exit teardown.
    delete_calls = [c for c in runner.calls if c[:3] == ["nft", "delete", "table"]]
    assert len(delete_calls) == 2


def test_ip_forward_disabled_on_exit() -> None:
    runner = FakeRunner()
    with Egress(subnet=SUBNET, uplink_iface=IFACE, runner=runner):
        pass
    assert ["sysctl", "-w", "net.ipv4.ip_forward=0"] in runner.calls


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
