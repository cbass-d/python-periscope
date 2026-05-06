from contextlib import contextmanager

from loguru import logger

from periscope.sandbox.command_runner import CommandRunner, SubprocessRunner
from periscope.sandbox.egress import Egress
from periscope.sandbox.network_sandbox import NetworkSandbox


@contextmanager
def session(
        name: str,
        subnet: str,
        uplink_iface: str,
        runner: CommandRunner | None = None
):
    runner = runner or SubprocessRunner()
    with (
        Egress(subnet=subnet, uplink_iface=uplink_iface, runner=runner) as gw,
        NetworkSandbox(
            name=name, subnet=subnet, uplink_iface=uplink_iface, runner=runner
        ) as sb
    ):
        logger.debug("entering session context")
        yield gw, sb
