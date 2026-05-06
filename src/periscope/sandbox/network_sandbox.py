import ipaddress
from typing import Self

from loguru import logger

from periscope.sandbox.command_runner import CommandRunner, SubprocessRunner

HOST_VETH = "peri-host-veth"
NS_VETH = "peri-ns-veth"


class NetworkSandbox:
    """Creates, manages, and deletes network namespaces."""

    def __init__(
        self,
        name: str,
        subnet: str,
        uplink_iface: str,
        runner: CommandRunner | None = None,
    ) -> None:
        logger.info(
            "creating new network namespace",
            name=name, subnet=subnet, iface=uplink_iface,
        )
        self.name = name
        self.subnet = subnet
        self.host_iface = uplink_iface
        self._runner = runner or SubprocessRunner()

        network = ipaddress.ip_network(subnet, strict=False)
        hosts = list(network.hosts())
        self._host_ip = str(hosts[0])
        self._host_addr = f"{hosts[0]}/{network.prefixlen}"
        self._ns_addr = f"{hosts[1]}/{network.prefixlen}"

    def __enter__(self) -> Self:
        logger.debug("entering network sandbox", name=self.name)
        try:
            self._runner.run(["ip", "netns", "add", self.name])
            self._runner.run([
                "ip", "link", "add", HOST_VETH,
                "type", "veth", "peer", "name", NS_VETH,
            ])
            self._runner.run(
                ["ip", "link", "set", NS_VETH, "netns", self.name])
            self._runner.run(
                ["ip", "addr", "add", self._host_addr, "dev", HOST_VETH])
            self._runner.run(
                ["ip", "-n", self.name, "addr", "add",
                    self._ns_addr, "dev", NS_VETH]
            )
            self._runner.run(["ip", "link", "set", HOST_VETH, "up"])
            self._runner.run(
                ["ip", "-n", self.name, "link", "set", NS_VETH, "up"])
            self._runner.run(
                ["ip", "-n", self.name, "link", "set", "lo", "up"])
            self._runner.run([
                "ip", "-n", self.name, "route", "add", "default",
                "via", self._host_ip,
            ])
        except Exception:
            logger.exception("sandbox setup failed; rolling back")
            self._safe_teardown()
            raise
        return self

    def __exit__(self, _exc_type, _exc_val, _exc_tb) -> None:
        logger.debug("exiting network sandbox", name=self.name)
        # Deleting the netns destroys interfaces inside it; veth peers die
        # together, so the host-side veth is removed too.
        self._runner.run(["ip", "netns", "delete", self.name])

    def _safe_teardown(self) -> None:
        for cmd in (
            ["ip", "netns", "delete", self.name],
            ["ip", "link", "delete", HOST_VETH],
        ):
            try:
                self._runner.run(cmd)
            except Exception:
                pass
