from typing import Self

from loguru import logger

from periscope.sandbox.command_runner import CommandRunner, SubprocessRunner

NFT_TABLE = "periscope"


class Egress:
    """Manages host-side IP forwarding and NAT rules for the sandbox."""

    def __init__(
        self,
        subnet: str,
        host_iface: str,
        runner: CommandRunner | None = None,
    ) -> None:
        logger.info("creating egress gateway", iface=host_iface, subnet=subnet)
        self.subnet = subnet
        self.iface = host_iface
        self._runner = runner or SubprocessRunner()

    def __enter__(self) -> Self:
        logger.debug("entering egress context")
        try:
            self._runner.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])

            # Drop any leftover table from a previous crashed run before
            # creating a fresh one. `nft add table` errors if it exists.
            try:
                self._runner.run(["nft", "delete", "table", "ip", NFT_TABLE])
            except Exception:
                pass

            self._runner.run(["nft", "add", "table", "ip", NFT_TABLE])
            self._runner.run([
                "nft", "add", "chain", "ip", NFT_TABLE, "postrouting",
                "{", "type", "nat", "hook", "postrouting",
                "priority", "100", ";", "}",
            ])
            self._runner.run([
                "nft", "add", "rule", "ip", NFT_TABLE, "postrouting",
                "ip", "saddr", self.subnet,
                "oifname", self.iface,
                "masquerade",
            ])
        except Exception:
            logger.exception("egress setup failed; rolling back")
            self._safe_teardown()
            raise
        return self

    def __exit__(self, _exc_type, _exc_val, _exc_tb) -> None:
        logger.debug("exiting egress context")
        # Deleting the table atomically removes the chain and all rules.
        self._runner.run(["nft", "delete", "table", "ip", NFT_TABLE])
        self._runner.run(["sysctl", "-w", "net.ipv4.ip_forward=0"])

    def _safe_teardown(self) -> None:
        for cmd in (
            ["nft", "delete", "table", "ip", NFT_TABLE],
            ["sysctl", "-w", "net.ipv4.ip_forward=0"],
        ):
            try:
                self._runner.run(cmd)
            except Exception:
                pass
