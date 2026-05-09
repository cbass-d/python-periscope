import os
import shutil
from pathlib import Path

REQUIRED_COMMANDS = ("podman", "ip", "nft", "iptables", "sysctl")


def check(uplink_iface: str) -> list[str]:
    """Return a list of error messages. Empty if none"""
    errors: list[str] = []

    if os.getuid() != 0:
        errors.append("persicope must be run as root")

    missing = [cmd for cmd in REQUIRED_COMMANDS if shutil.which(cmd) is None]
    if missing:
        errors.append(f"missing required commands: {'. '.join(missing)}")

    if not Path(f"/sys/class/net/{uplink_iface}").exists():
        errors.append(f"uplink interface {uplink_iface} does not exist")

    return errors
