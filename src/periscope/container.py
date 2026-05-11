import subprocess

from loguru import logger


def run_container(
    image: str,
    netns: str,
    duration: int,
    command: list[str] | None = None,
) -> int:
    """Run a container in the given network namespace via podman.

    The container's stdout/stderr are discarded so only periscope's own output
    appears on the terminal. The exit code is returned for diagnostics.
    """
    logger.info("running container", image=image, netns=netns, command=command)
    proc = subprocess.Popen(
        [
            "podman",
            "run",
            "--rm",
            f"--network=ns:/var/run/netns/{netns}",
            image,
            *(command or []),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        return proc.wait(timeout=duration)
    except subprocess.TimeoutExpired:
        logger.info("duration elapsed; closing container", duration=duration)
        proc.terminate()
        try:
            return proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            return proc.wait()
