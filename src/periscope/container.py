import subprocess

from loguru import logger


def run_container(
    image: str,
    netns: str,
    command: list[str] | None = None,
    duration: int = 30,
) -> int:
    """Run a container in the given network namespace via podman.

    Streams the container's stdout/stderr to the parent process and returns
    its exit code. Bypasses the CommandRunner abstraction because we want
    interactive output, not captured output.
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
        ]
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
