import subprocess

from loguru import logger


def run_container(
    image: str,
    netns: str,
    command: list[str] | None = None,
) -> int:
    """Run a container in the given network namespace via podman.

    Streams the container's stdout/stderr to the parent process and returns
    its exit code. Bypasses the CommandRunner abstraction because we want
    interactive output, not captured output.
    """
    logger.info("running container", image=image, netns=netns, command=command)
    result = subprocess.run([
        "podman", "run", "--rm",
        f"--network=ns:/var/run/netns/{netns}",
        image,
        *(command or []),
    ])
    logger.info("container exited", image=image, returncode=result.returncode)
    return result.returncode
