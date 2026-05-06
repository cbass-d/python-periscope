import sys

import typer
from loguru import logger

from periscope.session import session

app = typer.Typer(help="Audit container network egress.")


@app.callback()
def main() -> None:
    logger.remove()
    logger.add(sys.stderr, level="INFO")
    logger.add("periscope.log", level="DEBUG",
               serialize=True, rotation="10 MB")
    pass


@app.command()
def profile(
    image: str = typer.Argument(..., help="Docker image to profile"),
    duration: int = typer.Option(
        60, "--duration", "-d", help="Capture duration in seconds"),
) -> None:
    """Profile a container's network activity."""
    typer.echo(f"Would profile image={image} for {duration}s")
    with session(
            name="periscope-ns", subnet="10.1.0.0/24", host_iface="wlp0s20f3"
    ) as (gw, sb):
        logger.info("session active", namespace=sb.name, gateway=gw.iface)
