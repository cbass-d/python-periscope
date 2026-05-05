import typer
import sys
from loguru import logger

from periscope.sandbox.network_sandbox import NetworkSandbox


app = typer.Typer(help="Audit container network egress.")


@app.callback()
def main() -> None:
    logger.remove()
    logger.add(sys.stderr, level="INFO")
    logger.add("persicope.log", level="DEBUG",
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
