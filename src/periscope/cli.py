import sys

import typer
from loguru import logger

from periscope.capture import capture
from periscope.container import run_container
from periscope.sandbox.network_sandbox import HOST_VETH
from periscope.session import session

app = typer.Typer(help="Audit container network egress.")


@app.callback()
def main() -> None:
    logger.remove()
    logger.add(sys.stderr, level="INFO")
    logger.add("periscope.log", level="DEBUG", serialize=True, rotation="10 MB")
    pass


@app.command(
    context_settings={
        "allow_extra_args": True,
        "ignore_unknown_options": True,
    }
)
def profile(
    ctx: typer.Context,
    image: str = typer.Argument(..., help="Container image to profile"),
    uplink_iface: str = typer.Argument(..., help="The host's uplink interface"),
    duration: int = typer.Option(60, "--duration", "-d", help="Capture duration in seconds"),
) -> None:
    """Profile a container's network activity.

    Pass the container's command/args after `--`, e.g.:
        periscope profile <image> <iface> -- -sI https://example.com
    """
    command = ctx.args or None
    typer.echo(f"Profiling image={image} uplink={uplink_iface}")
    with session(name="periscope-ns", subnet="10.1.0.0/24", uplink_iface=uplink_iface) as (gw, sb):
        logger.info("session active", namespace=sb.name, gateway=gw.iface)
        with capture(HOST_VETH) as summary:
            run_container(image, sb.name, command)
        typer.echo(summary.render())
