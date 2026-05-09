import sys

import typer
from loguru import logger

from periscope import preflight
from periscope.capture import capture
from periscope.container import run_container
from periscope.sandbox.network_sandbox import HOST_VETH
from periscope.session import session

app = typer.Typer(help="Audit container network egress.")


@app.callback()
def main() -> None:
    logger.remove()
    logger.add(sys.stderr, level="INFO")
    pass


@app.command()
def check(uplink_iface: str = typer.Argument(..., help="The host's uplink interface")) -> None:
    """Verify that the host enviromment can run periscope"""
    errors = preflight.check(uplink_iface)
    if errors:
        for err in errors:
            typer.echo(f"error: {err}", err=True)
        raise typer.Exit(code=1)
    typer.echo("ok")


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
    # Check requirements
    logger.add("periscope.log", level="DEBUG", serialize=True, rotation="10 MB")

    errors = preflight.check(uplink_iface)
    if errors:
        for err in errors:
            typer.echo(f"error: {err}", err=True)
        raise typer.Exit(code=1)

    command = ctx.args or None
    typer.echo(f"Profiling image={image} uplink={uplink_iface}")
    with session(name="periscope-ns", subnet="10.1.0.0/24", uplink_iface=uplink_iface) as (gw, sb):
        logger.info("session active", namespace=sb.name, gateway=gw.iface)
        with capture(HOST_VETH, subnet="10.1.0.0/24") as summary:
            run_container(image, sb.name, duration, command)
        typer.echo(summary.render())
