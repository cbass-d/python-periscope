import sys
from pathlib import Path
from typing import Annotated

import typer
from loguru import logger

from periscope import preflight
from periscope.capture import capture
from periscope.container import run_container
from periscope.diff import compute_diff
from periscope.policy import PolicyError, load_policy
from periscope.sandbox.network_sandbox import HOST_VETH
from periscope.session import session

app = typer.Typer(help="Audit container network egress.")


@app.callback()
def main() -> None:
    logger.remove()
    logger.add(sys.stderr, level="INFO")


@app.command()
def check(
    uplink_iface: Annotated[str, typer.Argument(help="The host's uplink interface")],
) -> None:
    """Verify that the host environment can run periscope."""
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
    image: Annotated[str, typer.Argument(help="Container image to profile")],
    uplink_iface: Annotated[str, typer.Argument(help="The host's uplink interface")],
    duration: Annotated[
        int, typer.Option("--duration", "-d", help="Capture duration in seconds")
    ] = 60,
    namespace: Annotated[str, typer.Option("--namespace", "-n")] = "periscope-ns",
    subnet: Annotated[str, typer.Option("--subnet", "-s")] = "10.0.0.0/24",
    json_output: Annotated[bool, typer.Option("--json")] = False,
    policy: Annotated[
        Path | None,
        typer.Option("--policy", "-p", help="TOML policy file with expected destinations"),
    ] = None,
    strict: Annotated[
        bool,
        typer.Option("--strict", help="Exit nonzero if any destination is unexpected"),
    ] = False,
) -> None:
    """Profile a container's network activity.

    Pass the container's command/args after `--`, e.g.:
        periscope profile <image> <iface> -- -sI https://example.com
    """
    logger.add("periscope.log", level="DEBUG", serialize=True, rotation="10 MB")

    if strict and policy is None:
        typer.echo("error: --strict requires --policy", err=True)
        raise typer.Exit(code=1)

    loaded_policy = None
    if policy is not None:
        try:
            loaded_policy = load_policy(policy)
        except PolicyError as e:
            typer.echo(f"error: {e}", err=True)
            raise typer.Exit(code=1) from e

    errors = preflight.check(uplink_iface)
    if errors:
        for err in errors:
            typer.echo(f"error: {err}", err=True)
        raise typer.Exit(code=1)

    command = ctx.args or None

    if not json_output:
        typer.echo(f"Profiling image={image} uplink={uplink_iface}")

    with session(name=namespace, subnet=subnet, uplink_iface=uplink_iface) as (gw, sb):
        logger.info("session active", namespace=sb.name, gateway=gw.iface)
        with capture(HOST_VETH, subnet=subnet) as summary:
            run_container(image, sb.name, duration, command)

        diff = compute_diff(summary, loaded_policy) if loaded_policy is not None else None

        if json_output:
            import json

            payload = summary.to_dict()
            if diff is not None:
                payload["policy_diff"] = diff.to_dict()
            typer.echo(json.dumps(payload))
        else:
            typer.echo(summary.render())
            if diff is not None:
                typer.echo(diff.render())

        if strict and diff is not None and diff.has_unexpected():
            raise typer.Exit(code=2)
