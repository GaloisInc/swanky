import subprocess
from typing import Annotated

import click
import rich

from etc import ROOT


@click.command()
@click.option(
    "--check",
    is_flag=True,
    default=False,
    help="Don't change any files, just fail if files would be formatted",
)
def fmt(check: bool) -> None:
    "Reformat Rust and Python code in Swanky."
    commands = [
        ["cargo", "fmt"] + (["--", "--check"] if check else []),
        ["black", "."] + (["--check"] if check else []),
        ["isort", "--profile", "black", "."] + (["--check"] if check else []),
        ["nixpkgs-fmt", "."] + (["--check"] if check else []),
    ]
    failures = []
    for cmd in commands:
        if subprocess.call(cmd, cwd=str(ROOT)) != 0:
            failures.append(cmd)
    if len(failures) > 0:
        msg = (
            ["swanky fmt failed!", "The following formatting commands failed:"]
            + ["    * " + " ".join(failure) for failure in failures]
            + ["\nRunning `./swanky fmt' locally should fix the issue."]
        )
        raise click.ClickException("\n".join(msg))
