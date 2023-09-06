import shutil
import subprocess
from pathlib import Path

import click

from etc import ROOT


@click.group()
def vectoreyes():
    """Commands for working with the vectoreyes library."""


@vectoreyes.command()
@click.option(
    "--check",
    is_flag=True,
    default=False,
    help="Don't change any files, just fail if files would be formatted",
)
def generate(check: bool) -> None:
    """Regenerate the vectoreyes generated code."""
    # Do the import inside the command, to avoid importing extra stuff on every ./swanky invocation
    from .src.codegen.generate import CODEGEN, generate  # type: ignore

    GENERATED = CODEGEN.parent / "generated"
    sources = generate()
    if not check:
        # Write out the files.
        if GENERATED.exists():
            shutil.rmtree(GENERATED)
        GENERATED.mkdir()
        for k, v in sources.items():
            dst = GENERATED / k
            dst.parent.mkdir(exist_ok=True, parents=True)
            dst.write_bytes(v)
    actuals = {
        str(Path(path).relative_to(GENERATED.relative_to(ROOT))): Path(
            path
        ).read_bytes()
        for path in subprocess.check_output(
            ["git", "ls-files", "--cached", "--others", GENERATED.relative_to(ROOT)],
            cwd=str(ROOT),
        )
        .decode("ascii")
        .strip()
        .split("\n")
    }
    if actuals != sources:
        raise click.ClickException(
            "Vectoreyes code doesn't match what was generated. Re-run ./swanky vectoreyes generate"
        )
