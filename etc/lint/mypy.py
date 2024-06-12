import subprocess

import click

from etc import ROOT
from etc.lint import LintResult


def mypy(ctx: click.Context) -> LintResult:
    """Check types of Swanky python utilities

    This _only_ typechecks ./swanky and friends. It doesn't typecheck any other python code.
    """
    if (
        subprocess.call(
            [
                "mypy",
                "--config-file=etc/mypy.ini",
                "--cache-dir",
                "target/mypy",
                "etc",
                "swanky",
            ],
            cwd=ROOT,
        )
        == 0
    ):
        return LintResult.SUCCESS
    else:
        return LintResult.FAILURE
