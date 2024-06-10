import base64
import os
import subprocess
from hashlib import sha256
from pathlib import Path

import click

from etc import NIX_CACHE_KEY, ROOT


@click.group()
@click.pass_context
def main(
    ctx: click.Context,
) -> None:
    ctx.obj = dict()
    # Set in launcher script
    nix_cache_key = os.environ["SWANKY_NIX_CACHE_KEY"]

    # Set up CARGO_TARGET_DIR to make sure that we don't corrupt the standard target/ dir with
    # output compiled from the Nix compilers.
    cargo_target_dir = ROOT / "target" / f"nix-{nix_cache_key}"
    cargo_target_dir.mkdir(exist_ok=True, parents=True)
    os.environ["CARGO_TARGET_DIR"] = str(cargo_target_dir)
    ctx.obj[NIX_CACHE_KEY] = nix_cache_key


from etc.ci import ci
from etc.fmt import fmt
from etc.graph_deps import graph_deps
from etc.lint.cmd import lint
from etc.list_features import list_features
from etc.new_crate import new_crate
from etc.readme import readme
from etc.upgrades import upgrade_deps
from vectoreyes.cmd import vectoreyes

main.add_command(ci)
main.add_command(fmt)
main.add_command(lint)
main.add_command(list_features)
main.add_command(new_crate)
main.add_command(readme)
main.add_command(upgrade_deps)
main.add_command(vectoreyes)
main.add_command(graph_deps)
