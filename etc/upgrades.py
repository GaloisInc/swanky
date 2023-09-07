import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import List

import click
import rich
import rich.panel

from etc import ROOT


@click.command()
@click.option(
    "--post-rust-upgrade",
    is_flag=True,
    hidden=True,
    help="[INTERNAL] The rust toolchain has already been upgraded",
)
def upgrade_deps(post_rust_upgrade: bool = False) -> None:
    """Upgrade Swanky's pinned dependencies"""

    # TODO: when we support autogenerating flatbuffers from the CLI, automatically do so when we
    # upgrade the flatbuffers dependency.

    def cmd(args: List[str], cwd: Path = ROOT) -> None:
        cmd_name = " ".join(shlex.quote(arg) for arg in args)
        rich.get_console().rule(cmd_name)
        if subprocess.call(args, cwd=cwd) != 0:
            raise click.ClickException(f"{cmd_name} failed")

    if not post_rust_upgrade:
        cmd(["niv", "update"], cwd=ROOT / "etc")
        latest_rust = (
            subprocess.check_output(
                [
                    "nix-instantiate",
                    "--expr",
                    "(import ./etc/nix/pkgs.nix {}).rust-bin.stable.latest.minimal",
                ],
                cwd=ROOT,
            )
            .decode("ascii")
            .strip()
            .replace(".drv", "")
            .split("rust-minimal-")[1]
        )
        (ROOT / "rust-toolchain").write_text(latest_rust + "\n")
        # After we update nix and rust-toolchain, we neeed to restart the swanky processs to take
        # advantage of the new versions.
        sys.stdout.flush()
        sys.stderr.flush()
        os.execv(
            ROOT / "swanky",
            [str(ROOT / "swanky"), "upgrade-deps", "--post-rust-upgrade"],
        )
    else:
        cmd(["cargo", "upgrade", "--incompatible"])
        cmd(["cargo", "update"])
