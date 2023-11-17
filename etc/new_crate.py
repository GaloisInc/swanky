from pathlib import Path
from string import Template
from typing import Sequence

import click

from etc import ROOT

_TOML_TEMPLATE = Template(
    """
[package]
name = "$crate"
authors.workspace = true
edition.workspace = true
license.workspace = true
publish.workspace = true
version.workspace = true

[lints]
workspace = true

[dependencies]
# my_dependency.workspace = true
""".strip()
    + "\n"
)


@click.command()
@click.argument("names", nargs=-1)
def new_crate(names: Sequence[str]) -> None:
    """
    Create new crates in Swanky

    NAMES are names of crates to create. They must start with 'swanky-'.

    A crate template will be instantiated in the crates/ directory

    For example: ./swanky new-crate swanky-cool-protocol1 swanky-cool-protocol2
    """
    bad_names = [name for name in names if not name.startswith("swanky-")]
    if len(bad_names) > 0:
        raise click.UsageError(
            f"Crate names must start with 'swanky-'. But {repr(bad_names)} were submitted."
        )
    for crate in names:
        dst = ROOT / "crates" / crate.replace("swanky-", "", 1)
        if dst.exists():
            print(f"{dst} already exists. Skipping.")
        dst.mkdir()
        (dst / "Cargo.toml").write_text(_TOML_TEMPLATE.safe_substitute(crate=crate))
        (dst / "src").mkdir()
        (dst / "src" / "lib.rs").write_text("")
        cargo_toml_path = ROOT / "Cargo.toml"
        cargo_toml = cargo_toml_path.read_text()
        lines = cargo_toml.split("\n")
        assert "# BEGIN OUR CRATES" in lines
        assert "# END OUR CRATES" in lines
        begin_idx = lines.index("# BEGIN OUR CRATES")
        end_idx = lines.index("# END OUR CRATES")
        path = dst.relative_to(ROOT)
        lines = (
            lines[0 : begin_idx + 1]
            + sorted(
                lines[begin_idx + 1 : end_idx] + [f'{crate} = {{ path = "{path}" }}']
            )
            + lines[end_idx:]
        )
        cargo_toml = "\n".join(lines)
        cargo_toml_path.write_text(cargo_toml)
