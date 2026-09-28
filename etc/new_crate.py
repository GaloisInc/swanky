import json
from pathlib import Path
from string import Template
from typing import Sequence

import rich_click as click

from etc import ROOT, readme
from etc.rust import CrateDir, crate_path

_TOML_TEMPLATE = Template(
    """
[package]
name = "$crate"
description = $escaped_description
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

_LIB_RS_TEMPLATE = Template(
    """
#![deny(missing_docs)]
//! $description
    """.strip()
    + "\n"
)


@click.command()
@click.option(
    "--name",
    help="What should the new crate be called? (It must start with 'swanky-')"
    + " If absent, you'll be prompted for the name.",
    prompt="Crate Name",
)
@click.option(
    "--description",
    help="What's the description of the new crate? If absent, you'll be prompted for it.",
    prompt="Crate Description",
)
@click.option(
    "--core/--edge",
    default=False,
    help="Is the crate an edge crate or a core crate?",
)
@click.pass_context
def new_crate(ctx: click.Context, name: str, description: str, core: bool) -> None:
    """
    Create a new crate in Swanky

    A crate template will be instantiated in the edge/ directory
    """
    if not name.startswith("swanky-"):
        raise click.UsageError(
            f"Crate names must start with 'swanky-'. But {repr(name)} were submitted."
        )
    dst = crate_path(name, CrateDir.CORE if core else CrateDir.EDGE)
    if dst.exists():
        raise click.ClickException(f"Crate {repr(name)} already exists.")
    dst.mkdir()
    (dst / "Cargo.toml").write_text(
        _TOML_TEMPLATE.safe_substitute(
            crate=name, escaped_description=json.dumps(description)
        )
    )
    (dst / "src").mkdir()
    (dst / "src" / "lib.rs").write_text(
        _LIB_RS_TEMPLATE.safe_substitute(description=description)
    )
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
        + sorted(lines[begin_idx + 1 : end_idx] + [f'{name} = {{ path = "{path}" }}'])
        + lines[end_idx:]
    )
    begin_idx = lines.index("members = [")
    end_idx = lines.index("]", begin_idx)
    lines = (
        lines[0 : begin_idx + 1]
        + sorted(lines[begin_idx + 1 : end_idx] + [f'  "{path}",'])
        + lines[end_idx:]
    )
    cargo_toml = "\n".join(lines)
    cargo_toml_path.write_text(cargo_toml)
    if core:
        pre_push_hook_path = ROOT / "etc" / "hooks" / "pre-push"
        pre_push_hook = pre_push_hook_path.read_text()
        lines = pre_push_hook.split("\n")

        assert "    # BEGIN CORE CRATES" in lines
        assert "    # END CORE CRATES" in lines

        begin_idx = lines.index("    # BEGIN CORE CRATES")
        end_idx = lines.index("    # END CORE CRATES")

        lines = (
            lines[0 : begin_idx + 1]
            + sorted(lines[begin_idx + 1 : end_idx] + [f"    {name}"])
            + lines[end_idx:]
        )
        pre_push_hook = "\n".join(lines)
        pre_push_hook_path.write_text(pre_push_hook)
    ctx.invoke(readme.gen_crate_list, check=False)
