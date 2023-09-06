import json
import subprocess
from typing import Any, cast

import click
import rich
from rich.text import Text
from rich.tree import Tree

from etc import ROOT


def cargo_metadata() -> Any:
    return json.loads(
        subprocess.check_output(["cargo", "metadata", "--format-version=1"], cwd=ROOT)
    )


@click.command()
def list_features() -> None:
    """List cargo features defined in Swanky."""
    metadata = cargo_metadata()
    workspace_member_ids = set(metadata["workspace_members"])
    workspace_members = [
        pkg for pkg in metadata["packages"] if pkg["id"] in workspace_member_ids
    ]
    assert len(workspace_members) == len(workspace_member_ids)
    for member in sorted(
        workspace_members, key=lambda member: cast(str, member["name"])
    ):
        if len(member["features"]) > 0:
            crate = Tree(member["name"])
            for feature in sorted(member["features"]):
                crate.add(feature)
            rich.print(crate)
