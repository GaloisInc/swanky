import subprocess

import click

from etc import ROOT

def cargo_depgraph():
    return subprocess.check_output(["cargo", "depgraph", "--all-deps", "--dedup-transitive-deps", "--workspace-only"], text=True, cwd=ROOT)

@click.command()
def graph_deps() -> None:
    """Format Swanky dependency graph in the DOT language."""
    print(cargo_depgraph(), end="")
