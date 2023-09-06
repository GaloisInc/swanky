import itertools
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import List

import click
import rich
import rich.panel
import rich.syntax
import rich.text
import toml

from etc import ROOT
from etc.lint import LintResult


def list_cargo_toml_files() -> List[Path]:
    """
    Return Cargo.toml files for crates in Swanky

    This won't return ROOT/Cargo.toml
    """
    return [
        ROOT / x
        for x in subprocess.check_output(
            ["git", "ls-files", "--cached", "--others"], cwd=str(ROOT)
        )
        .decode("ascii")
        .strip()
        .split("\n")
        if x.endswith("Cargo.toml") and ROOT / x != ROOT / "Cargo.toml"
    ]


def check_cargo_lock(ctx: click.Context) -> LintResult:
    "Check Cargo.lock is up-to-date"
    if (
        subprocess.call(
            ["cargo", "metadata", "--format-version=1", "--locked"],
            stdout=subprocess.DEVNULL,
            cwd=ROOT,
        )
        != 0
    ):
        rich.print("Cargo.lock isn't up to date. Run `cargo update` to fix this.")
        return LintResult.FAILURE
    return LintResult.SUCCESS


def root_cargo_toml():
    return toml.loads((ROOT / "Cargo.toml").read_text())


def crates_in_manifest() -> List[Path]:
    return list(
        itertools.chain.from_iterable(
            ROOT.glob(member) for member in root_cargo_toml()["workspace"]["members"]
        )
    )


def crates_enumerated_in_workspace(ctx: click.Context) -> LintResult:
    "Check that all crates in Swanky are listed in the workspace"
    crates_in_manifest_cargo_tomls = set(
        crate / "Cargo.toml" for crate in crates_in_manifest()
    )
    cargo_toml_files = set(list_cargo_toml_files())
    if cargo_toml_files != crates_in_manifest_cargo_tomls:
        rich.print(
            "The following crates aren't listed in /Cargo.toml as a workspace member"
        )
        for cargo_toml in cargo_toml_files - crates_in_manifest_cargo_tomls:
            rich.print(f"- {cargo_toml.parent.relative_to(ROOT)}")
        return LintResult.FAILURE
    else:
        return LintResult.SUCCESS


def validate_crate_manifests(ctx: click.Context) -> LintResult:
    "Validate crate manifests to ensure they adhere to workspace rules."
    any_errors = False
    inherited_keys = set(root_cargo_toml()["workspace"]["package"].keys())
    for crate in crates_in_manifest():
        data = toml.loads((crate / "Cargo.toml").read_text())
        missing_workspace_keys = inherited_keys - set(
            k
            for k, v in data["package"].items()
            if isinstance(v, dict) and v.get("workspace") == True
        )
        if len(missing_workspace_keys) > 0:
            any_errors = True
            crate_toml = (crate / "Cargo.toml").relative_to(ROOT)
            rich.print(
                f"[bold][underline]{crate_toml}[/underline] missing workspace package keys[/bold]"
            )
            rich.print("Add the following to the TOML file to resolve the problem:")
            rich.get_console().print(
                rich.syntax.Syntax(
                    "[package]\n"
                    + "\n".join(
                        f"{k}.workspace = true"
                        for k in sorted(list(missing_workspace_keys))
                    ),
                    "toml",
                )
            )
            rich.print("")
        deps_needing_workspace = defaultdict(lambda: set())
        # TODO: this list of sections isn't complete, since these also exist in target-specific sections.
        for section in ["dependencies", "dev-dependencies", "build-dependencies"]:
            for k, v in data.get(section, dict()).items():
                if (not isinstance(v, dict)) or v.get("workspace") != True:
                    deps_needing_workspace[section].add(k)
        if len(deps_needing_workspace) > 0:
            code = ""
            for section, deps in deps_needing_workspace.items():
                code += f"[{section}]\n"
                for dep in sorted(list(deps)):
                    code += f"{dep}.workspace = true\n"
            rich.print(
                f"[bold][underline]{crate_toml}[/underline] isn't using a workspace dependency[/bold]"
            )
            rich.print("Here are the keys that should change:")
            rich.get_console().print(rich.syntax.Syntax(code, "toml"))
            rich.print("")
            any_errors = True
    return LintResult.FAILURE if any_errors else LintResult.SUCCESS


def cargo_deny(ctx: click.Context) -> LintResult:
    """
    Check that we only use liberally-licensed dependencies
    """
    if (
        subprocess.call(
            [
                "cargo",
                "deny",
                "--workspace",
                "--offline",
                "check",
                "--config",
                str(ROOT / "etc/deny.toml"),
                "bans",
                "licenses",
                "sources",
            ],
            cwd=ROOT,
        )
        != 0
    ):
        return LintResult.FAILURE
    else:
        return LintResult.SUCCESS
