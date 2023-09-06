import itertools
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any, List

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
    """Check Cargo.lock is up-to-date"""
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


def root_cargo_toml() -> Any:
    return toml.loads((ROOT / "Cargo.toml").read_text())


def crates_in_manifest() -> List[Path]:
    return list(
        itertools.chain.from_iterable(
            ROOT.glob(member) for member in root_cargo_toml()["workspace"]["members"]
        )
    )


def crates_enumerated_in_workspace(ctx: click.Context) -> LintResult:
    """Check that all crates in Swanky are listed in the workspace"""
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


def workspace_members_are_defined_in_workspace(ctx: click.Context) -> LintResult:
    """Check that all crates in Swanky are defined as workspace dependencies"""
    missing = (
        set(
            toml.loads((crate / "Cargo.toml").read_text())["package"]["name"]
            for crate in crates_in_manifest()
        )
        - root_cargo_toml()["workspace"]["dependencies"].keys()
    )
    if len(missing) > 0:
        rich.print(
            "The following crates aren't listed in the '#BEGIN OUR CRATES' section:"
        )
        for x in sorted(list(missing)):
            rich.print(f"- {x}")
        return LintResult.FAILURE
    else:
        return LintResult.SUCCESS


def validate_crate_manifests(ctx: click.Context) -> LintResult:
    """Validate crate manifests to ensure they adhere to workspace rules."""
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
        sections = []
        for section in ["dependencies", "dev-dependencies", "build-dependencies"]:
            sections.append((section, data.get(section, dict())))
            for target_name, target in data.get("target", dict()).items():
                sections.append(
                    (f"target.'{target_name}'.section", target.get(section, dict()))
                )
        for section, section_contents in sections:
            for k, v in section_contents.items():
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
