import click
import rich
import toml

from etc import ROOT
from etc.lint import LintResult


def check_version_matches(ctx: click.Context) -> LintResult:
    """
    Check pinned flatc version

    It should match the version of the rust dependency.
    """
    flatbuffers_version = toml.loads((ROOT / "Cargo.toml").read_text())["workspace"][
        "dependencies"
    ]["flatbuffers"]
    flatc_ver_path = "crates/flatbuffer-build/src/flatc-ver.txt"
    actual_flatc_ver = (ROOT / flatc_ver_path).read_text().strip()
    expected_flatc_ver = f"flatc version {flatbuffers_version}"
    if actual_flatc_ver != expected_flatc_ver:
        rich.print(
            f"{flatc_ver_path} contains {repr(actual_flatc_ver)}, which doesn't match "
            + f"{repr(expected_flatc_ver)}, as set in /Cargo.toml",
        )
        return LintResult.FAILURE
    return LintResult.SUCCESS
