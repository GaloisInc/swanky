import tomllib

import rich
import rich_click as click

from etc import ROOT
from etc.lint import LintResult


def lint_pre_push_hook(ctx: click.Context) -> LintResult:
    """
    Lint etc/hooks/pre-push

    Check that all core crates are tested
    """
    any_errors = False

    # Get actual / expected core crates from root manifest
    cargo_toml_path = ROOT / "Cargo.toml"
    cargo_toml = cargo_toml_path.read_text()

    try:
        manifest = tomllib.loads(cargo_toml)
    except tomllib.TOMLDecodeError:
        rich.print(f"{ROOT}/Cargo.toml is malformed.")
        return LintResult.FAILURE

    actual_core_crates = {
        crate
        for crate, params in manifest["workspace"]["dependencies"].items()
        if "path" in params and "core" in params["path"]
    }

    # Get core crates according to pre-push hook
    pre_push_hook_path = ROOT / "etc" / "hooks" / "pre-push"
    pre_push_hook = pre_push_hook_path.read_text()
    lines = [line.strip() for line in pre_push_hook.split("\n")]

    assert "# BEGIN CORE CRATES" in lines
    assert "# END CORE CRATES" in lines

    begin_idx = lines.index("# BEGIN CORE CRATES")
    end_idx = lines.index("# END CORE CRATES")

    tested_core_crates = set(lines[begin_idx + 1 : end_idx])

    # Compute and report any untested core crates
    untested_core_crates = actual_core_crates - tested_core_crates

    if untested_core_crates:
        any_errors = True
        rich.print(
            f"[bold red]Error:[/bold red] Some core crates are untested by the pre-push hook: {untested_core_crates}"
        )

    if any_errors:
        return LintResult.FAILURE
    else:
        return LintResult.SUCCESS
