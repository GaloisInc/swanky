from typing import Callable, Sequence

import click
import rich

from etc.fmt import fmt
from etc.lint import LintResult
from etc.lint import flatbuffers as lint_flatbuffers
from etc.lint import rust as lint_rust
from vectoreyes.cmd import generate as vectoreyes_generate


def existing_command_as_lint(doc: str, cmd: click.Command, **kwargs) -> LintResult:
    """
    Run cmd (which is already exposed via ./swanky) as a lint

    doc: the description of what the lint is
    cmd: the command to run
    kwargs: the arguments to pass to the lint
    """

    def out(ctx: click.Context) -> LintResult:
        try:
            ctx.invoke(cmd, **kwargs)
            return LintResult.SUCCESS
        except click.ClickException as e:
            rich.print(e.message)
            return LintResult.FAILURE

    setattr(out, "__doc__", doc)
    return out


LINTS: Sequence[Callable[[click.Context], LintResult]] = (
    existing_command_as_lint("Run ./swanky fmt --check", fmt, check=True),
    existing_command_as_lint(
        "Run ./swanky vectoreyes generate --check", vectoreyes_generate, check=True
    ),
    lint_flatbuffers.check_version_matches,
    lint_rust.check_cargo_lock,
    lint_rust.validate_crate_manifests,
    lint_rust.crates_enumerated_in_workspace,
    lint_rust.workspace_members_are_defined_in_workspace,
    lint_rust.cargo_deny,
)


@click.command()
@click.pass_context
def lint(ctx: click.Context) -> None:
    "Run lints! (These lints are checked in CI.)"
    failures = []
    for lint in LINTS:
        lint_name = lint.__doc__.strip().split("\n")[0].strip()
        rich.get_console().rule(lint_name)
        if lint(ctx) == LintResult.FAILURE:
            failures.append(lint_name)
    if len(failures) > 0:
        raise click.ClickException(
            "Some lints were unsuccessful:\n"
            + "\n".join(f"  - {name}" for name in failures)
        )
